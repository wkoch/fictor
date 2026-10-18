//! Core-only credentials. Never format backend errors: several include secret bytes.
//!
//! Native API references verified against the selected keyring ecosystem stores:
//! https://docs.rs/zbus-secret-service-keyring-store/1.0.1/zbus_secret_service_keyring_store/
//! https://docs.rs/keyring-core/1.0.1/keyring_core/struct.Entry.html

use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
};
use tracing_subscriber::fmt::MakeWriter;

const SERVICE: &str = "fictor";

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SecretError {
    #[error("nome de segredo deve seguir ^[a-z0-9_]+$")]
    InvalidName,
    #[error("o valor do segredo não pode ser vazio")]
    InvalidValue,
    #[error("segredo não encontrado")]
    NotFound,
    #[error("mais de uma credencial corresponde ao segredo")]
    Ambiguous,
    #[error(
        "keyring indisponível ou bloqueado; tente novamente. Se não houver backend nativo, escolha [secrets] backend = \"file\"; não há fallback automático"
    )]
    Unavailable,
    #[error("operação de keyring não suportada pelo backend")]
    Unsupported,
    #[error("operação de keyring falhou; tente novamente")]
    Backend,
    #[error("não foi possível acessar o arquivo de segredos")]
    FileIo,
    #[error("secrets.toml deve ser arquivo regular, sem symlink, do usuário atual e com modo 0600")]
    InsecureFile,
    #[error(
        "secrets.toml inválido; exige schema = 1 e tabela secrets com nomes ^[a-z0-9_]+$ e strings não vazias"
    )]
    InvalidFormat,
    #[error("registro de mascaramento de segredos indisponível")]
    RedactionUnavailable,
}

/// Initialization status only; this deliberately does not claim that a store is unlocked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendStatus {
    Initialized,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    #[default]
    Keyring,
    File,
}

/// Explicit access prevents accidentally including a credential in Debug/logging output.
pub struct SecretValue(String);

impl SecretValue {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue(***)")
    }
}

trait SecretBackend: Send + Sync {
    fn initialize(&self) -> Result<(), SecretError>;
    fn get(&self, name: &str) -> Result<String, SecretError>;
    fn set(&self, name: &str, value: &str) -> Result<(), SecretError>;
    fn remove(&self, name: &str) -> Result<(), SecretError>;
    fn list(&self) -> Result<Vec<String>, SecretError>;
    fn reload(&self) -> Result<(), SecretError> {
        self.initialize()
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct SecretFile {
    schema: u32,
    secrets: BTreeMap<String, String>,
}

struct FileBackend {
    home: PathBuf,
    values: Mutex<BTreeMap<String, String>>,
    redactor: Redactor,
    owner: Option<Arc<crate::ownership::HomeLease>>,
}

impl FileBackend {
    fn new(home: &Path, redactor: Redactor) -> Result<Self, SecretError> {
        let home = home.canonicalize().map_err(|_| SecretError::FileIo)?;
        if !home.is_dir() {
            return Err(SecretError::FileIo);
        }
        let backend = Self {
            home,
            values: Mutex::new(BTreeMap::new()),
            redactor,
            owner: None,
        };
        backend.reload()?;
        Ok(backend)
    }

    fn new_owned(
        owner: Arc<crate::ownership::HomeLease>,
        redactor: Redactor,
    ) -> Result<Self, SecretError> {
        owner.verify().map_err(|_| SecretError::FileIo)?;
        let backend = Self {
            home: owner.home().to_path_buf(),
            values: Mutex::new(BTreeMap::new()),
            redactor,
            owner: Some(owner),
        };
        backend.reload()?;
        Ok(backend)
    }

    fn path(&self) -> PathBuf {
        self.effective_home().join("secrets.toml")
    }

    fn effective_home(&self) -> PathBuf {
        match &self.owner {
            Some(owner) => owner.anchored_path(),
            None => self.home.clone(),
        }
    }

    fn read_file(&self) -> Result<BTreeMap<String, String>, SecretError> {
        use std::os::unix::fs::OpenOptionsExt;
        self.verify_owner()?;
        let path = self.path();
        // SAFETY: geteuid takes no arguments and has no memory preconditions.
        let owner = unsafe { libc::geteuid() };
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) => check_file_metadata(&metadata, owner)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(_) => return Err(SecretError::FileIo),
        }
        let mut file = match std::fs::OpenOptions::new()
            .read(true)
            // Nonblocking also prevents a raced-in FIFO from hanging the core.
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                return Err(SecretError::InsecureFile);
            }
            Err(_) => return Err(SecretError::FileIo),
        };
        let metadata = file.metadata().map_err(|_| SecretError::FileIo)?;
        check_file_metadata(&metadata, owner)?;
        let mut text = String::new();
        file.read_to_string(&mut text)
            .map_err(|_| SecretError::InvalidFormat)?;
        let document: SecretFile = toml::from_str(&text).map_err(|_| SecretError::InvalidFormat)?;
        if document.schema != 1
            || document
                .secrets
                .iter()
                .any(|(name, value)| validate_name(name).is_err() || value.is_empty())
        {
            return Err(SecretError::InvalidFormat);
        }
        Ok(document.secrets)
    }

    fn register(&self, values: &BTreeMap<String, String>) -> Result<(), SecretError> {
        for value in values.values() {
            self.redactor.register(value)?;
        }
        Ok(())
    }

    fn lock_directory(&self) -> Result<std::fs::File, SecretError> {
        use std::os::fd::AsRawFd;
        let directory = std::fs::File::open(&self.home).map_err(|_| SecretError::FileIo)?;
        loop {
            // Serialize cooperating writers without another persisted file/schema.
            // SAFETY: directory owns a live descriptor; flock does not use pointers.
            if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX) } == 0 {
                return Ok(directory);
            }
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return Err(SecretError::FileIo);
            }
        }
    }

    fn verify_owner(&self) -> Result<(), SecretError> {
        if let Some(owner) = &self.owner {
            owner.verify().map_err(|_| SecretError::FileIo)?;
        }
        Ok(())
    }

    fn mutate(
        &self,
        change: impl FnOnce(&mut BTreeMap<String, String>) -> Result<(), SecretError>,
    ) -> Result<(), SecretError> {
        use std::os::unix::fs::PermissionsExt;
        let mut cached = self.values.lock().map_err(|_| SecretError::FileIo)?;
        let _shared = self
            .owner
            .as_ref()
            .map(|owner| owner.lock_secrets().map_err(|_| SecretError::FileIo))
            .transpose()?;
        let directory = if self.owner.is_none() {
            Some(self.lock_directory()?)
        } else {
            None
        };
        let mut values = self.read_file()?;
        self.register(&values)?;
        change(&mut values)?;
        let document = SecretFile {
            schema: 1,
            secrets: values,
        };
        let text = toml::to_string(&document).map_err(|_| SecretError::InvalidFormat)?;
        self.verify_owner()?;
        let mut temporary = tempfile::NamedTempFile::new_in(self.effective_home())
            .map_err(|_| SecretError::FileIo)?;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|_| SecretError::FileIo)?;
        temporary
            .write_all(text.as_bytes())
            .map_err(|_| SecretError::FileIo)?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|_| SecretError::FileIo)?;
        if let Ok(metadata) = std::fs::symlink_metadata(self.path())
            && metadata.file_type().is_symlink()
        {
            return Err(SecretError::InsecureFile);
        }
        self.verify_owner()?;
        temporary
            .persist(self.path())
            .map_err(|_| SecretError::FileIo)?;
        if let Some(owner) = &self.owner {
            owner.sync_directory().map_err(|_| SecretError::FileIo)?;
        } else if let Some(directory) = &directory {
            directory.sync_all().map_err(|_| SecretError::FileIo)?;
        }
        // Refresh from the actual committed bytes, retaining masks for old values.
        let reloaded = self.read_file()?;
        self.register(&reloaded)?;
        *cached = reloaded;
        Ok(())
    }
}

fn check_file_metadata(metadata: &std::fs::Metadata, owner: u32) -> Result<(), SecretError> {
    use std::os::unix::fs::MetadataExt;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(SecretError::InsecureFile);
    }
    Ok(())
}

impl SecretBackend for FileBackend {
    fn initialize(&self) -> Result<(), SecretError> {
        Ok(())
    }
    fn get(&self, name: &str) -> Result<String, SecretError> {
        self.values
            .lock()
            .map_err(|_| SecretError::FileIo)?
            .get(name)
            .cloned()
            .ok_or(SecretError::NotFound)
    }
    fn set(&self, name: &str, value: &str) -> Result<(), SecretError> {
        self.mutate(|values| {
            values.insert(name.into(), value.into());
            Ok(())
        })
    }
    fn remove(&self, name: &str) -> Result<(), SecretError> {
        self.mutate(|values| values.remove(name).map(|_| ()).ok_or(SecretError::NotFound))
    }
    fn list(&self) -> Result<Vec<String>, SecretError> {
        Ok(self
            .values
            .lock()
            .map_err(|_| SecretError::FileIo)?
            .keys()
            .cloned()
            .collect())
    }
    fn reload(&self) -> Result<(), SecretError> {
        let mut cached = self.values.lock().map_err(|_| SecretError::FileIo)?;
        let values = self.read_file()?;
        self.register(&values)?;
        *cached = values;
        Ok(())
    }
}

#[derive(Default)]
struct NativeBackend {
    store: Mutex<Option<Arc<keyring_core::CredentialStore>>>,
}

impl NativeBackend {
    fn store(&self) -> Result<Arc<keyring_core::CredentialStore>, SecretError> {
        self.store_with(create_native_store)
    }

    fn store_with(
        &self,
        create: impl FnOnce() -> Result<Arc<keyring_core::CredentialStore>, SecretError>,
    ) -> Result<Arc<keyring_core::CredentialStore>, SecretError> {
        let mut cached = self.store.lock().map_err(|_| SecretError::Unavailable)?;
        if let Some(store) = cached.as_ref() {
            return Ok(store.clone());
        }
        // Cache only success. The keyring v1 convenience wrapper caches initialization
        // errors forever; direct native construction lets a restarted service recover.
        let store = create()?;
        *cached = Some(store.clone());
        Ok(store)
    }

    fn with_store<T>(
        &self,
        operation: impl FnOnce(&keyring_core::CredentialStore) -> Result<T, SecretError>,
    ) -> Result<T, SecretError> {
        let store = self.store()?;
        let result = operation(store.as_ref());
        if matches!(result, Err(SecretError::Unavailable | SecretError::Backend)) {
            // Secret Service sessions cannot survive a daemon/bus restart. Invalidate
            // for the NEXT call only: replaying a failed set/remove can duplicate effects.
            // An older in-flight failure must not discard a newer replacement store.
            if let Ok(mut cached) = self.store.lock()
                && cached
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &store))
            {
                *cached = None;
            }
        }
        result
    }
}

fn create_native_store() -> Result<Arc<keyring_core::CredentialStore>, SecretError> {
    // Store initialization never enumerates entries, reads values, or writes credentials.
    zbus_secret_service_keyring_store::Store::new()
        .map(|store| store as Arc<keyring_core::CredentialStore>)
        .map_err(|_| SecretError::Unavailable)
}

impl SecretBackend for NativeBackend {
    fn initialize(&self) -> Result<(), SecretError> {
        self.store().map(|_| ())
    }

    fn get(&self, name: &str) -> Result<String, SecretError> {
        self.with_store(|store| {
            store
                .build(SERVICE, name, None)
                .map_err(sanitize)?
                .get_password()
                .map_err(sanitize)
        })
    }

    fn set(&self, name: &str, value: &str) -> Result<(), SecretError> {
        self.with_store(|store| {
            store
                .build(SERVICE, name, None)
                .map_err(sanitize)?
                .set_password(value)
                .map_err(sanitize)
        })
    }

    fn remove(&self, name: &str) -> Result<(), SecretError> {
        self.with_store(|store| {
            store
                .build(SERVICE, name, None)
                .map_err(sanitize)?
                .delete_credential()
                .map_err(sanitize)
        })
    }

    fn list(&self) -> Result<Vec<String>, SecretError> {
        // Both native stores support service-only searches. Metadata only: never call
        // get_password/get_secret or persist a parallel index of credential names.
        self.with_store(|store| {
            let entries = store
                .search(&HashMap::from([("service", SERVICE)]))
                .map_err(sanitize)?;
            entries
                .into_iter()
                .map(|entry| {
                    // These native stores support specifiers. The Linux wrapper returns
                    // None when its metadata lookup fails, including on a stale session.
                    let (service, name) = entry.get_specifiers().ok_or(SecretError::Backend)?;
                    if service != SERVICE {
                        return Err(SecretError::Backend);
                    }
                    validate_name(&name)?;
                    Ok(name)
                })
                .collect()
        })
    }
}

fn sanitize(error: keyring_core::Error) -> SecretError {
    match error {
        keyring_core::Error::NoEntry => SecretError::NotFound,
        keyring_core::Error::Ambiguous(_) => SecretError::Ambiguous,
        keyring_core::Error::NoDefaultStore | keyring_core::Error::NoStorageAccess(_) => {
            SecretError::Unavailable
        }
        keyring_core::Error::NotSupportedByStore(_) => SecretError::Unsupported,
        _ => SecretError::Backend,
    }
}

fn validate_name(name: &str) -> Result<(), SecretError> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(SecretError::InvalidName);
    }
    Ok(())
}

/// Calls are blocking native APIs; async callers should use spawn_blocking.
#[derive(Clone)]
pub struct SecretStore {
    backend: Arc<dyn SecretBackend>,
    redactor: Redactor,
    owner: Option<Arc<crate::ownership::HomeLease>>,
}

impl Default for SecretStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretStore {
    /// Construction is lazy: no credential reads or writes.
    pub fn new() -> Self {
        Self {
            backend: Arc::new(NativeBackend::default()),
            redactor: Redactor::default(),
            owner: None,
        }
    }

    /// Uses exactly the configured backend. File values are loaded and registered
    /// immediately; an absent file represents an empty store until explicit set.
    pub fn open(
        home: &Path,
        backend: BackendKind,
        redactor: Redactor,
    ) -> Result<Self, SecretError> {
        let backend: Arc<dyn SecretBackend> = match backend {
            BackendKind::Keyring => Arc::new(NativeBackend::default()),
            BackendKind::File => Arc::new(FileBackend::new(home, redactor.clone())?),
        };
        // A temporarily unavailable native store must not prevent the server from
        // starting: individual model calls report secret-unavailable as HTTP 503.
        // FileBackend::new has already validated and loaded its selected file.
        Ok(Self {
            backend,
            redactor,
            owner: None,
        })
    }

    /// Join the core's existing exclusive home ownership. Retain it across
    /// credential operations instead of flocking the same inode a second time.
    pub fn open_with_lease(
        owner: Arc<crate::ownership::HomeLease>,
        backend: BackendKind,
        redactor: Redactor,
    ) -> Result<Self, SecretError> {
        owner.verify().map_err(|_| SecretError::FileIo)?;
        let backend: Arc<dyn SecretBackend> = match backend {
            BackendKind::Keyring => Arc::new(NativeBackend::default()),
            BackendKind::File => Arc::new(FileBackend::new_owned(owner.clone(), redactor.clone())?),
        };
        Ok(Self {
            backend,
            redactor,
            owner: Some(owner),
        })
    }

    /// Used after an administrative credential change; never changes backends.
    pub fn reload(&self) -> Result<(), SecretError> {
        self.backend.reload()
    }

    pub fn backend_status(&self) -> BackendStatus {
        match self.backend.initialize() {
            Ok(()) => BackendStatus::Initialized,
            Err(_) => BackendStatus::Unavailable,
        }
    }

    pub fn redactor(&self) -> Redactor {
        self.redactor.clone()
    }

    pub fn get(&self, name: &str) -> Result<SecretValue, SecretError> {
        validate_name(name)?;
        let value = self.backend.get(name)?;
        if value.is_empty() {
            return Err(SecretError::InvalidValue);
        }
        self.redactor.register(&value)?;
        Ok(SecretValue(value))
    }

    pub fn set(&self, name: &str, value: &str) -> Result<(), SecretError> {
        validate_name(name)?;
        if value.is_empty() {
            return Err(SecretError::InvalidValue);
        }
        if let Some(owner) = &self.owner {
            owner.verify().map_err(|_| SecretError::FileIo)?;
        }
        self.redactor.register(value)?;
        self.backend.set(name, value)
    }

    pub fn remove(&self, name: &str) -> Result<(), SecretError> {
        validate_name(name)?;
        if let Some(owner) = &self.owner {
            owner.verify().map_err(|_| SecretError::FileIo)?;
        }
        // Retain the old value in the redactor: in-flight logs may still contain it.
        self.backend.remove(name)
    }

    pub fn list(&self) -> Result<Vec<String>, SecretError> {
        let mut names = self.backend.list()?;
        for name in &names {
            validate_name(name)?;
        }
        names.sort();
        names.dedup();
        Ok(names)
    }
}

/// Shared by every core log destination. Values remain registered across replacement
/// and deletion so in-flight events containing an old credential are still masked.
#[derive(Clone, Default)]
pub struct Redactor {
    values: Arc<RwLock<Vec<Vec<u8>>>>,
}

impl Redactor {
    /// Snapshots every currently registered representation for one child stream.
    /// Register the child's credentials and tokens before creating it and spawning
    /// the child; later registrations intentionally do not change this snapshot.
    pub fn stream(&self) -> Result<RedactionStream, SecretError> {
        let patterns = self
            .values
            .read()
            .map_err(|_| SecretError::RedactionUnavailable)?
            .clone();
        let retained = patterns.iter().map(Vec::len).max().unwrap_or(1) - 1;
        Ok(RedactionStream {
            patterns,
            retained,
            pending: Vec::new(),
            masked: Vec::new(),
            in_mask: false,
        })
    }

    pub fn register(&self, value: &str) -> Result<(), SecretError> {
        if value.is_empty() {
            return Ok(());
        }
        let mut values = self
            .values
            .write()
            .map_err(|_| SecretError::RedactionUnavailable)?;
        // Debug formatting can escape newlines/backslashes before reaching MakeWriter.
        let debug = format!("{value:?}");
        for representation in [value, &debug[1..debug.len() - 1]] {
            if !values
                .iter()
                .any(|existing| existing == representation.as_bytes())
            {
                values.push(representation.as_bytes().to_vec());
            }
        }
        Ok(())
    }

    fn redact(&self, input: &[u8]) -> Vec<u8> {
        let Ok(values) = self.values.read() else {
            // A poisoned registry must never turn masking into a plaintext pass-through.
            return b"[secret redaction unavailable]\n".to_vec();
        };
        let mut output = Vec::with_capacity(input.len());
        let mut position = 0;
        while position < input.len() {
            if let Some(length) = values
                .iter()
                .filter(|value| input[position..].starts_with(value))
                .map(Vec::len)
                .max()
            {
                output.extend_from_slice(b"***");
                position += length;
            } else {
                output.push(input[position]);
                position += 1;
            }
        }
        output
    }

    pub fn make_writer<M>(&self, inner: M) -> RedactingMakeWriter<M> {
        RedactingMakeWriter {
            inner,
            redactor: self.clone(),
        }
    }
}

/// Byte-oriented incremental redaction for stderr, including multiline secrets.
/// Never format or log this value: its immutable snapshot contains credentials.
/// Call `finish` at EOF to release the final safe bytes. Dropping it instead loses
/// the buffered suffix rather than exposing a potentially incomplete secret.
pub struct RedactionStream {
    patterns: Vec<Vec<u8>>,
    retained: usize,
    pending: Vec<u8>,
    masked: Vec<bool>,
    in_mask: bool,
}

impl RedactionStream {
    pub fn push(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(bytes);
        self.masked.resize(self.pending.len(), false);
        // Mark the union, rather than skipping a longest match: a second secret
        // can start inside the first and extend beyond it (abc + bcd in abcd).
        for start in 0..self.pending.len() {
            for pattern in &self.patterns {
                if self.pending[start..].starts_with(pattern) {
                    self.masked[start..start + pattern.len()].fill(true);
                }
            }
        }
        // No future input can extend a match starting in the emitted prefix.
        // Mask bits survive draining so matches crossing that boundary stay masked.
        self.emit(self.pending.len().saturating_sub(self.retained))
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.emit(self.pending.len())
    }

    fn emit(&mut self, length: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(length);
        for index in 0..length {
            if self.masked[index] {
                if !self.in_mask {
                    output.extend_from_slice(b"***");
                }
                self.in_mask = true;
            } else {
                output.push(self.pending[index]);
                self.in_mask = false;
            }
        }
        self.pending.drain(..length);
        self.masked.drain(..length);
        output
    }
}

/// Buffers one tracing event until its writer is dropped. Per-write replacement leaks
/// credentials when a formatter splits one value across multiple Write calls.
pub struct RedactingMakeWriter<M> {
    inner: M,
    redactor: Redactor,
}

impl<'a, M: MakeWriter<'a>> MakeWriter<'a> for RedactingMakeWriter<M> {
    type Writer = RedactingWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter {
            inner: self.inner.make_writer(),
            redactor: self.redactor.clone(),
            bytes: Vec::new(),
        }
    }

    fn make_writer_for(&'a self, metadata: &tracing::Metadata<'_>) -> Self::Writer {
        RedactingWriter {
            inner: self.inner.make_writer_for(metadata),
            redactor: self.redactor.clone(),
            bytes: Vec::new(),
        }
    }
}

pub struct RedactingWriter<W: Write> {
    inner: W,
    redactor: Redactor,
    bytes: Vec<u8>,
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // Do not emit partial secret prefixes before the event is complete.
        self.inner.flush()
    }
}

impl<W: Write> Drop for RedactingWriter<W> {
    fn drop(&mut self) {
        let masked = self.redactor.redact(&self.bytes);
        let _ = self.inner.write_all(&masked);
        let _ = self.inner.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, sync::Mutex};

    #[derive(Default)]
    struct MockBackend {
        values: Mutex<BTreeMap<String, String>>,
        reads: Mutex<usize>,
    }
    impl SecretBackend for MockBackend {
        fn initialize(&self) -> Result<(), SecretError> {
            Ok(())
        }
        fn get(&self, name: &str) -> Result<String, SecretError> {
            *self.reads.lock().unwrap() += 1;
            self.values
                .lock()
                .unwrap()
                .get(name)
                .cloned()
                .ok_or(SecretError::NotFound)
        }
        fn set(&self, name: &str, value: &str) -> Result<(), SecretError> {
            self.values
                .lock()
                .unwrap()
                .insert(name.into(), value.into());
            Ok(())
        }
        fn remove(&self, name: &str) -> Result<(), SecretError> {
            self.values
                .lock()
                .unwrap()
                .remove(name)
                .map(|_| ())
                .ok_or(SecretError::NotFound)
        }
        fn list(&self) -> Result<Vec<String>, SecretError> {
            Ok(self.values.lock().unwrap().keys().cloned().collect())
        }
    }

    fn fixture() -> (SecretStore, Arc<MockBackend>) {
        let backend = Arc::new(MockBackend::default());
        let store = SecretStore {
            backend: backend.clone(),
            redactor: Redactor::default(),
            owner: None,
        };
        (store, backend)
    }

    #[test]
    fn crud_lists_names_without_loading_values_and_retains_old_masks() {
        let (store, backend) = fixture();
        store.set("provider", "fake-secret-old").unwrap();
        assert_eq!(store.backend_status(), BackendStatus::Initialized);
        assert_eq!(store.list().unwrap(), ["provider"]);
        assert_eq!(*backend.reads.lock().unwrap(), 0);
        let value = store.get("provider").unwrap();
        assert_eq!(value.expose(), "fake-secret-old");
        assert!(!format!("{value:?}").contains("fake-secret-old"));
        store.set("provider", "fake-secret-new").unwrap();
        store.remove("provider").unwrap();
        assert_eq!(store.get("provider").unwrap_err(), SecretError::NotFound);
        assert!(store.list().unwrap().is_empty());
        assert_eq!(
            store.redactor.redact(b"fake-secret-old / fake-secret-new"),
            b"*** / ***"
        );
    }

    #[test]
    fn invalid_names_fail_before_touching_the_backend() {
        let (store, backend) = fixture();
        for name in [
            "",
            "bad\nname",
            "bad\0name",
            "bad\u{1b}name",
            "Uppercase",
            "a-b",
            "é",
        ] {
            assert_eq!(store.get(name).unwrap_err(), SecretError::InvalidName);
            assert_eq!(
                store.set(name, "fake").unwrap_err(),
                SecretError::InvalidName
            );
            assert_eq!(store.remove(name).unwrap_err(), SecretError::InvalidName);
        }
        assert_eq!(*backend.reads.lock().unwrap(), 0);
        assert!(backend.values.lock().unwrap().is_empty());
        assert_eq!(
            store.set("valid_name0", "").unwrap_err(),
            SecretError::InvalidValue
        );
    }

    #[test]
    fn loaded_values_are_registered_before_returning_to_the_caller() {
        let (store, backend) = fixture();
        backend
            .values
            .lock()
            .unwrap()
            .insert("provider".into(), "loaded-fake-key".into());
        let shared = store.redactor();
        let value = store.get("provider").unwrap();
        assert_eq!(value.expose(), "loaded-fake-key");
        assert_eq!(shared.redact(b"loaded-fake-key"), b"***");
    }

    #[test]
    fn backend_errors_never_expose_payloads() {
        let poison = "fake-secret-in-error";
        for error in [
            keyring_core::Error::BadEncoding(poison.as_bytes().to_vec()),
            keyring_core::Error::Invalid("secret".into(), poison.into()),
            keyring_core::Error::PlatformFailure(Box::new(io::Error::other(poison))),
        ] {
            let sanitized = sanitize(error);
            assert!(!format!("{sanitized}: {sanitized:?}").contains(poison));
            assert!(std::error::Error::source(&sanitized).is_none());
        }
    }

    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn masks_all_write_boundaries_including_flush_and_overlapping_values() {
        let redactor = Redactor::default();
        redactor.register("fake-token").unwrap();
        redactor.register("fake-token-longer").unwrap();
        for split in 0..="before fake-token-longer after".len() {
            let sink = Sink::default();
            let mut writer = RedactingWriter {
                inner: sink.clone(),
                redactor: redactor.clone(),
                bytes: vec![],
            };
            let bytes = b"before fake-token-longer after";
            writer.write_all(&bytes[..split]).unwrap();
            writer.flush().unwrap();
            assert!(sink.0.lock().unwrap().is_empty());
            writer.write_all(&bytes[split..]).unwrap();
            drop(writer);
            assert_eq!(*sink.0.lock().unwrap(), b"before *** after");
        }
    }

    fn stream_chunks(redactor: &Redactor, chunks: &[&[u8]]) -> Vec<u8> {
        let mut stream = redactor.stream().unwrap();
        let mut output = Vec::new();
        for chunk in chunks {
            output.extend(stream.push(chunk));
            assert!(stream.pending.len() <= stream.retained);
        }
        output.extend(stream.finish());
        output
    }

    #[test]
    fn incremental_redaction_masks_every_split_and_multiline_representation() {
        let redactor = Redactor::default();
        let secret = "faké\nsecret\\tail";
        redactor.register(secret).unwrap();
        let escaped = format!("{secret:?}");
        let input = format!(
            "before {secret}\nafter {} done",
            &escaped[1..escaped.len() - 1]
        );
        for split in 0..=input.len() {
            assert_eq!(
                stream_chunks(
                    &redactor,
                    &[&input.as_bytes()[..split], &input.as_bytes()[split..]]
                ),
                b"before ***\nafter *** done",
                "split {split}"
            );
        }
        for width in 1..=input.len() {
            let chunks: Vec<_> = input.as_bytes().chunks(width).collect();
            assert_eq!(
                stream_chunks(&redactor, &chunks),
                b"before ***\nafter *** done"
            );
        }
    }

    #[test]
    fn incremental_redaction_covers_longest_and_transitive_overlapping_matches() {
        let redactor = Redactor::default();
        for secret in ["abc", "abcdef", "bcd", "cdefg", "fgh", "xy"] {
            redactor.register(secret).unwrap();
        }
        let input = b"start abcdefgh / abcZ / xyxy / ab end";
        let expected = b"start *** / ***Z / *** / ab end";
        for split in 0..=input.len() {
            assert_eq!(
                stream_chunks(&redactor, &[&input[..split], &input[split..]]),
                expected,
                "split {split}"
            );
        }
        assert_eq!(
            stream_chunks(&redactor, &input.chunks(1).collect::<Vec<_>>()),
            expected
        );
    }

    #[test]
    fn incremental_redaction_is_binary_safe_and_retains_possible_prefixes() {
        let redactor = Redactor::default();
        redactor.register("secret").unwrap();
        let mut stream = redactor.stream().unwrap();
        assert!(stream.push(b"se").is_empty());
        assert!(stream.push(b"cr").is_empty());
        let mut output = stream.push(b"et\n\xff");
        output.extend(stream.finish());
        assert_eq!(output, b"***\n\xff");
        assert_eq!(
            stream_chunks(&redactor, &[b"partial secr"]),
            b"partial secr"
        );
        assert_eq!(
            stream_chunks(&Redactor::default(), &[b"\xff\0\n"]),
            b"\xff\0\n"
        );
    }

    #[test]
    fn incremental_snapshot_survives_registry_poison_and_new_snapshots_fail_closed() {
        let redactor = Redactor::default();
        redactor.register("original-secret").unwrap();
        let mut stream = redactor.stream().unwrap();
        redactor.register("later-secret").unwrap();
        let values = redactor.values.clone();
        let _ = std::thread::spawn(move || {
            let _guard = values.write().unwrap();
            panic!("poison the registry for this test");
        })
        .join();
        assert!(matches!(
            redactor.stream(),
            Err(SecretError::RedactionUnavailable)
        ));
        let mut output = stream.push(b"original-secret later-secret");
        output.extend(stream.finish());
        assert_eq!(output, b"*** later-secret");
    }

    #[test]
    fn tracing_event_masks_debug_escaped_and_unicode_values() {
        let redactor = Redactor::default();
        let secret = "faké\nsecret\\tail";
        redactor.register(secret).unwrap();
        let sink = Sink::default();
        let output = sink.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(redactor.make_writer(move || output.clone()))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(display = %secret, debug = ?secret);
        });
        let output = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        assert!(!output.contains("faké"));
        assert!(output.contains("***"));
    }

    #[test]
    fn a_poisoned_registry_never_emits_unmasked_events() {
        let (store, backend) = fixture();
        backend
            .values
            .lock()
            .unwrap()
            .insert("provider".into(), "loaded-fake-key".into());
        let redactor = store.redactor();
        let values = redactor.values.clone();
        let _ = std::thread::spawn(move || {
            let _guard = values.write().unwrap();
            panic!("poison the registry for this test");
        })
        .join();
        assert_eq!(
            store.get("provider").unwrap_err(),
            SecretError::RedactionUnavailable
        );
        assert_eq!(
            store.set("other", "fake").unwrap_err(),
            SecretError::RedactionUnavailable
        );
        assert!(!backend.values.lock().unwrap().contains_key("other"));
        assert_eq!(
            redactor.redact(b"loaded-fake-key"),
            b"[secret redaction unavailable]\n"
        );
    }

    fn write_secret_file(home: &Path, contents: &str) {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(home.join("secrets.toml"))
            .unwrap();
        file.write_all(contents.as_bytes()).unwrap();
    }

    #[test]
    fn configured_keyring_construction_is_lazy_and_never_reads_a_file_alternative() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(
            home.path().join("secrets.toml"),
            "deliberately invalid plaintext",
        )
        .unwrap();
        assert!(SecretStore::open(home.path(), BackendKind::Keyring, Redactor::default()).is_ok());
        assert_eq!(
            std::fs::read_to_string(home.path().join("secrets.toml")).unwrap(),
            "deliberately invalid plaintext"
        );
    }

    #[test]
    fn native_initialization_retries_failures_and_caches_only_success() {
        let backend = NativeBackend::default();
        assert!(matches!(
            backend.store_with(|| Err(SecretError::Unavailable)),
            Err(SecretError::Unavailable)
        ));
        // The keyring-core mock creates only an in-memory store, without global state.
        let expected: Arc<keyring_core::CredentialStore> =
            keyring_core::mock::Store::new().unwrap();
        let actual = backend.store_with(|| Ok(expected.clone())).unwrap();
        assert!(Arc::ptr_eq(&actual, &expected));
        let cached = backend
            .store_with(|| panic!("successful initialization must be reused"))
            .unwrap();
        assert!(Arc::ptr_eq(&cached, &expected));
    }

    #[test]
    fn native_transport_failures_clear_the_cache_without_replaying_operations() {
        for failure in [SecretError::Unavailable, SecretError::Backend] {
            let backend = NativeBackend::default();
            let original: Arc<keyring_core::CredentialStore> =
                keyring_core::mock::Store::new().unwrap();
            backend.store_with(|| Ok(original)).unwrap();
            let calls = std::sync::atomic::AtomicUsize::new(0);
            let result: Result<(), _> = backend.with_store(|_| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Err(failure)
            });
            assert_eq!(result, Err(failure));
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
            assert!(backend.store.lock().unwrap().is_none());
            let replacement: Arc<keyring_core::CredentialStore> =
                keyring_core::mock::Store::new().unwrap();
            let current = backend.store_with(|| Ok(replacement.clone())).unwrap();
            assert!(Arc::ptr_eq(&current, &replacement));
        }
    }

    #[test]
    fn native_credential_errors_preserve_a_healthy_cached_store() {
        let backend = NativeBackend::default();
        let expected: Arc<keyring_core::CredentialStore> =
            keyring_core::mock::Store::new().unwrap();
        backend.store_with(|| Ok(expected.clone())).unwrap();
        for failure in [
            SecretError::NotFound,
            SecretError::Ambiguous,
            SecretError::InvalidName,
            SecretError::InvalidValue,
        ] {
            assert_eq!(backend.with_store::<()>(|_| Err(failure)), Err(failure));
            assert!(Arc::ptr_eq(
                backend.store.lock().unwrap().as_ref().unwrap(),
                &expected
            ));
        }
    }

    #[test]
    fn a_late_native_failure_does_not_discard_a_newer_connection() {
        let backend = NativeBackend::default();
        let original: Arc<keyring_core::CredentialStore> =
            keyring_core::mock::Store::new().unwrap();
        let replacement: Arc<keyring_core::CredentialStore> =
            keyring_core::mock::Store::new().unwrap();
        backend.store_with(|| Ok(original)).unwrap();
        let result: Result<(), _> = backend.with_store(|_| {
            // Simulate another caller replacing a failed connection while this
            // operation is still in flight on the old Arc.
            *backend.store.lock().unwrap() = Some(replacement.clone());
            Err(SecretError::Backend)
        });
        assert_eq!(result, Err(SecretError::Backend));
        assert!(Arc::ptr_eq(
            backend.store.lock().unwrap().as_ref().unwrap(),
            &replacement
        ));
    }

    #[test]
    fn file_backend_is_explicit_atomic_private_and_refreshes_after_changes() {
        use std::os::unix::fs::MetadataExt;
        let home = tempfile::tempdir().unwrap();
        let redactor = Redactor::default();
        let store = SecretStore::open(home.path(), BackendKind::File, redactor.clone()).unwrap();
        assert!(store.list().unwrap().is_empty());
        assert!(!home.path().join("secrets.toml").exists());
        store
            .set("provider0_key", "fake-file-key\nwith quotes \" and é")
            .unwrap();
        store.set("other", "another-fake-key").unwrap();
        let path = home.path().join("secrets.toml");
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        // SAFETY: geteuid has no arguments or memory preconditions.
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        let text = std::fs::read_to_string(&path).unwrap();
        let document: SecretFile = toml::from_str(&text).unwrap();
        assert_eq!(document.schema, 1);
        assert_eq!(document.secrets.len(), 2);
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 1);
        let initial_redactor = Redactor::default();
        let loaded =
            SecretStore::open(home.path(), BackendKind::File, initial_redactor.clone()).unwrap();
        // Initialization registers every loaded value before any get call.
        assert_eq!(initial_redactor.redact(b"another-fake-key"), b"***");
        assert_eq!(loaded.get("other").unwrap().expose(), "another-fake-key");
        store.remove("other").unwrap();
        assert_eq!(store.get("other").unwrap_err(), SecretError::NotFound);
        loaded.reload().unwrap();
        assert_eq!(loaded.get("other").unwrap_err(), SecretError::NotFound);
        assert_eq!(redactor.redact(b"another-fake-key"), b"***");
    }

    #[test]
    fn separate_file_stores_merge_updates_without_a_persisted_index_or_lock_file() {
        let home = tempfile::tempdir().unwrap();
        let first = SecretStore::open(home.path(), BackendKind::File, Redactor::default()).unwrap();
        let second =
            SecretStore::open(home.path(), BackendKind::File, Redactor::default()).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let barrier_clone = barrier.clone();
        let worker = std::thread::spawn(move || {
            barrier_clone.wait();
            first.set("first", "fake-first").unwrap();
        });
        barrier.wait();
        second.set("second", "fake-second").unwrap();
        worker.join().unwrap();
        second.reload().unwrap();
        assert_eq!(second.list().unwrap(), ["first", "second"]);
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 1);
    }

    #[test]
    fn file_backend_rejects_insecure_metadata_symlinks_and_non_regular_files() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
        for mode in [0o644, 0o660, 0o601, 0o400] {
            let home = tempfile::tempdir().unwrap();
            write_secret_file(home.path(), "schema = 1\n[secrets]\nkey = 'fake'\n");
            std::fs::set_permissions(
                home.path().join("secrets.toml"),
                std::fs::Permissions::from_mode(mode),
            )
            .unwrap();
            assert!(
                matches!(
                    SecretStore::open(home.path(), BackendKind::File, Redactor::default()),
                    Err(SecretError::InsecureFile)
                ),
                "requested mode {mode:o}, actual mode {:o}",
                std::fs::metadata(home.path().join("secrets.toml"))
                    .unwrap()
                    .mode()
                    & 0o7777
            );
        }
        let home = tempfile::tempdir().unwrap();
        let target = home.path().join("outside");
        std::fs::write(&target, "must stay untouched").unwrap();
        symlink(&target, home.path().join("secrets.toml")).unwrap();
        assert!(matches!(
            SecretStore::open(home.path(), BackendKind::File, Redactor::default()),
            Err(SecretError::InsecureFile)
        ));
        assert_eq!(
            std::fs::read_to_string(target).unwrap(),
            "must stay untouched"
        );
        std::fs::remove_file(home.path().join("secrets.toml")).unwrap();
        std::fs::create_dir(home.path().join("secrets.toml")).unwrap();
        assert!(matches!(
            SecretStore::open(home.path(), BackendKind::File, Redactor::default()),
            Err(SecretError::InsecureFile)
        ));
        std::fs::remove_dir(home.path().join("secrets.toml")).unwrap();
        write_secret_file(home.path(), "schema = 1\n[secrets]\n");
        let metadata = std::fs::metadata(home.path().join("secrets.toml")).unwrap();
        assert_eq!(
            check_file_metadata(&metadata, metadata.uid().wrapping_add(1)),
            Err(SecretError::InsecureFile)
        );
    }

    #[test]
    fn file_schema_and_value_failures_are_sanitized_and_never_overwritten() {
        for text in [
            "schema = 2\n[secrets]\nkey = 'fake-secret-in-parser'",
            "schema = 1\n[secrets]\nkey = ''",
            "schema = 1\n[secrets]\nkey = 3",
            "schema = 1\n[secrets]\n'bad-name' = 'fake-secret-in-parser'",
            "schema = 1\n[secrets]\nkey = 'fake-secret-in-parser",
            "schema = 1\nextra = 'fake-secret-in-parser'\n[secrets]\n",
            "[secrets]\nkey = 'fake-secret-in-parser'",
        ] {
            let home = tempfile::tempdir().unwrap();
            write_secret_file(home.path(), text);
            let result = SecretStore::open(home.path(), BackendKind::File, Redactor::default());
            let error = match result {
                Ok(_) => panic!("invalid file accepted"),
                Err(error) => error,
            };
            assert_eq!(error, SecretError::InvalidFormat);
            assert!(!format!("{error}: {error:?}").contains("fake-secret-in-parser"));
            assert_eq!(
                std::fs::read_to_string(home.path().join("secrets.toml")).unwrap(),
                text
            );
        }
    }

    #[test]
    fn a_file_replaced_with_a_symlink_is_not_modified_by_set() {
        use std::os::unix::fs::symlink;
        let home = tempfile::tempdir().unwrap();
        let store = SecretStore::open(home.path(), BackendKind::File, Redactor::default()).unwrap();
        store.set("key", "fake-old").unwrap();
        std::fs::remove_file(home.path().join("secrets.toml")).unwrap();
        let target = home.path().join("target");
        std::fs::write(&target, "do not modify").unwrap();
        symlink(&target, home.path().join("secrets.toml")).unwrap();
        assert_eq!(store.set("key", "fake-new"), Err(SecretError::InsecureFile));
        assert_eq!(std::fs::read_to_string(target).unwrap(), "do not modify");
    }
}
