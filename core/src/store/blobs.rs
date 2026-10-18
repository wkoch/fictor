use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::PathBuf,
};

pub const MAX_BLOB_BYTES: usize = 256 * 1024 * 1024;

#[derive(Clone)]
pub struct BlobStore {
    root: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("hash de blob inválido")]
    InvalidHash,
    #[error("blob excede o limite de tamanho")]
    TooLarge,
    #[error("conteúdo do blob difere do hash")]
    Corrupt,
    #[error("erro de arquivo: {0}")]
    Io(#[from] std::io::Error),
}

impl BlobStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub(super) fn home(&self) -> Result<&std::path::Path, super::StoreError> {
        self.root
            .parent()
            .ok_or(super::StoreError::Invalid("diretório de blobs sem raiz"))
    }

    fn path(&self, hash: &str) -> Result<PathBuf, BlobError> {
        let hex = hash.strip_prefix("sha256:").ok_or(BlobError::InvalidHash)?;
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(BlobError::InvalidHash);
        }
        Ok(self.root.join(&hex[..2]).join(&hex[2..]))
    }

    pub fn put(&self, data: &[u8]) -> Result<String, BlobError> {
        if data.len() > MAX_BLOB_BYTES {
            return Err(BlobError::TooLarge);
        }
        let hash = hash_bytes(data);
        let path = self.path(&hash)?;
        // Prefix directory is always below the configured private blob root.
        let parent = path.parent().ok_or(BlobError::InvalidHash)?;
        crate::home::private_dir(parent)?;
        if path.exists() {
            self.verify(&hash)?;
            return Ok(hash);
        }
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary.write_all(data)?;
        temporary.as_file().sync_all()?;
        match temporary.persist_noclobber(&path) {
            Ok(_) => {
                fs::File::open(parent)?.sync_all()?;
            }
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.verify(&hash)?;
            }
            Err(error) => return Err(BlobError::Io(error.error)),
        }
        Ok(hash)
    }

    /// Validate references without allocating the entire (up to 256 MiB) blob.
    pub fn verify(&self, hash: &str) -> Result<(), BlobError> {
        let mut file = fs::File::open(self.path(hash)?)?;
        let mut digest = Sha256::new();
        let mut total = 0usize;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let count = match file.read(&mut buffer) {
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            if count == 0 {
                break;
            }
            total += count;
            if total > MAX_BLOB_BYTES {
                return Err(BlobError::TooLarge);
            }
            digest.update(&buffer[..count]);
        }
        let hex: String = digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        if hash != format!("sha256:{hex}") {
            return Err(BlobError::Corrupt);
        }
        Ok(())
    }

    pub fn get(&self, hash: &str) -> Result<Vec<u8>, BlobError> {
        self.get_bounded(hash, MAX_BLOB_BYTES)
    }

    /// A caller with a smaller response budget must reject before loading the
    /// entire blob. The descriptor and bounded read also cover concurrent growth.
    pub(crate) fn get_bounded(&self, hash: &str, max_bytes: usize) -> Result<Vec<u8>, BlobError> {
        let max_bytes = max_bytes.min(MAX_BLOB_BYTES);
        let file = fs::File::open(self.path(hash)?)?;
        if file.metadata()?.len() > max_bytes as u64 {
            return Err(BlobError::TooLarge);
        }
        let mut bytes = Vec::new();
        file.take(max_bytes as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > max_bytes {
            return Err(BlobError::TooLarge);
        }
        if hash_bytes(&bytes) != hash {
            return Err(BlobError::Corrupt);
        }
        Ok(bytes)
    }
}

fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("sha256:{hex}")
}

/// Private, bounded stream capture. File writes finish before bytes are exposed.
/// Temporary captures are never mounted into extensions.
pub struct Capture {
    temporary: tempfile::NamedTempFile,
    digest: Sha256,
    length: usize,
    // Drop the temporary before releasing startup cleanup's exclusion lease.
    _cleanup_guard: fs::File,
}
impl Capture {
    pub fn len(&self) -> usize {
        self.length
    }
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
    pub fn append(&mut self, bytes: &[u8]) -> Result<(), BlobError> {
        if bytes.len() > MAX_BLOB_BYTES.saturating_sub(self.length) {
            return Err(BlobError::TooLarge);
        }
        let mut remaining = bytes;
        while !remaining.is_empty() {
            match self.temporary.write(remaining) {
                Ok(0) => {
                    return Err(BlobError::Io(std::io::Error::from(
                        std::io::ErrorKind::WriteZero,
                    )));
                }
                Ok(count) => {
                    self.digest.update(&remaining[..count]);
                    self.length += count;
                    remaining = &remaining[count..];
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}
impl BlobStore {
    fn capture_lock(&self, operation: libc::c_int) -> Result<fs::File, BlobError> {
        crate::home::private_dir(&self.root)?;
        // Independent opens are essential: dup/try_clone would share a flock
        // identity and allow one capture to convert or release another's lock.
        let directory = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.root)?;
        let metadata = directory.metadata()?;
        // SAFETY: geteuid takes no arguments and dereferences no pointers.
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "unsafe capture directory",
            )
            .into());
        }
        // SAFETY: directory owns a live descriptor. Nonblocking acquisition
        // refuses concurrent cleanup instead of blocking a Tokio worker.
        if unsafe { libc::flock(directory.as_raw_fd(), operation | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(directory)
    }

    pub fn begin_capture(&self) -> Result<Capture, BlobError> {
        let cleanup_guard = self.capture_lock(libc::LOCK_SH)?;
        let temporary = tempfile::Builder::new()
            .prefix(".model-capture-")
            .tempfile_in(&self.root)?;
        Ok(Capture {
            temporary,
            digest: Sha256::new(),
            length: 0,
            _cleanup_guard: cleanup_guard,
        })
    }
    pub fn finish_capture(&self, capture: Capture) -> Result<String, BlobError> {
        let Capture {
            temporary,
            digest,
            length: _,
            _cleanup_guard,
        } = capture;
        temporary.as_file().sync_all()?;
        let digest = digest.finalize();
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        let hash = format!("sha256:{hex}");
        let path = self.path(&hash)?;
        let parent = path.parent().ok_or(BlobError::InvalidHash)?;
        crate::home::private_dir(parent)?;
        match temporary.persist_noclobber(&path) {
            Ok(_) => fs::File::open(parent)?.sync_all()?,
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.verify(&hash)?;
            }
            Err(error) => return Err(BlobError::Io(error.error)),
        }
        Ok(hash)
    }
    pub fn cleanup_captures(&self) -> Result<(), BlobError> {
        let _cleanup_guard = self.capture_lock(libc::LOCK_EX)?;
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(".model-capture-"))
            {
                // No live capture owns this prefix; remove files, never recurse.
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod capture_tests {
    use super::*;
    #[test]
    fn limited_blob_reads_preserve_full_store_access_and_hash_verification() {
        let root = tempfile::tempdir().unwrap();
        let store = BlobStore::new(root.path().join("blobs"));
        let hash = store.put(b"original").unwrap();
        assert!(matches!(
            store.get_bounded(&hash, 7),
            Err(BlobError::TooLarge)
        ));
        assert_eq!(store.get_bounded(&hash, 8).unwrap(), b"original");
        assert_eq!(store.get(&hash).unwrap(), b"original");
        // The limit does not permit returning an unverified prefix or corrupt bytes.
        fs::write(store.path(&hash).unwrap(), b"modified").unwrap();
        assert!(matches!(
            store.get_bounded(&hash, 8),
            Err(BlobError::Corrupt)
        ));
        let empty = store.put(b"").unwrap();
        assert_eq!(store.get_bounded(&empty, 0).unwrap(), b"");
        let oversized = fs::OpenOptions::new()
            .write(true)
            .open(store.path(&hash).unwrap())
            .unwrap();
        oversized.set_len(MAX_BLOB_BYTES as u64 + 1).unwrap();
        assert!(matches!(
            store.get_bounded(&hash, usize::MAX),
            Err(BlobError::TooLarge)
        ));
    }

    #[test]
    fn independent_captures_exclude_cleanup_until_the_last_owner_releases() {
        let root = tempfile::tempdir().unwrap();
        let store = BlobStore::new(root.path().join("blobs"));
        let mut first = store.begin_capture().unwrap();
        let mut second = store.begin_capture().unwrap();
        first.append(b"complete").unwrap();
        second.append(b"unfinished").unwrap();
        let orphan = root.path().join("blobs/.model-capture-orphan");
        fs::write(&orphan, b"orphan").unwrap();
        let hash = store.finish_capture(first).unwrap();
        assert!(matches!(
            store.cleanup_captures(),
            Err(BlobError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
        assert!(orphan.exists());
        // A failed cleanup must not retain EX or prevent further captures.
        drop(store.begin_capture().unwrap());
        drop(second);
        store.cleanup_captures().unwrap();
        assert!(!orphan.exists());
        assert_eq!(store.get(&hash).unwrap(), b"complete");
        assert_eq!(fs::read_dir(&store.root).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn reopening_store_preserves_live_captures_and_releases_the_cleanup_lease() {
        let home = tempfile::tempdir().unwrap();
        crate::home::prepare(home.path()).unwrap();
        let first = super::super::Store::open(home.path()).await.unwrap();
        let blobs = BlobStore::new(home.path().join("blobs"));
        let mut capture = blobs.begin_capture().unwrap();
        capture.append(b"first").unwrap();
        let orphan = home.path().join("blobs/.model-capture-orphan");
        fs::write(&orphan, b"partial").unwrap();
        // Startup must refuse cleanup while another writer still owns a capture.
        assert!(super::super::Store::open(home.path()).await.is_err());
        assert!(orphan.exists());
        capture.append(b"second").unwrap();
        let hash = first.finish_capture(capture).await.unwrap();
        assert_eq!(blobs.get(&hash).unwrap(), b"firstsecond");
        let second = super::super::Store::open(home.path()).await.unwrap();
        assert!(!orphan.exists());
        drop(second);
        drop(first);
    }

    #[test]
    fn capture_hashes_stream_bytes_and_cleans_orphans_without_touching_blobs() {
        let root = tempfile::tempdir().unwrap();
        let store = BlobStore::new(root.path().join("blobs"));
        let mut capture = store.begin_capture().unwrap();
        capture.append(b"first").unwrap();
        capture.append(b"second").unwrap();
        let hash = store.finish_capture(capture).unwrap();
        assert_eq!(store.get(&hash).unwrap(), b"firstsecond");
        std::fs::write(root.path().join("blobs/.model-capture-orphan"), b"partial").unwrap();
        store.cleanup_captures().unwrap();
        assert!(!root.path().join("blobs/.model-capture-orphan").exists());
        assert_eq!(store.get(&hash).unwrap(), b"firstsecond");
    }
}
