//! Prepare approved bytes for activation. This operation never changes the lock,
//! proposal state, audit log, or running processes; activation recovery awaits ADR.
use super::{
    BundleBudget, BundleError, BundleProfile, Inspection, bundle,
    lease::InstallerLease,
    manifest::{Manifest, RuntimeKind, Scope},
};
use crate::store::{Proposal, ProposalState, Store, StoreError};
use std::{
    collections::BTreeSet,
    ffi::{CStr, CString},
    fs::{self, File, OpenOptions},
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Debug, thiserror::Error)]
pub enum PromotionError {
    #[error("proposta indisponível para materialização")]
    Store(#[from] StoreError),
    #[error("proposta não tem aprovação humana e checagens completas")]
    Unapproved,
    #[error("conteúdo difere da proposta aprovada")]
    Changed,
    #[error("caminho ou permissões inseguros para materialização")]
    UnsafePath,
    #[error("não foi possível inspecionar a cópia aprovada")]
    Bundle(#[from] BundleError),
    #[error("não foi possível preparar a cópia aprovada")]
    Io(#[from] io::Error),
    #[error("worker de materialização indisponível")]
    Task,
}

#[derive(Debug, PartialEq, Eq)]
pub struct MaterializedBundle {
    pub proposal_id: String,
    pub ext_id: String,
    pub key: String,
    pub hash: String,
    pub path: PathBuf,
}

/// Trusted installer entrypoint. Its caller holds the admission lease for this
/// home. A detached worker retains that lease through all filesystem work even
/// when the request is cancelled. Only a validated, human-approved snapshot is
/// published; publication alone grants no execution or activation capability.
pub async fn materialize(
    home: &Path,
    store: Arc<Store>,
    lease: Arc<InstallerLease>,
    proposal_id: String,
) -> Result<MaterializedBundle, PromotionError> {
    if proposal_id.len() != 26 || proposal_id.parse::<ulid::Ulid>().is_err() {
        return Err(PromotionError::Unapproved);
    }
    let proposal = store.proposal(proposal_id).await?;
    let home = home.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let _lease = lease;
        materialize_owned(&home, proposal)
    })
    .await
    .map_err(|_| PromotionError::Task)?
}

fn materialize_owned(
    home: &Path,
    proposal: Proposal,
) -> Result<MaterializedBundle, PromotionError> {
    let (manifest, hash) = approved(&proposal)?;
    let key = format!("{}-{}", manifest.version, &hash[7..19]);
    let home_file = open_directory(home)?;
    check_directory(&home_file, false)?;
    let extensions = directory(&home_file, c"extensions")?;
    let quarantine = directory(&extensions, c"quarantine")?;
    let store = directory(&extensions, c"store")?;
    let home = home.canonicalize()?;
    let quarantine_path = home.join("extensions/quarantine");
    let source = quarantine_path.join(&proposal.id);
    // Unverified bytes remain outside the store. A crash can leave unreferenced
    // staging directories for later architectural recovery; none imply activation.
    let mut staging = Staging::new(&quarantine_path)?;
    let inspection = bundle::copy_local(
        &source,
        &staging.bundle,
        &BundleBudget::start(BundleProfile::PostDependencies),
    )?;
    if inspection.bundle_hash != hash {
        return Err(PromotionError::Changed);
    }
    check_manifest(&staging.bundle, &proposal)?;
    staging.freeze(&inspection)?;
    let id = CString::new(manifest.id.as_str()).map_err(|_| PromotionError::UnsafePath)?;
    // SAFETY: store is a live directory descriptor and id is a validated single
    // manifest component. Existing directories are opened without following links.
    if unsafe { libc::mkdirat(store.as_raw_fd(), id.as_ptr(), 0o700) } < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(error.into());
        }
    } else {
        store.sync_all()?;
    }
    let extension = directory(&store, &id)?;
    let destination = home.join("extensions/store").join(&manifest.id).join(&key);
    let name = CString::new(key.as_str()).map_err(|_| PromotionError::UnsafePath)?;
    let existing = match directory(&extension, &name) {
        Ok(_) => true,
        Err(PromotionError::Io(error)) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };
    if existing {
        // A retry may reuse exactly these immutable bytes; collisions and
        // tampering fail closed, preserving the existing version and last lock.
        let existing = bundle::inspect(
            &destination,
            &BundleBudget::start(BundleProfile::PostDependencies),
        )?;
        if existing.bundle_hash != hash || !existing.ignored.is_empty() {
            return Err(PromotionError::Changed);
        }
        check_manifest(&destination, &proposal)?;
        check_immutable(&destination)?;
    } else {
        let staging_directory = open_directory(staging.temporary.path())?;
        let candidate = open_directory(&staging.bundle)?;
        let pending = CString::new(format!(".promotion-{}", ulid::Ulid::generate()))
            .map_err(|_| PromotionError::UnsafePath)?;
        // Linux requires directory write permission when moving between parents
        // to update '..'. Only verified approved bytes enter this private store
        // staging entry; freeze its root before the final same-parent rename.
        // SAFETY: descriptors and single-component names remain live; NOREPLACE
        // excludes replacing any existing staging entry.
        if unsafe {
            libc::renameat2(
                staging_directory.as_raw_fd(),
                c"bundle".as_ptr(),
                extension.as_raw_fd(),
                pending.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } < 0
        {
            return Err(io::Error::last_os_error().into());
        }
        // From here onward errors retain the store staging entry. RAII must never
        // make retained/published store bytes writable or infer compensation.
        staging.retained_in_store = true;
        candidate.set_permissions(fs::Permissions::from_mode(0o555))?;
        candidate.sync_all()?;
        extension.sync_all()?;
        staging_directory.sync_all()?;
        // SAFETY: both names are within one live parent. Same-parent rename does
        // not update '..', so the final key becomes visible already read-only.
        if unsafe {
            libc::renameat2(
                extension.as_raw_fd(),
                pending.as_ptr(),
                extension.as_raw_fd(),
                name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } < 0
        {
            return Err(io::Error::last_os_error().into());
        }
        // If this sync fails, retain the published bytes and report uncertainty;
        // never remove a possibly durable version or change the previous lock.
        extension.sync_all()?;
        staging_directory.sync_all()?;
        quarantine.sync_all()?;
    }
    Ok(MaterializedBundle {
        proposal_id: proposal.id,
        ext_id: manifest.id,
        key,
        hash,
        path: destination,
    })
}

fn approved(proposal: &Proposal) -> Result<(Manifest, String), PromotionError> {
    if proposal.state != ProposalState::Approved
        || proposal.decided_by.as_deref() != Some("user")
        || proposal
            .source
            .get("kind")
            .and_then(serde_json::Value::as_str)
            != Some("local")
    {
        return Err(PromotionError::Unapproved);
    }
    let checks = proposal
        .checks
        .as_deref()
        .ok_or(PromotionError::Unapproved)?;
    if checks.iter().any(|check| check.blocking && !check.passed)
        || [
            "manifest",
            "dependencies",
            "bundle",
            "declarations",
            "smoke",
        ]
        .iter()
        .any(|name| {
            checks
                .iter()
                .filter(|check| check.name == *name && check.blocking && check.passed)
                .count()
                != 1
        })
    {
        return Err(PromotionError::Unapproved);
    }
    let value = proposal
        .manifest
        .as_ref()
        .ok_or(PromotionError::Unapproved)?;
    let manifest = Manifest::parse(&value.to_string()).map_err(|_| PromotionError::Unapproved)?;
    if proposal.ext_id.as_deref() != Some(manifest.id.as_str())
        || proposal.version.as_deref() != Some(manifest.version.as_str())
        || (manifest.scope == Scope::Global && manifest.runtime.kind != RuntimeKind::None)
    {
        return Err(PromotionError::Unapproved);
    }
    let hash = proposal
        .hash
        .as_ref()
        .filter(|hash| {
            hash.strip_prefix("sha256:").is_some_and(|hex| {
                hex.len() == 64
                    && hex
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            })
        })
        .ok_or(PromotionError::Unapproved)?;
    Ok((manifest, hash.clone()))
}

fn check_manifest(root: &Path, proposal: &Proposal) -> Result<(), PromotionError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(root.join("fictor.yaml"))?;
    if !file.metadata()?.is_file() {
        return Err(PromotionError::Changed);
    }
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    let manifest = Manifest::parse(&text).map_err(|_| PromotionError::Changed)?;
    let normalized = serde_json::to_value(manifest).map_err(|_| PromotionError::Changed)?;
    if proposal.manifest.as_ref() != Some(&normalized) {
        return Err(PromotionError::Changed);
    }
    Ok(())
}

struct Staging {
    temporary: tempfile::TempDir,
    bundle: PathBuf,
    directories: Vec<PathBuf>,
    retained_in_store: bool,
}
impl Staging {
    fn new(quarantine: &Path) -> Result<Self, PromotionError> {
        let temporary = tempfile::Builder::new()
            .prefix(".promotion-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(quarantine)?;
        Ok(Self {
            bundle: temporary.path().join("bundle"),
            temporary,
            directories: Vec::new(),
            retained_in_store: false,
        })
    }

    fn freeze(&mut self, inspection: &Inspection) -> Result<(), PromotionError> {
        let mut directories = BTreeSet::from([self.bundle.clone()]);
        for entry in &inspection.files {
            let path = self.bundle.join(&entry.path);
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(&path)?;
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.nlink() != 1 {
                return Err(PromotionError::UnsafePath);
            }
            for parent in path
                .ancestors()
                .skip(1)
                .take_while(|parent| parent.starts_with(&self.bundle))
            {
                directories.insert(parent.to_path_buf());
            }
            file.set_permissions(fs::Permissions::from_mode(if entry.mode == 0o755 {
                0o555
            } else {
                0o444
            }))?;
            file.sync_all()?;
        }
        // Retain cleanup ownership before the first directory becomes read-only.
        self.directories = directories.into_iter().collect();
        for path in self.directories.iter().rev() {
            if path == &self.bundle {
                continue;
            }
            let directory = open_directory(path)?;
            directory.set_permissions(fs::Permissions::from_mode(0o555))?;
            directory.sync_all()?;
        }
        Ok(())
    }
}
impl Drop for Staging {
    fn drop(&mut self) {
        if self.retained_in_store {
            return;
        }
        // These paths only describe the private copied tree. After successful
        // publication they no longer exist here; the store is never made writable.
        for path in &self.directories {
            if let Ok(directory) = open_directory(path) {
                let _ = directory.set_permissions(fs::Permissions::from_mode(0o700));
            }
        }
    }
}

fn check_immutable(root: &Path) -> Result<(), PromotionError> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let directory = open_directory(&path)?;
        if directory.metadata()?.mode() & 0o7777 != 0o555 {
            return Err(PromotionError::UnsafePath);
        }
        for entry in fs::read_dir(&path)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if !metadata.is_file()
                || metadata.nlink() != 1
                || !matches!(metadata.mode() & 0o7777, 0o444 | 0o555)
            {
                return Err(PromotionError::UnsafePath);
            }
        }
    }
    Ok(())
}

fn open_directory(path: &Path) -> Result<File, PromotionError> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?)
}
fn directory(parent: &File, name: &CStr) -> Result<File, PromotionError> {
    // SAFETY: descriptor and NUL-terminated single-component name remain live.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: openat returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(descriptor) };
    check_directory(&file, false)?;
    Ok(file)
}
fn check_directory(file: &File, immutable: bool) -> Result<(), PromotionError> {
    let metadata = file.metadata()?;
    // SAFETY: geteuid takes no arguments and has no memory preconditions.
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
        || (immutable && metadata.mode() & 0o7777 != 0o555)
    {
        return Err(PromotionError::UnsafePath);
    }
    Ok(())
}
