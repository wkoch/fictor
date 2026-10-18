//! Prepare approved bytes for activation. This operation never changes the lock,
//! proposal state, audit log, or running processes; activation recovery awaits ADR.
use super::{
    BundleBudget, BundleError, BundleProfile, Inspection, bundle, dependencies,
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
    materialize_attempt(home, store, lease, proposal_id, None).await
}

pub(crate) async fn materialize_intent(
    home: &Path,
    store: Arc<Store>,
    lease: Arc<InstallerLease>,
    proposal_id: String,
    operation_id: String,
) -> Result<MaterializedBundle, PromotionError> {
    if operation_id.parse::<ulid::Ulid>().is_err() {
        return Err(PromotionError::Unapproved);
    }
    materialize_attempt(home, store, lease, proposal_id, Some(operation_id)).await
}

async fn materialize_attempt(
    home: &Path,
    store: Arc<Store>,
    lease: Arc<InstallerLease>,
    proposal_id: String,
    operation_id: Option<String>,
) -> Result<MaterializedBundle, PromotionError> {
    if proposal_id.len() != 26 || proposal_id.parse::<ulid::Ulid>().is_err() {
        return Err(PromotionError::Unapproved);
    }
    let proposal = store.proposal(proposal_id).await?;
    let owner = store.owner().clone();
    if home.canonicalize()? != owner.home() {
        return Err(PromotionError::UnsafePath);
    }
    let home = home.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let _lease = lease;
        let _owner = owner;
        _owner.verify().map_err(|_| PromotionError::UnsafePath)?;
        materialize_owned(&home, proposal, operation_id.as_deref())
    })
    .await
    .map_err(|_| PromotionError::Task)?
}

fn materialize_owned(
    home: &Path,
    proposal: Proposal,
    operation_id: Option<&str>,
) -> Result<MaterializedBundle, PromotionError> {
    let budget = BundleBudget::start(BundleProfile::PostDependencies);
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
    let mut staging = Staging::new(&quarantine_path, operation_id)?;
    let inspection = bundle::copy_local(&source, &staging.bundle, &budget)?;
    if inspection.bundle_hash != hash {
        return Err(PromotionError::Changed);
    }
    check_manifest(&staging.bundle, &proposal, &budget)?;
    check_inventory(
        &staging.bundle,
        manifest.runtime.kind,
        &proposal,
        &inspection,
        &budget,
    )?;
    staging.freeze(&inspection, &budget)?;
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
        let existing = bundle::inspect(&destination, &budget)?;
        if existing.bundle_hash != hash || !existing.ignored.is_empty() {
            return Err(PromotionError::Changed);
        }
        check_manifest(&destination, &proposal, &budget)?;
        check_immutable(&destination, &budget)?;
    } else {
        let staging_directory = open_directory(staging.temporary.path())?;
        let candidate = open_directory(&staging.bundle)?;
        let pending = CString::new(format!(
            ".promotion-{}",
            operation_id
                .map(str::to_owned)
                .unwrap_or_else(|| ulid::Ulid::generate().to_string())
        ))
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
    budget.check_time()?;
    Ok(MaterializedBundle {
        proposal_id: proposal.id,
        ext_id: manifest.id,
        key,
        hash,
        path: destination,
    })
}

pub(crate) fn approved(proposal: &Proposal) -> Result<(Manifest, String), PromotionError> {
    if proposal.state != ProposalState::Approved
        || proposal.decided_by.as_deref() != Some("user")
        || proposal.packages.is_none()
        || proposal.audit_blob.is_some()
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

/// Recovery proves the already-published candidate without reading its origin,
/// running smoke, installing dependencies or executing extension code.
pub(crate) async fn verify_published(
    store: Arc<Store>,
    proposal_id: String,
) -> Result<MaterializedBundle, PromotionError> {
    let proposal = store.proposal(proposal_id).await?;
    let owner = store.owner().clone();
    tokio::task::spawn_blocking(move || {
        owner.verify().map_err(|_| PromotionError::UnsafePath)?;
        let (manifest, hash) = approved(&proposal)?;
        let key = format!("{}-{}", manifest.version, &hash[7..19]);
        let path = owner
            .home()
            .join("extensions/store")
            .join(&manifest.id)
            .join(&key);
        let home = open_directory(owner.home())?;
        let extensions = directory(&home, c"extensions")?;
        let stored = directory(&extensions, c"store")?;
        let id = CString::new(manifest.id.as_str()).map_err(|_| PromotionError::UnsafePath)?;
        let name = CString::new(key.as_str()).map_err(|_| PromotionError::UnsafePath)?;
        let extension = directory(&stored, &id)?;
        directory(&extension, &name)?;
        let budget = BundleBudget::start(BundleProfile::PostDependencies);
        let inspection = bundle::inspect(&path, &budget)?;
        if inspection.bundle_hash != hash || !inspection.ignored.is_empty() {
            return Err(PromotionError::Changed);
        }
        check_manifest(&path, &proposal, &budget)?;
        check_inventory(
            &path,
            manifest.runtime.kind,
            &proposal,
            &inspection,
            &budget,
        )?;
        check_immutable(&path, &budget)?;
        Ok(MaterializedBundle {
            proposal_id: proposal.id,
            ext_id: manifest.id,
            key,
            hash,
            path,
        })
    })
    .await
    .map_err(|_| PromotionError::Task)?
}

fn check_manifest(
    root: &Path,
    proposal: &Proposal,
    budget: &BundleBudget,
) -> Result<(), PromotionError> {
    budget.check_time()?;
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
    budget.check_time()?;
    Ok(())
}

fn check_inventory(
    root: &Path,
    runtime: RuntimeKind,
    proposal: &Proposal,
    inspection: &Inspection,
    budget: &BundleBudget,
) -> Result<(), PromotionError> {
    budget.check_time()?;
    // Re-read package metadata only. An old successful check may predate an
    // inventory fix; publication must not preserve an incomplete review list.
    let planned = dependencies::plan(runtime, root).map_err(|_| PromotionError::Changed)?;
    // A prepacked Node receipt skips npm and cannot acquire a dependency tree.
    // Missing declarations must not hide physical packages from this review.
    if runtime == RuntimeKind::Node
        && planned.is_none()
        && inspection
            .files
            .iter()
            .any(|file| file.path.starts_with("node_modules"))
    {
        return Err(PromotionError::Changed);
    }
    let current = match planned {
        Some(kind) => {
            dependencies::inventory(kind, root, inspection).map_err(|_| PromotionError::Changed)?
        }
        None => vec![],
    };
    let approved = proposal
        .packages
        .as_deref()
        .ok_or(PromotionError::Unapproved)?;
    let current: BTreeSet<_> = current
        .iter()
        .map(|package| (&package.ecosystem, &package.name, &package.version))
        .collect();
    let approved: BTreeSet<_> = approved
        .iter()
        .map(|package| (&package.ecosystem, &package.name, &package.version))
        .collect();
    if current != approved {
        return Err(PromotionError::Changed);
    }
    budget.check_time()?;
    Ok(())
}

struct Staging {
    temporary: tempfile::TempDir,
    bundle: PathBuf,
    directories: Vec<PathBuf>,
    retained_in_store: bool,
    journaled: bool,
}
impl Staging {
    fn new(quarantine: &Path, operation_id: Option<&str>) -> Result<Self, PromotionError> {
        let mut builder = tempfile::Builder::new();
        builder.permissions(fs::Permissions::from_mode(0o700));
        let prefix = operation_id
            .map(|id| format!(".promotion-{id}"))
            .unwrap_or_else(|| ".promotion-".into());
        builder.prefix(&prefix);
        if operation_id.is_some() {
            // The journal owns cleanup. Retain on cancellation/error so a
            // destructor cannot guess whether filesystem publication committed.
            builder.rand_bytes(0).disable_cleanup(true);
        }
        let temporary = builder.tempdir_in(quarantine)?;
        Ok(Self {
            bundle: temporary.path().join("bundle"),
            temporary,
            directories: Vec::new(),
            retained_in_store: false,
            journaled: operation_id.is_some(),
        })
    }

    fn freeze(
        &mut self,
        inspection: &Inspection,
        budget: &BundleBudget,
    ) -> Result<(), PromotionError> {
        let mut directories = BTreeSet::from([self.bundle.clone()]);
        for entry in &inspection.files {
            budget.check_time()?;
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
            budget.check_time()?;
            if path == &self.bundle {
                continue;
            }
            let directory = open_directory(path)?;
            directory.set_permissions(fs::Permissions::from_mode(0o555))?;
            directory.sync_all()?;
        }
        budget.check_time()?;
        Ok(())
    }
}
impl Drop for Staging {
    fn drop(&mut self) {
        if self.retained_in_store || self.journaled {
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

fn check_immutable(root: &Path, budget: &BundleBudget) -> Result<(), PromotionError> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        budget.check_time()?;
        let directory = open_directory(&path)?;
        if directory.metadata()?.mode() & 0o7777 != 0o555 {
            return Err(PromotionError::UnsafePath);
        }
        for entry in fs::read_dir(&path)? {
            budget.check_time()?;
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
    budget.check_time()?;
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
