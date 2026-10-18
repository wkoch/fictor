//! ADR-038: one mutating owner of a canonical home inode. This lease alone
//! never proves that a previous owner's sandbox processes have exited.
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OwnershipError {
    #[error("FICTOR_HOME ocupado; operação exige posse exclusiva")]
    Busy,
    #[error("diretório de dados inseguro")]
    Unsafe,
    #[error("identidade do diretório de dados mudou")]
    Changed,
    #[error("não foi possível adquirir a posse do diretório de dados")]
    Unavailable,
}

pub struct HomeLease {
    directory: File,
    home: PathBuf,
    owner_id: String,
    writer_claimed: AtomicBool,
    secrets_mutation: Mutex<()>,
    installer_gate: Arc<tokio::sync::Mutex<()>>,
}

pub(crate) struct WriterLease(Arc<HomeLease>);

impl Drop for WriterLease {
    fn drop(&mut self) {
        self.0.writer_claimed.store(false, Ordering::Release);
    }
}

impl fmt::Debug for HomeLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HomeLease")
            .field("owner_id", &self.owner_id)
            .finish_non_exhaustive()
    }
}

impl HomeLease {
    /// Existing homes are never repaired. Only init may create the home first.
    pub fn acquire(home: &Path) -> Result<Arc<Self>, OwnershipError> {
        let home = home
            .canonicalize()
            .map_err(|_| OwnershipError::Unavailable)?;
        let directory = open(&home)?;
        validate(&directory)?;
        loop {
            // SAFETY: the owned directory FD remains live. No explicit unlock:
            // the last retained Arc closes the FD after all mutators finish.
            if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(if error.kind() == io::ErrorKind::WouldBlock {
                OwnershipError::Busy
            } else {
                OwnershipError::Unavailable
            });
        }
        let lease = Arc::new(Self {
            directory,
            home,
            owner_id: ulid::Ulid::generate().to_string(),
            writer_claimed: AtomicBool::new(false),
            secrets_mutation: Mutex::new(()),
            installer_gate: Arc::new(tokio::sync::Mutex::new(())),
        });
        lease.verify()?;
        Ok(lease)
    }

    pub fn create_for_init(home: &Path) -> Result<Arc<Self>, OwnershipError> {
        let home = std::path::absolute(home).map_err(|_| OwnershipError::Unavailable)?;
        match fs::symlink_metadata(&home) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                crate::home::private_dir(&home).map_err(|_| OwnershipError::Unavailable)?;
                if let Some(parent) = home.parent() {
                    File::open(parent)
                        .and_then(|file| file.sync_all())
                        .map_err(|_| OwnershipError::Unavailable)?;
                }
            }
            Err(_) => return Err(OwnershipError::Unavailable),
        }
        Self::acquire(&home)
    }

    pub fn home(&self) -> &Path {
        &self.home
    }
    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }

    /// One section covers lock snapshots, promotion and online configuration
    /// reads. The file lease separately excludes other processes/legacy callers.
    pub fn installer_gate(&self) -> Arc<tokio::sync::Mutex<()>> {
        self.installer_gate.clone()
    }

    /// Core-only access below the pinned inode, never a sandbox import. The
    /// caller retains this lease through every operation and deferred cleanup.
    pub(crate) fn anchored_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
    }

    /// Shared by cooperating file backends. The home is already flock-owned;
    /// independently flocking its inode here would deadlock that same owner.
    pub(crate) fn lock_secrets(&self) -> Result<MutexGuard<'_, ()>, OwnershipError> {
        let guard = self
            .secrets_mutation
            .lock()
            .map_err(|_| OwnershipError::Unavailable)?;
        self.verify()?;
        Ok(guard)
    }

    pub(crate) fn sync_directory(&self) -> Result<(), OwnershipError> {
        self.verify()?;
        self.directory
            .sync_all()
            .map_err(|_| OwnershipError::Unavailable)
    }

    pub(crate) fn claim_writer(self: &Arc<Self>) -> Result<WriterLease, OwnershipError> {
        self.verify()?;
        self.writer_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| OwnershipError::Busy)?;
        Ok(WriterLease(self.clone()))
    }

    pub(crate) fn verify(&self) -> Result<(), OwnershipError> {
        validate(&self.directory)?;
        let current = open(&self.home)?;
        validate(&current)?;
        let pinned = self
            .directory
            .metadata()
            .map_err(|_| OwnershipError::Unavailable)?;
        let current = current
            .metadata()
            .map_err(|_| OwnershipError::Unavailable)?;
        if (pinned.dev(), pinned.ino()) != (current.dev(), current.ino()) {
            return Err(OwnershipError::Changed);
        }
        Ok(())
    }
}

fn open(home: &Path) -> Result<File, OwnershipError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(home)
        .map_err(|_| OwnershipError::Unavailable)
}

fn validate(directory: &File) -> Result<(), OwnershipError> {
    let metadata = directory
        .metadata()
        .map_err(|_| OwnershipError::Unavailable)?;
    // SAFETY: geteuid has no arguments or memory-safety preconditions.
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o700
        || metadata.nlink() == 0
    {
        return Err(OwnershipError::Unsafe);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn directory_lease_is_cloexec_and_never_creates_a_lock_file() {
        let home = tempfile::tempdir().unwrap();
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let owner = HomeLease::acquire(home.path()).unwrap();
        // SAFETY: F_GETFD only inspects the flags of this live descriptor.
        let flags = unsafe { libc::fcntl(owner.directory.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
    }
}
