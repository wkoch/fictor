//! Explicit human controls with the core stopped. These edit only `enabled`;
//! live-server routing, process shutdown and crash-loop reset are separate work.
use super::{
    lease::InstallerLease,
    lock::{Lock, LockError},
};
use std::{
    fs::OpenOptions,
    io,
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::OpenOptionsExt,
    },
    path::Path,
};

#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("não foi possível obter exclusividade do instalador")]
    Admission(#[source] io::Error),
    #[error("há um endpoint administrativo; controle offline recusado")]
    ServerPresent,
    #[error("extensão não encontrada no lock")]
    NotFound,
    #[error("caminho administrativo inseguro")]
    UnsafePath,
    #[error("não foi possível verificar se o core está parado")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Lock(#[from] LockError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlChange {
    pub ext_id: String,
    pub enabled: bool,
    pub changed: bool,
}

/// The admission lease covers the complete read-modify-write, including the
/// no-op case. It excludes another offline command and all installer workers.
/// No stale endpoint is removed or contacted: any admin entry fails closed.
pub fn set_enabled(
    home: &Path,
    ext_id: &str,
    enabled: bool,
) -> Result<ControlChange, ControlError> {
    let _lease = InstallerLease::acquire(home).map_err(ControlError::Admission)?;
    require_offline(home)?;
    let mut lock = Lock::load(home)?;
    let extension = lock
        .extensions
        .get_mut(ext_id)
        .ok_or(ControlError::NotFound)?;
    let changed = extension.enabled != enabled;
    if changed {
        extension.enabled = enabled;
        // The future server must enter through the same admission lease before
        // publishing its endpoint. Recheck the marker before the atomic writer;
        // this milestone provides no server protocol or process coordination.
        require_offline(home)?;
        lock.write_atomic(home)?;
    }
    Ok(ControlChange {
        ext_id: ext_id.to_owned(),
        enabled,
        changed,
    })
}

fn require_offline(home: &Path) -> Result<(), ControlError> {
    let home = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(home)?;
    // SAFETY: the descriptor and static NUL-terminated component remain live.
    let descriptor = unsafe {
        libc::openat(
            home.as_raw_fd(),
            c"run".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(error.into())
        };
    }
    // SAFETY: openat returned a new descriptor transferred to exactly one owner.
    let run = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let mut metadata = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: descriptor is live and metadata is aligned writable storage.
    if unsafe { libc::fstat(run.as_raw_fd(), metadata.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: successful fstat initialized metadata; geteuid has no preconditions.
    let metadata = unsafe { metadata.assume_init() };
    if metadata.st_uid != unsafe { libc::geteuid() } || metadata.st_mode & 0o077 != 0 {
        return Err(ControlError::UnsafePath);
    }
    let mut admin = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: inspect only the directory entry. Do not follow a symlink or open
    // a socket/FIFO, and never use an extension-selected path component.
    if unsafe {
        libc::fstatat(
            run.as_raw_fd(),
            c"admin.sock".as_ptr(),
            admin.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Err(ControlError::ServerPresent);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(error.into())
    }
}
