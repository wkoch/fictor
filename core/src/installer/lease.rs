//! A lifetime lease on the private quarantine directory serializes recovery and
//! admission, including detached workers after their caller is cancelled.
use std::{
    fs::{File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

pub struct InstallerLease {
    quarantine: File,
}

impl InstallerLease {
    pub fn acquire(home: &Path) -> io::Result<Self> {
        let home = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(home)?;
        private_directory(&home)?;
        let extensions = directory(&home, c"extensions")?;
        let quarantine = directory(&extensions, c"quarantine")?;
        // SAFETY: quarantine is a live directory descriptor; no pointers are used.
        if unsafe { libc::flock(quarantine.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { quarantine })
    }

    pub(crate) fn retain_receipt(&self, id: &str) -> io::Result<()> {
        if id.len() != 26 || id.parse::<ulid::Ulid>().is_err() {
            return Err(io::Error::other("invalid proposal identifier"));
        }
        let pending = std::ffi::CString::new(format!(".receipt-{id}"))
            .map_err(|_| io::Error::other("invalid proposal identifier"))?;
        let final_name = std::ffi::CString::new(id)
            .map_err(|_| io::Error::other("invalid proposal identifier"))?;
        // SAFETY: names are validated single components, descriptors remain open.
        // RENAME_NOREPLACE also refuses an existing symlink or empty directory.
        if unsafe {
            libc::renameat2(
                self.quarantine.as_raw_fd(),
                pending.as_ptr(),
                self.quarantine.as_raw_fd(),
                final_name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(crate) fn sync_receipts(&self) -> io::Result<()> {
        self.quarantine.sync_all()
    }
}

fn directory(parent: &File, name: &std::ffi::CStr) -> io::Result<File> {
    // SAFETY: parent and static NUL-terminated name remain live during openat.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(descriptor) };
    private_directory(&file)?;
    Ok(file)
}

fn private_directory(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    // SAFETY: geteuid takes no arguments and does not dereference pointers.
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe installer directory",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_is_exclusive_until_its_last_owner_is_dropped() {
        let home = tempfile::tempdir().unwrap();
        crate::home::prepare(home.path()).unwrap();
        let lease = std::sync::Arc::new(InstallerLease::acquire(home.path()).unwrap());
        let worker = lease.clone();
        drop(lease);
        assert!(
            matches!(InstallerLease::acquire(home.path()), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        drop(worker);
        assert!(InstallerLease::acquire(home.path()).is_ok());
    }

    #[test]
    fn receipt_rename_never_overwrites_an_existing_destination() {
        let home = tempfile::tempdir().unwrap();
        crate::home::prepare(home.path()).unwrap();
        let lease = InstallerLease::acquire(home.path()).unwrap();
        let id = ulid::Ulid::generate().to_string();
        let quarantine = home.path().join("extensions/quarantine");
        let pending = quarantine.join(format!(".receipt-{id}"));
        let destination = quarantine.join(&id);
        std::fs::create_dir(&pending).unwrap();
        std::fs::write(pending.join("candidate"), b"candidate").unwrap();
        std::fs::create_dir(&destination).unwrap();
        assert!(lease.retain_receipt(&id).is_err());
        assert!(pending.join("candidate").exists());
        std::fs::remove_dir(&destination).unwrap();
        lease.retain_receipt(&id).unwrap();
        assert!(!pending.exists());
        assert!(destination.join("candidate").exists());
    }
}
