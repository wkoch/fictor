//! ADR-042: core controls are direct names below one pinned private home.
use std::{
    ffi::CStr,
    fs::{File, Metadata, OpenOptions, Permissions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

pub const MAX_CONTROL_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Unsafe,
    Changed,
    Unreadable,
    Invalid,
    TooLarge,
}
impl Failure {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Unsafe => "control_file:unsafe",
            Self::Changed => "control_file:changed",
            Self::Unreadable => "control_file:unreadable",
            Self::Invalid => "control_file:invalid",
            Self::TooLarge => "control_file:too_large",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{name}: {reason}", name = .control.name(), reason = .failure.reason())]
pub struct ControlError {
    control: Control,
    failure: Failure,
}
impl ControlError {
    pub fn name(self) -> &'static str {
        self.control.name()
    }
    pub fn failure(self) -> Failure {
        self.failure
    }
    pub fn reason(self) -> &'static str {
        self.failure.reason()
    }
    pub fn invalid_config() -> Self {
        Control::Config.error(Failure::Invalid)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Control {
    Config,
    Instructions,
}
impl Control {
    fn name(self) -> &'static str {
        match self {
            Self::Config => "config.toml",
            Self::Instructions => "AGENTS.md",
        }
    }
    fn c_name(self) -> &'static CStr {
        match self {
            Self::Config => c"config.toml",
            Self::Instructions => c"AGENTS.md",
        }
    }
    fn error(self, failure: Failure) -> ControlError {
        ControlError {
            control: self,
            failure,
        }
    }
}

pub struct ControlFiles {
    directory: File,
    canonical_home: PathBuf,
}
impl ControlFiles {
    pub fn open(home: &Path) -> Result<Self, ControlError> {
        let canonical_home = home
            .canonicalize()
            .map_err(|_| Control::Config.error(Failure::Unreadable))?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&canonical_home)
            .map_err(|_| Control::Config.error(Failure::Unreadable))?;
        let controls = Self {
            directory,
            canonical_home,
        };
        controls.validate_home(Control::Config)?;
        Ok(controls)
    }

    pub fn home(&self) -> &Path {
        &self.canonical_home
    }

    pub fn config(&self) -> Result<String, ControlError> {
        self.read(Control::Config)?
            .ok_or_else(|| Control::Config.error(Failure::Unreadable))
    }

    pub fn instructions(&self) -> Result<Option<String>, ControlError> {
        self.read(Control::Instructions)
    }

    pub fn validate_boot(&self) -> Result<String, ControlError> {
        let text = self.config()?;
        self.instructions()?;
        Ok(text)
    }

    fn validate_home(&self, control: Control) -> Result<(), ControlError> {
        let metadata = self
            .directory
            .metadata()
            .map_err(|_| control.error(Failure::Unreadable))?;
        // SAFETY: geteuid has no arguments or memory-safety preconditions.
        let uid = unsafe { libc::geteuid() };
        if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o7777 != 0o700 {
            return Err(control.error(Failure::Unsafe));
        }
        if metadata.nlink() == 0 {
            return Err(control.error(Failure::Unreadable));
        }
        Ok(())
    }

    fn pinned(&self, control: Control) -> Result<Option<PinnedRead>, ControlError> {
        self.validate_home(control)?;
        let how = OpenHow {
            flags: (libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: 0x08 | 0x04 | 0x01, // BENEATH | NO_SYMLINKS | NO_XDEV
        };
        // SAFETY: the live directory, static C name and Linux open_how layout
        // remain valid for the syscall. No fallback weakens its resolution.
        let descriptor = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                self.directory.as_raw_fd(),
                control.c_name().as_ptr(),
                &how,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if descriptor < 0 {
            let error = std::io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(libc::ENOENT) if control == Control::Instructions => Ok(None),
                Some(libc::ELOOP | libc::EXDEV | libc::ENOSYS | libc::EINVAL) => {
                    Err(control.error(Failure::Unsafe))
                }
                _ => Err(control.error(Failure::Unreadable)),
            };
        }
        // SAFETY: successful openat2 returned this fresh owned descriptor.
        let pinned = unsafe { File::from_raw_fd(descriptor as i32) };
        let initial = pinned
            .metadata()
            .map_err(|_| control.error(Failure::Unreadable))?;
        validate_file(&initial).map_err(|failure| control.error(failure))?;
        let initial = Snapshot::from(&initial);
        // O_PATH does not open a device for I/O. Only after checking the pinned
        // inode's type do we reopen that exact live FD through procfs. Its
        // numeric slot cannot be reused while `pinned` remains owned here.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
            .map_err(|_| control.error(Failure::Unreadable))?;
        let reopened = file
            .metadata()
            .map_err(|_| control.error(Failure::Unreadable))?;
        if Snapshot::from(&reopened) != initial {
            return Err(control.error(Failure::Changed));
        }
        validate_file(&reopened).map_err(|failure| control.error(failure))?;
        Ok(Some(PinnedRead {
            file,
            initial,
            control,
        }))
    }

    fn read(&self, control: Control) -> Result<Option<String>, ControlError> {
        let text = self.pinned(control)?.map(PinnedRead::read).transpose()?;
        self.validate_home(control)?;
        Ok(text)
    }

    /// Only an explicitly authorized init calls this. An existing entry is
    /// validated and preserved; a racing publication is never overwritten.
    pub fn create_config_if_missing(&self, bytes: &[u8]) -> Result<(), ControlError> {
        match self.config() {
            Ok(_) => return Ok(()),
            Err(error) if error.failure == Failure::Unreadable => {
                // Distinguish actual final-name absence from every other error.
                let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
                // SAFETY: all pointers are live; no symlink is followed.
                let result = unsafe {
                    libc::fstatat(
                        self.directory.as_raw_fd(),
                        c"config.toml".as_ptr(),
                        stat.as_mut_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
                if result == 0
                    || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT)
                {
                    return Err(error);
                }
            }
            Err(error) => return Err(error),
        }
        self.validate_home(Control::Config)?;
        let temporary = std::ffi::CString::new(format!(".control-{}", ulid::Ulid::generate()))
            .map_err(|_| Control::Config.error(Failure::Unreadable))?;
        // SAFETY: anchored directory and C name are live; EXCL creates a new inode.
        let descriptor = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor < 0 {
            return Err(Control::Config.error(Failure::Unreadable));
        }
        // SAFETY: openat returned a fresh owned descriptor.
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        let result = (|| {
            file.set_permissions(Permissions::from_mode(0o600))
                .map_err(|_| Control::Config.error(Failure::Unreadable))?;
            file.write_all(bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| Control::Config.error(Failure::Unreadable))?;
            // SAFETY: both names resolve under our live home descriptor. NOREPLACE
            // is mandatory: do not replace a concurrently installed entry.
            let result = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    self.directory.as_raw_fd(),
                    temporary.as_ptr(),
                    self.directory.as_raw_fd(),
                    c"config.toml".as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            };
            if result < 0 {
                return Err(Control::Config.error(Failure::Unreadable));
            }
            self.directory
                .sync_all()
                .map_err(|_| Control::Config.error(Failure::Unreadable))
        })();
        // Remove only our still-identical temporary inode, never an unrelated
        // concurrent entry and never an unsafe existing config.toml.
        let mut current = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: live descriptor, name and writable stat storage.
        if unsafe {
            libc::fstatat(
                self.directory.as_raw_fd(),
                temporary.as_ptr(),
                current.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
        {
            // SAFETY: successful fstatat initialized current.
            let current = unsafe { current.assume_init() };
            if file.metadata().is_ok_and(|metadata| {
                metadata.dev() == current.st_dev && metadata.ino() == current.st_ino
            }) {
                // SAFETY: unlinkat removes this direct temporary name only.
                unsafe {
                    libc::unlinkat(self.directory.as_raw_fd(), temporary.as_ptr(), 0);
                }
            }
        }
        result
    }
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[derive(PartialEq, Eq)]
struct Snapshot {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    nlink: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}
impl From<&Metadata> for Snapshot {
    fn from(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            mode: m.mode(),
            uid: m.uid(),
            nlink: m.nlink(),
            size: m.len(),
            mtime: m.mtime(),
            mtime_nsec: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_nsec: m.ctime_nsec(),
        }
    }
}
fn validate_file(metadata: &Metadata) -> Result<(), Failure> {
    // SAFETY: geteuid has no arguments or memory-safety preconditions.
    validate_file_uid(metadata, unsafe { libc::geteuid() })
}
fn validate_file_uid(metadata: &Metadata, uid: u32) -> Result<(), Failure> {
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o400 == 0
        || metadata.mode() & 0o7133 != 0
    {
        return Err(Failure::Unsafe);
    }
    Ok(())
}

struct PinnedRead {
    file: File,
    initial: Snapshot,
    control: Control,
}
impl PinnedRead {
    fn read(mut self) -> Result<String, ControlError> {
        if self.initial.size > MAX_CONTROL_BYTES as u64 {
            return Err(self.control.error(Failure::TooLarge));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut self.file)
            .take(MAX_CONTROL_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| self.control.error(Failure::Unreadable))?;
        let after = self
            .file
            .metadata()
            .map_err(|_| self.control.error(Failure::Unreadable))?;
        if Snapshot::from(&after) != self.initial {
            return Err(self.control.error(Failure::Changed));
        }
        if bytes.len() > MAX_CONTROL_BYTES {
            return Err(self.control.error(Failure::TooLarge));
        }
        String::from_utf8(bytes).map_err(|_| self.control.error(Failure::Invalid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::{fs::symlink, net::UnixListener},
        sync::{Arc, Barrier},
    };

    fn private_home() -> tempfile::TempDir {
        let home = tempfile::tempdir().unwrap();
        fs::set_permissions(home.path(), Permissions::from_mode(0o700)).unwrap();
        home
    }

    fn write(home: &Path, control: Control, bytes: &[u8], mode: u32) {
        let path = home.join(control.name());
        if fs::symlink_metadata(&path).is_ok() {
            fs::remove_file(&path).unwrap();
        }
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn admitted_modes_and_both_controls_are_read_from_regular_single_link_files() {
        let home = private_home();
        let controls = ControlFiles::open(home.path()).unwrap();
        for mode in [0o400, 0o600, 0o644, 0o404] {
            for control in [Control::Config, Control::Instructions] {
                write(home.path(), control, b"complete snapshot", mode);
                assert_eq!(
                    controls.read(control).unwrap().as_deref(),
                    Some("complete snapshot")
                );
            }
        }
    }

    #[test]
    fn unsafe_modes_owner_and_nonregular_sources_are_rejected_before_consumption() {
        let home = private_home();
        let controls = ControlFiles::open(home.path()).unwrap();
        for control in [Control::Config, Control::Instructions] {
            let path = home.path().join(control.name());
            for mode in [0o000, 0o200, 0o660, 0o602, 0o601, 0o4600, 0o2600, 0o1600] {
                write(home.path(), control, &[0xff], mode);
                assert_eq!(
                    controls.read(control).unwrap_err().failure(),
                    Failure::Unsafe
                );
            }
            fs::remove_file(&path).unwrap();
            fs::create_dir(&path).unwrap();
            assert_eq!(
                controls.read(control).unwrap_err().failure(),
                Failure::Unsafe
            );
            fs::remove_dir(&path).unwrap();
            let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY: this temporary path is owned by the test.
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            assert_eq!(
                controls.read(control).unwrap_err().failure(),
                Failure::Unsafe
            );
            fs::remove_file(&path).unwrap();
            let socket = UnixListener::bind(&path).unwrap();
            assert_eq!(
                controls.read(control).unwrap_err().failure(),
                Failure::Unsafe
            );
            drop(socket);
            fs::remove_file(&path).unwrap();
        }
        write(home.path(), Control::Config, b"valid", 0o600);
        let metadata = fs::metadata(home.path().join("config.toml")).unwrap();
        assert_eq!(
            validate_file_uid(&metadata, metadata.uid().wrapping_add(1)),
            Err(Failure::Unsafe)
        );
        assert_eq!(
            validate_file(&fs::metadata("/dev/null").unwrap()),
            Err(Failure::Unsafe)
        );
    }

    #[test]
    fn symlinks_chains_dangling_links_and_hardlinks_are_never_control_sources() {
        let home = private_home();
        let external = tempfile::tempdir().unwrap();
        let target = external.path().join("extension-writable");
        fs::write(&target, "external data").unwrap();
        let controls = ControlFiles::open(home.path()).unwrap();
        fs::write(home.path().join("relative-target"), "relative data").unwrap();
        for control in [Control::Config, Control::Instructions] {
            let path = home.path().join(control.name());
            for destination in [
                target.clone(),
                PathBuf::from("relative-target"),
                PathBuf::from("missing"),
            ] {
                symlink(&destination, &path).unwrap();
                assert_eq!(
                    controls.read(control).unwrap_err().failure(),
                    Failure::Unsafe
                );
                fs::remove_file(&path).unwrap();
            }
            symlink(&target, home.path().join("chain")).unwrap();
            symlink("chain", &path).unwrap();
            assert_eq!(
                controls.read(control).unwrap_err().failure(),
                Failure::Unsafe
            );
            fs::remove_file(&path).unwrap();
            fs::remove_file(home.path().join("chain")).unwrap();
            for source in [&target, &home.path().join("internal")] {
                if !source.exists() {
                    fs::write(source, "shared inode").unwrap();
                }
                fs::hard_link(source, &path).unwrap();
                assert_eq!(
                    controls.read(control).unwrap_err().failure(),
                    Failure::Unsafe
                );
                fs::remove_file(&path).unwrap();
            }
        }
        assert_eq!(fs::read_to_string(target).unwrap(), "external data");
    }

    #[test]
    fn observed_metadata_changes_and_renames_fail_without_a_partial_snapshot() {
        let home = private_home();
        let controls = ControlFiles::open(home.path()).unwrap();
        for control in [Control::Config, Control::Instructions] {
            for change in ["write", "mode", "rename", "symlink", "fifo"] {
                write(home.path(), control, b"original complete snapshot", 0o600);
                let read = controls.pinned(control).unwrap().unwrap();
                let path = home.path().join(control.name());
                match change {
                    "write" => fs::write(&path, "new snapshot with different length").unwrap(),
                    "mode" => fs::set_permissions(&path, Permissions::from_mode(0o400)).unwrap(),
                    "rename" => {
                        let replacement = home.path().join("replacement");
                        fs::write(&replacement, "new complete snapshot").unwrap();
                        fs::rename(replacement, &path).unwrap();
                    }
                    "symlink" => {
                        fs::remove_file(&path).unwrap();
                        symlink("missing", &path).unwrap();
                    }
                    "fifo" => {
                        fs::remove_file(&path).unwrap();
                        let name =
                            std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
                        // SAFETY: this test owns the direct temporary path.
                        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                    }
                    _ => unreachable!(),
                }
                assert_eq!(
                    read.read().unwrap_err().failure(),
                    Failure::Changed,
                    "{change}"
                );
                fs::remove_file(path).unwrap();
            }
        }
    }

    #[test]
    fn anchored_home_alias_does_not_retarget_and_control_descriptors_are_cloexec() {
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("first");
        let second = root.path().join("second");
        crate::home::private_dir(&first).unwrap();
        crate::home::private_dir(&second).unwrap();
        write(&first, Control::Config, b"first", 0o600);
        write(&second, Control::Config, b"second", 0o600);
        let alias = root.path().join("alias");
        symlink(&first, &alias).unwrap();
        let controls = ControlFiles::open(&alias).unwrap();
        fs::remove_file(&alias).unwrap();
        symlink(&second, &alias).unwrap();
        assert_eq!(controls.config().unwrap(), "first");
        assert_eq!(
            ControlFiles::open(&alias).unwrap().config().unwrap(),
            "second"
        );
        let read = controls.pinned(Control::Config).unwrap().unwrap();
        for fd in [controls.directory.as_raw_fd(), read.file.as_raw_fd()] {
            // SAFETY: these descriptors are live; F_GETFD takes no pointer.
            assert_ne!(
                unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
        }
    }

    #[test]
    fn only_actual_optional_absence_is_none_and_limits_precede_decoding() {
        let home = private_home();
        let controls = ControlFiles::open(home.path()).unwrap();
        assert_eq!(controls.instructions().unwrap(), None);
        assert_eq!(
            controls.config().unwrap_err().failure(),
            Failure::Unreadable
        );
        write(home.path(), Control::Instructions, b"", 0o600);
        assert_eq!(controls.instructions().unwrap().as_deref(), Some(""));
        write(home.path(), Control::Instructions, &[0xff], 0o600);
        assert_eq!(
            controls.instructions().unwrap_err().failure(),
            Failure::Invalid
        );
        OpenOptions::new()
            .write(true)
            .open(home.path().join("AGENTS.md"))
            .unwrap()
            .set_len(MAX_CONTROL_BYTES as u64 + 1)
            .unwrap();
        assert_eq!(
            controls.instructions().unwrap_err().failure(),
            Failure::TooLarge
        );
        fs::set_permissions(home.path(), Permissions::from_mode(0o750)).unwrap();
        assert_eq!(
            controls.instructions().unwrap_err().failure(),
            Failure::Unsafe
        );
        fs::set_permissions(home.path(), Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(home.path()).unwrap();
        assert_eq!(
            controls.instructions().unwrap_err().failure(),
            Failure::Unreadable
        );
    }

    #[test]
    fn concurrent_creation_publishes_one_complete_new_inode_without_overwriting() {
        let home = private_home();
        let controls = Arc::new(ControlFiles::open(home.path()).unwrap());
        let barrier = Arc::new(Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|index| {
                let controls = controls.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let bytes = vec![b'A' + index; 1024 * 1024];
                    barrier.wait();
                    controls.create_config_if_missing(&bytes)
                })
            })
            .collect();
        let results: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert!(results.iter().any(Result::is_ok));
        let bytes = fs::read(home.path().join("config.toml")).unwrap();
        assert_eq!(bytes.len(), 1024 * 1024);
        assert!(bytes.iter().all(|byte| *byte == bytes[0]));
        let initial = fs::metadata(home.path().join("config.toml")).unwrap();
        assert_eq!(initial.mode() & 0o7777, 0o600);
        assert_eq!(initial.nlink(), 1);
        controls
            .create_config_if_missing(b"do not overwrite")
            .unwrap();
        assert_eq!(fs::read(home.path().join("config.toml")).unwrap(), bytes);
        assert_eq!(
            fs::metadata(home.path().join("config.toml")).unwrap().ino(),
            initial.ino()
        );
    }
}
