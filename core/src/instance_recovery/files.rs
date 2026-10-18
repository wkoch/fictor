use super::{InstanceError, LegacyResources, StateRecord, valid_id};
use crate::ownership::HomeLease;
use std::{
    collections::VecDeque,
    ffi::{CStr, CString, OsString},
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
};

const MAX_STATE: usize = 64 * 1024;

pub(super) fn legacy_resources(owner: &HomeLease) -> LegacyResources {
    let mut found = LegacyResources::default();
    let pid_files = || -> io::Result<bool> {
        let home = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(owner.anchored_path().join("."))?;
        let run = open_directory(&home, c"run")?;
        private_directory(&run)?;
        // The private home anchors this namespace; foreign/unknown ownership
        // does not erase an unidentifiable legacy entry inside its run/.
        any_legacy(&run, None, |name| name.len() > 4 && name.ends_with(b".pid"))
    };
    match pid_files() {
        Ok(value) => found.pid_files = value,
        Err(_) => found.scan_unavailable = true,
    }
    let temporary = || -> io::Result<bool> {
        // Exactly the current mount namespace's /tmp. Never search other
        // namespaces or recurse through an entry whose ownership is unproven.
        let tmp = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/tmp")?;
        any_legacy(&tmp, Some(uid()), |name| {
            name == b"fictor" || name.starts_with(b"fictor-")
        })
    };
    match temporary() {
        Ok(value) => found.temporaries = value,
        Err(_) => found.scan_unavailable = true,
    }
    found
}

fn any_legacy(
    directory: &File,
    expected_uid: Option<u32>,
    matches: impl Fn(&[u8]) -> bool,
) -> io::Result<bool> {
    let independent = open_directory(directory, c".")?;
    let fd = independent.into_raw_fd();
    // SAFETY: fdopendir takes ownership of this directory on success.
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: fdopendir failed, so the descriptor remains ours.
        drop(unsafe { File::from_raw_fd(fd) });
        return Err(error);
    }
    let stream = Stream(stream);
    loop {
        // SAFETY: errno is thread-local and the directory stream is live.
        let entry = unsafe {
            *libc::__errno_location() = 0;
            libc::readdir(stream.0)
        };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(0) {
                Ok(false)
            } else {
                Err(error)
            };
        }
        // SAFETY: this entry's NUL-terminated name lives until the next readdir.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if !matches(name.to_bytes()) {
            continue;
        }
        // Observe the directory entry itself. Do not open a legacy FIFO, read a
        // PID, follow symlinks or trigger an automount to determine ownership.
        let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: the direct entry and the output storage remain live.
        if unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                name.as_ptr(),
                &mut metadata,
                libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT,
            )
        } != 0
        {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                continue;
            }
            return Err(error);
        }
        if expected_uid.is_none_or(|uid| metadata.st_uid == uid) {
            return Ok(true);
        }
    }
}

pub(super) struct Directories {
    pub instances: File,
    kernel: File,
}
impl Directories {
    pub fn open(owner: &HomeLease, create: bool) -> Result<Self, InstanceError> {
        let home = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(owner.anchored_path().join("."))?;
        let run = open_directory(&home, c"run")?;
        private_directory(&run)?;
        let instances = match open_directory(&run, c"instances") {
            Ok(directory) => directory,
            Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                create_directory(&run, c"instances")?
            }
            Err(error) => return Err(error.into()),
        };
        private_directory(&instances)?;
        let kernel = open_directory(&run, c"k")?;
        private_directory(&kernel)?;
        Ok(Self { instances, kernel })
    }
    pub fn existing(owner: &HomeLease) -> Result<Option<Self>, InstanceError> {
        let home = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(owner.anchored_path().join("."))?;
        let run = open_directory(&home, c"run")?;
        private_directory(&run)?;
        let instances = match open_directory(&run, c"instances") {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        private_directory(&instances)?;
        // Once journals exist, another missing root is uncertainty rather than
        // a claim that there were no instances to inspect.
        let kernel = open_directory(&run, c"k")?;
        private_directory(&kernel)?;
        Ok(Some(Self { instances, kernel }))
    }
    pub fn create(&self, id: &str) -> Result<File, InstanceError> {
        if !valid_id(id) {
            return Err(InstanceError::Invalid);
        }
        Ok(create_directory(&self.instances, &component(id)?)?)
    }
    pub fn read(&self, id: &str) -> Result<(File, StateRecord), InstanceError> {
        let directory = open_directory(&self.instances, &component(id)?)?;
        private_directory(&directory)?;
        let record = read_record(&directory, id)?;
        Ok((directory, record))
    }
    pub fn cleanup(&self, directory: &File, record: &StateRecord) -> Result<(), InstanceError> {
        // Re-read the authoritative entry before mutation. Unknown siblings are
        // retained rather than treating their directory as an owned temp tree.
        if read_record(directory, &record.instance_id)? != *record {
            return Err(InstanceError::Uncertain);
        }
        private_directory(directory)?;
        let id = component(&record.instance_id)?;
        same_entry(&self.instances, &id, directory)?;
        let entries = names(directory)?;
        for name in &entries {
            if name == "tmp" || name == "state.json" {
                continue;
            }
            if name == "admission.sock" {
                let socket = open_at(directory, c"admission.sock", libc::O_PATH)?;
                private_socket(&socket)?;
                continue;
            }
            let Some(suffix) = name.to_str().and_then(|name| name.strip_prefix(".state-")) else {
                return Err(InstanceError::Uncertain);
            };
            if !valid_id(suffix) {
                return Err(InstanceError::Uncertain);
            }
            let temporary = open_at(directory, &component_os(name)?, libc::O_PATH)?;
            private_state(&temporary)?;
        }
        match open_directory(directory, c"tmp") {
            Ok(temporary) => {
                private_directory(&temporary)?;
                remove_tree(directory, c"tmp", temporary)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let socket = component(&format!("{}.sock", record.instance_id))?;
        match open_at(&self.kernel, &socket, libc::O_PATH) {
            Ok(file) => {
                private_socket(&file)?;
                same_entry(&self.kernel, &socket, &file)?;
                unlink(&self.kernel, &socket, 0)?;
                self.kernel.sync_all()?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        for name in entries {
            if name != "tmp" && name != "state.json" {
                if name == "admission.sock" {
                    let socket = open_at(directory, c"admission.sock", libc::O_PATH)?;
                    private_socket(&socket)?;
                    same_entry(directory, c"admission.sock", &socket)?;
                }
                unlink(directory, &component_os(&name)?, 0)?;
            }
        }
        directory.sync_all()?;
        // State and its directory are last. A crash before this point leaves
        // the same valid authority and retry accepts resources already absent.
        if read_record(directory, &record.instance_id)? != *record {
            return Err(InstanceError::Uncertain);
        }
        unlink(directory, c"state.json", 0)?;
        directory.sync_all()?;
        same_entry(&self.instances, &id, directory)?;
        unlink(&self.instances, &id, libc::AT_REMOVEDIR)?;
        self.instances.sync_all()?;
        Ok(())
    }
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}
fn component(name: &str) -> io::Result<CString> {
    component_os(std::ffi::OsStr::new(name))
}
fn component_os(name: &std::ffi::OsStr) -> io::Result<CString> {
    if name.is_empty() || name == "." || name == ".." || name.as_bytes().contains(&b'/') {
        return Err(io::Error::other("invalid journal component"));
    }
    CString::new(name.as_bytes()).map_err(|_| io::Error::other("invalid journal component"))
}
fn open_at(parent: &File, name: &CStr, flags: i32) -> io::Result<File> {
    // NO_XDEV rejects bind mounts too, including mounts on the same device.
    let nonblock = if flags & libc::O_PATH == 0 {
        libc::O_NONBLOCK
    } else {
        0
    };
    let how = OpenHow {
        flags: (flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | nonblock) as u64,
        mode: 0,
        resolve: 0x01 | 0x04 | 0x08,
    };
    // SAFETY: open_how matches Linux's ABI and all referenced storage is live.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            parent.as_raw_fd(),
            name.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful openat2 returned this new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}
fn open_directory(parent: &File, name: &CStr) -> io::Result<File> {
    open_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY)
}
fn uid() -> u32 {
    // SAFETY: geteuid has no arguments or preconditions.
    unsafe { libc::geteuid() }
}
fn private_directory(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != uid()
        || metadata.mode() & 0o7777 != 0o700
        || metadata.nlink() == 0
    {
        return Err(io::Error::other("unsafe instance directory"));
    }
    Ok(())
}
fn private_state(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != uid()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(io::Error::other("unsafe instance state"));
    }
    Ok(())
}
fn private_socket(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if metadata.mode() & libc::S_IFMT != libc::S_IFSOCK
        || metadata.uid() != uid()
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(io::Error::other("unsafe instance socket"));
    }
    Ok(())
}
pub(super) fn create_directory(parent: &File, name: &CStr) -> io::Result<File> {
    // SAFETY: parent is pinned, and name is a validated direct component.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } < 0 {
        return Err(io::Error::last_os_error());
    }
    parent.sync_all()?;
    let directory = open_directory(parent, name)?;
    private_directory(&directory)?;
    Ok(directory)
}
fn same_entry(parent: &File, name: &CStr, file: &File) -> io::Result<()> {
    let current = open_at(parent, name, libc::O_PATH)?;
    let a = current.metadata()?;
    let b = file.metadata()?;
    if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
        return Err(io::Error::other("instance entry changed"));
    }
    Ok(())
}
pub(super) fn read_record(directory: &File, id: &str) -> Result<StateRecord, InstanceError> {
    let file = open_at(directory, c"state.json", libc::O_RDONLY)?;
    private_state(&file)?;
    let before = file.metadata()?;
    if before.len() > MAX_STATE as u64 {
        return Err(InstanceError::Invalid);
    }
    let mut bytes = Vec::new();
    (&file).take(MAX_STATE as u64 + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() > MAX_STATE
        || bytes.len() as u64 != before.len()
        || (
            before.dev(),
            before.ino(),
            before.len(),
            before.ctime(),
            before.ctime_nsec(),
            before.mtime(),
            before.mtime_nsec(),
            before.nlink(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.ctime(),
            after.ctime_nsec(),
            after.mtime(),
            after.mtime_nsec(),
            after.nlink(),
        )
    {
        return Err(InstanceError::Uncertain);
    }
    same_entry(directory, c"state.json", &file)?;
    StateRecord::parse(&bytes, id)
}
pub(super) fn publish(directory: &File, record: &StateRecord) -> Result<(), InstanceError> {
    let bytes = serde_json::to_vec(record).map_err(|_| InstanceError::Invalid)?;
    if bytes.len() > MAX_STATE {
        return Err(InstanceError::Invalid);
    }
    let name = component(&format!(".state-{}", ulid::Ulid::generate()))?;
    // SAFETY: exclusive creation uses a fresh direct name in the pinned parent.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: openat returned a fresh descriptor exclusively owned here.
    let mut file = unsafe { File::from_raw_fd(fd) };
    private_state(&file)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    // SAFETY: both names are direct components of the live pinned directory.
    if unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            name.as_ptr(),
            directory.as_raw_fd(),
            c"state.json".as_ptr(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error().into());
    }
    directory.sync_all()?;
    Ok(())
}
struct Stream(*mut libc::DIR);
impl Drop for Stream {
    fn drop(&mut self) {
        // SAFETY: fdopendir transferred sole ownership to this guard.
        unsafe {
            libc::closedir(self.0);
        }
    }
}
pub(super) fn names(directory: &File) -> io::Result<Vec<OsString>> {
    let independent = open_directory(directory, c".")?;
    let fd = independent.into_raw_fd();
    // SAFETY: fdopendir takes ownership of this directory on success.
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        let error = io::Error::last_os_error(); // SAFETY: fdopendir failed, ownership is still ours.
        drop(unsafe { File::from_raw_fd(fd) });
        return Err(error);
    }
    let stream = Stream(stream);
    let mut names = Vec::new();
    loop {
        // SAFETY: errno is thread-local; the directory stream remains live.
        let entry = unsafe {
            *libc::__errno_location() = 0;
            libc::readdir(stream.0)
        };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(0) {
                Ok(names)
            } else {
                Err(error)
            };
        }
        // SAFETY: readdir's entry has a NUL-terminated name until the next call.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(OsString::from_vec(name.to_vec()));
        }
    }
}
fn unlink(parent: &File, name: &CStr, flags: i32) -> io::Result<()> {
    // SAFETY: parent is live, and name is a direct component, never followed.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) } < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotFound {
            return Err(error);
        }
    }
    Ok(())
}
fn remove_tree(parent: &File, name: &CStr, directory: File) -> io::Result<()> {
    struct Frame {
        directory: File,
        name: CString,
        children: VecDeque<OsString>,
    }
    let mut stack = vec![Frame {
        children: names(&directory)?.into(),
        directory,
        name: name.to_owned(),
    }];
    while let Some(frame) = stack.last_mut() {
        if let Some(name) = frame.children.pop_front() {
            let name = component_os(&name)?;
            let entry = open_at(&frame.directory, &name, libc::O_PATH)?;
            if entry.metadata()?.is_dir() {
                let directory = open_directory(&frame.directory, &name)?;
                let before = entry.metadata()?;
                let opened = directory.metadata()?;
                if (before.dev(), before.ino()) != (opened.dev(), opened.ino()) {
                    return Err(io::Error::other("instance directory changed"));
                }
                same_entry(&frame.directory, &name, &directory)?;
                let children = names(&directory)?.into();
                stack.push(Frame {
                    directory,
                    name,
                    children,
                });
            } else {
                same_entry(&frame.directory, &name, &entry)?;
                unlink(&frame.directory, &name, 0)?;
            }
        } else {
            let frame = stack
                .pop()
                .ok_or_else(|| io::Error::other("instance traversal"))?;
            let parent = stack.last().map_or(parent, |frame| &frame.directory);
            frame.directory.sync_all()?;
            same_entry(parent, &frame.name, &frame.directory)?;
            unlink(parent, &frame.name, libc::AT_REMOVEDIR)?;
            parent.sync_all()?;
        }
    }
    Ok(())
}
