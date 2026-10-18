//! ADR-044's first-exec boundary. Preparation may allocate; `enter` must not.
//! The installed system remains the TCB: this freezes mount topology, not every
//! byte in /usr. Only the trusted bootstrap gets a private byte snapshot.
use super::mounts::{SnapshotEntry, SourceSnapshot};
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::{Component, Path, PathBuf},
    process::Command,
};

const NO_MAGICLINKS: u64 = 0x02;
const PATH_BYTES: usize = 4096;
const REQUIRED_STATX: u32 = libc::STATX_INO | libc::STATX_MNT_ID | libc::STATX_TYPE;

#[derive(Clone, Copy)]
struct Object {
    device: (u32, u32),
    inode: u64,
    kind: u16,
    magic: u64,
}
struct Entry {
    path: CString,
    object: Object,
    filesystem: Vec<u8>,
}
struct Source {
    path: CString,
    canonical: CString,
    entries: Vec<Entry>,
    directory: bool,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
impl Stamp {
    fn metadata(value: &std::fs::Metadata) -> Self {
        Self {
            size: value.len(),
            mtime: (value.mtime(), value.mtime_nsec()),
            ctime: (value.ctime(), value.ctime_nsec()),
        }
    }
    fn statx(value: &libc::statx) -> Self {
        Self {
            size: value.stx_size,
            mtime: (value.stx_mtime.tv_sec, i64::from(value.stx_mtime.tv_nsec)),
            ctime: (value.stx_ctime.tv_sec, i64::from(value.stx_ctime.tv_nsec)),
        }
    }
}

/// All strings, buffers, expected metadata and FD names are made before fork.
/// The caller reserves `alias` inside the instance's protected preparation tree,
/// uses it only as bwrap's bootstrap SRC, and uses bootstrap_snapshot for the
/// final /fx/fictor proof. The destination and grants do not change.
pub(super) struct Prepared {
    sources: Vec<Source>,
    _anchors: Vec<File>,
    bootstrap: CString,
    bootstrap_object: Object,
    bootstrap_stamp: Stamp,
    alias: PathBuf,
    alias_c: CString,
    alias_object: Object,
    alias_stamp: Stamp,
    _alias_anchor: File,
    directory: CString,
    directory_object: Object,
    _directory_anchor: File,
    bootstrap_snapshot: SourceSnapshot,
    uid_map: Vec<u8>,
    gid_map: Vec<u8>,
    parent_pid: libc::pid_t,
    mountinfo: Box<[u8]>,
    scratch: Box<[u8]>,
}

impl Prepared {
    pub(super) fn new(
        observations: Vec<(PathBuf, SourceSnapshot)>,
        bootstrap: &Path,
        alias: &Path,
    ) -> io::Result<Self> {
        let mut anchors = Vec::new();
        let mut sources = Vec::new();
        for (path, snapshot) in observations {
            let reference = cpath(&path)?;
            let root = open_path(&reference)?;
            let canonical_path = std::fs::read_link(format!("/proc/self/fd/{}", root.as_raw_fd()))?;
            let canonical = cpath(&canonical_path)?;
            if snapshot.entries.is_empty()
                || !snapshot
                    .entries
                    .iter()
                    .any(|e| e.relative.as_os_str().is_empty())
            {
                return Err(invalid());
            }
            let mut entries = Vec::new();
            for expected in snapshot.entries {
                if expected
                    .relative
                    .components()
                    .any(|c| !matches!(c, Component::Normal(_)))
                {
                    return Err(invalid());
                }
                let path = if expected.relative.as_os_str().is_empty() {
                    cpath(&canonical_path)?
                } else {
                    cpath(&canonical_path.join(&expected.relative))?
                };
                if entries.iter().any(|e: &Entry| e.path == path) {
                    return Err(invalid());
                }
                let anchor = open_path(&path)?;
                let object = object(anchor.as_raw_fd())?.0;
                if object.device != expected.device
                    || object.inode != expected.inode
                    || object.magic != expected.filesystem_magic
                {
                    return Err(invalid());
                }
                entries.push(Entry {
                    path,
                    object,
                    filesystem: expected.filesystem.into_bytes(),
                });
                anchors.push(anchor);
            }
            let directory = root.metadata()?.is_dir();
            sources.push(Source {
                path: reference,
                canonical,
                entries,
                directory,
            });
            anchors.push(root);
        }
        let bootstrap = cpath(bootstrap)?;
        let source = sources
            .iter()
            .find(|source| source.path == bootstrap)
            .ok_or_else(invalid)?;
        let original = open_path(&bootstrap)?;
        let original_object = object(original.as_raw_fd())?.0;
        let expected = source
            .entries
            .iter()
            .find(|entry| entry.path == source.canonical)
            .ok_or_else(invalid)?;
        if !same(original_object, expected.object) || original_object.kind != libc::S_IFREG as u16 {
            return Err(invalid());
        }
        let metadata = original.metadata()?;
        if metadata.mode() & 0o111 == 0 {
            return Err(invalid());
        }
        let stamp = Stamp::metadata(&metadata);
        let mut readable = File::open(format!("/proc/self/fd/{}", original.as_raw_fd()))?;
        // The caller creates this directory exclusively in the protected
        // instance preparation tree. No extension can traverse its ancestors.
        // It intentionally has no Drop cleanup: the outer instance owner alone
        // removes it after the sandbox has been reaped.
        let directory = cpath(alias.parent().ok_or_else(invalid)?)?;
        let directory_anchor = open_path(&directory)?;
        let directory_object = object(directory_anchor.as_raw_fd())?.0;
        let metadata = directory_anchor.metadata()?;
        // SAFETY: geteuid/getegid/getpid have no pointer arguments.
        let (uid, gid, parent_pid) = unsafe { (libc::geteuid(), libc::getegid(), libc::getpid()) };
        if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o7777 != 0o700 {
            return Err(invalid());
        }
        let alias_c = cpath(alias)?;
        let mut image = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(alias)?;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = readable.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            image.write_all(&buffer[..count])?;
        }
        if Stamp::metadata(&original.metadata()?) != stamp || image.metadata()?.len() != stamp.size
        {
            return Err(invalid());
        }
        image.set_permissions(std::fs::Permissions::from_mode(0o500))?;
        let image_object = object(image.as_raw_fd())?.0;
        // Linux refuses exec while any writable descriptor is open. Retain only
        // O_PATH anchors, which also prevent identity reuse until Command drops.
        drop(image);
        let alias_anchor = open_path(&alias_c)?;
        let (alias_object, alias_stat) = object(alias_anchor.as_raw_fd())?;
        let metadata = alias_anchor.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != uid
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o500
            || !same(image_object, alias_object)
        {
            return Err(invalid());
        }
        let alias_stamp = Stamp::metadata(&metadata);
        let directory_after = open_path(&directory)?;
        if !same(directory_object, object(directory_after.as_raw_fd())?.0) {
            return Err(invalid());
        }
        let table = std::fs::read("/proc/self/mountinfo")?;
        let mount = table
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(mount_line)
            .collect::<io::Result<Vec<_>>>()?
            .into_iter()
            .find(|mount| mount.id == alias_stat.stx_mnt_id)
            .ok_or_else(invalid)?;
        let filesystem = std::str::from_utf8(mount.filesystem).map_err(|_| invalid())?;
        if !super::mounts::ordinary_filesystem(filesystem, alias_object.magic) {
            return Err(invalid());
        }
        // New namespace IDs can acquire more decimal digits. This preallocated
        // bound does not accept truncation; topology growth/overflow fails closed.
        let capacity = table
            .len()
            .checked_mul(4)
            .and_then(|n| n.checked_add(4096))
            .ok_or_else(invalid)?;
        Ok(Self {
            sources,
            _anchors: anchors,
            bootstrap,
            bootstrap_object: original_object,
            bootstrap_stamp: stamp,
            alias: alias.to_owned(),
            alias_c,
            alias_object,
            alias_stamp,
            _alias_anchor: alias_anchor,
            directory,
            directory_object,
            _directory_anchor: directory_anchor,
            bootstrap_snapshot: SourceSnapshot {
                entries: vec![SnapshotEntry {
                    relative: PathBuf::new(),
                    device: alias_object.device,
                    inode: alias_object.inode,
                    filesystem: filesystem.into(),
                    filesystem_magic: alias_object.magic,
                }],
                private: true,
            },
            uid_map: format!("0 {uid} 1\n").into_bytes(),
            gid_map: format!("0 {gid} 1\n").into_bytes(),
            parent_pid,
            mountinfo: vec![0; capacity].into_boxed_slice(),
            scratch: vec![0; PATH_BYTES + 1].into_boxed_slice(),
        })
    }
    pub(super) fn bootstrap_alias(&self) -> &Path {
        &self.alias
    }
    pub(super) fn bootstrap_snapshot(&self) -> &SourceSnapshot {
        &self.bootstrap_snapshot
    }

    /// Does not replace env_clear, the final namespace attestation or either
    /// admission gate. The callback runs in the forked child, before any exec.
    pub(super) fn install(mut self, command: &mut Command) {
        // SAFETY: enter uses only direct Linux syscalls and preallocated memory.
        // No logging, locks, allocation, unwinding or libc NSS/loader work occurs.
        unsafe {
            command.pre_exec(move || self.enter());
        }
    }

    fn enter(&mut self) -> io::Result<()> {
        parent_guard(self.parent_pid)?;
        call(
            libc::SYS_unshare,
            [u(libc::CLONE_NEWUSER | libc::CLONE_NEWNS), 0, 0, 0, 0, 0],
        )?;
        write_control(c"/proc/self/setgroups", b"deny")?;
        write_control(c"/proc/self/uid_map", &self.uid_map)?;
        write_control(c"/proc/self/gid_map", &self.gid_map)?;
        parent_guard(self.parent_pid)?;
        call(
            libc::SYS_mount,
            [
                0,
                c"/".as_ptr() as usize,
                0,
                (libc::MS_REC | libc::MS_PRIVATE) as usize,
                0,
                0,
            ],
        )?;
        let fd = call(
            libc::SYS_openat,
            [
                libc::AT_FDCWD as usize,
                c"/proc/self/mountinfo".as_ptr() as usize,
                (libc::O_RDONLY | libc::O_CLOEXEC) as usize,
                0,
                0,
                0,
            ],
        )? as RawFd;
        let length = read_bounded(fd, &mut self.mountinfo);
        close_raw(fd);
        let length = length?;
        let table = self.mountinfo.get(..length).ok_or_else(invalid)?;
        for source in &self.sources {
            verify_source(source, table, &mut self.scratch)?;
        }
        self.verify_bootstrap()?;
        // Mapping above makes the creating core UID be zero in this namespace.
        let alias = self.verified_alias(0)?;
        // Pin the named core copy through an FD opened in this private view.
        // Unlike an anonymous memfd this is bindable on older supported kernels;
        // bwrap 0.6's realpath(SRC) then resolves a pinned named mountpoint.
        let mut target = [0u8; 32];
        let mounted = fd_path(alias, &mut target).and_then(|target| {
            call(
                libc::SYS_mount,
                [
                    target.as_ptr() as usize,
                    target.as_ptr() as usize,
                    0,
                    libc::MS_BIND as usize,
                    0,
                    0,
                ],
            )
        });
        close_raw(alias);
        mounted?;
        parent_guard(self.parent_pid)
    }

    fn verify_bootstrap(&self) -> io::Result<()> {
        let original = open_raw(&self.bootstrap)?;
        let actual = object(original);
        close_raw(original);
        let (object, stat) = actual?;
        if !same(object, self.bootstrap_object) || Stamp::statx(&stat) != self.bootstrap_stamp {
            return Err(invalid());
        }
        Ok(())
    }

    fn verified_alias(&self, uid: u32) -> io::Result<RawFd> {
        let directory = open_raw(&self.directory)?;
        let actual = object(directory);
        close_raw(directory);
        let (actual, stat) = actual?;
        if !same(actual, self.directory_object)
            || stat.stx_uid != uid
            || stat.stx_mode & 0o7777 != 0o700
        {
            return Err(invalid());
        }
        let alias = open_raw(&self.alias_c)?;
        let valid = object(alias).is_ok_and(|(actual, stat)| {
            same(actual, self.alias_object)
                && Stamp::statx(&stat) == self.alias_stamp
                && stat.stx_uid == uid
                && stat.stx_nlink == 1
                && stat.stx_mode & 0o7777 == 0o500
        });
        if !valid {
            close_raw(alias);
            return Err(invalid());
        }
        Ok(alias)
    }
}

fn invalid() -> io::Error {
    io::Error::from_raw_os_error(libc::EACCES)
}
fn cpath(path: &Path) -> io::Result<CString> {
    if !path.is_absolute() {
        return Err(invalid());
    }
    CString::new(path.as_os_str().as_bytes()).map_err(|_| invalid())
}
fn same(left: Object, right: Object) -> bool {
    left.device == right.device
        && left.inode == right.inode
        && left.kind == right.kind
        && left.magic == right.magic
}
fn u(value: i32) -> usize {
    value as u32 as usize
}

/// x86-64 is the sole supported platform. No libc lazy symbol resolution can
/// acquire a loader lock in the interval between fork and exec.
fn call(number: libc::c_long, args: [usize; 6]) -> io::Result<usize> {
    let mut result = number as isize;
    // SAFETY: Linux syscall ABI; pointer validity is established at each call.
    unsafe {
        std::arch::asm!("syscall",inlateout("rax") result,in("rdi") args[0],in("rsi") args[1],in("rdx") args[2],in("r10") args[3],in("r8") args[4],in("r9") args[5],lateout("rcx") _,lateout("r11") _,options(nostack));
    }
    if (-4095..0).contains(&result) {
        Err(io::Error::from_raw_os_error(-result as i32))
    } else {
        Ok(result as usize)
    }
}
fn parent_guard(parent: libc::pid_t) -> io::Result<()> {
    call(
        libc::SYS_prctl,
        [u(libc::PR_SET_PDEATHSIG), u(libc::SIGKILL), 0, 0, 0, 0],
    )?;
    if call(libc::SYS_getppid, [0; 6])? != parent as usize {
        return Err(invalid());
    }
    Ok(())
}
fn close_raw(fd: RawFd) {
    let _ = call(libc::SYS_close, [fd as usize, 0, 0, 0, 0, 0]);
}
fn open_raw(path: &std::ffi::CStr) -> io::Result<RawFd> {
    #[repr(C)]
    struct How {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = How {
        flags: (libc::O_PATH | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: NO_MAGICLINKS,
    };
    call(
        libc::SYS_openat2,
        [
            libc::AT_FDCWD as usize,
            path.as_ptr() as usize,
            &how as *const How as usize,
            std::mem::size_of::<How>(),
            0,
            0,
        ],
    )
    .and_then(|fd| i32::try_from(fd).map_err(|_| invalid()))
}
fn open_path(path: &std::ffi::CStr) -> io::Result<File> {
    let fd = open_raw(path)?;
    // SAFETY: open_raw returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn fd_path(fd: RawFd, output: &mut [u8; 32]) -> io::Result<&std::ffi::CStr> {
    if fd < 0 {
        return Err(invalid());
    }
    let prefix = b"/proc/self/fd/";
    output
        .get_mut(..prefix.len())
        .ok_or_else(invalid)?
        .copy_from_slice(prefix);
    let mut digits = [0u8; 10];
    let mut value = fd as u32;
    let mut count = 0usize;
    loop {
        *digits.get_mut(count).ok_or_else(invalid)? = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for (index, digit) in digits
        .get(..count)
        .ok_or_else(invalid)?
        .iter()
        .rev()
        .enumerate()
    {
        *output.get_mut(prefix.len() + index).ok_or_else(invalid)? = *digit;
    }
    *output.get_mut(prefix.len() + count).ok_or_else(invalid)? = 0;
    std::ffi::CStr::from_bytes_with_nul(output.get(..prefix.len() + count + 1).ok_or_else(invalid)?)
        .map_err(|_| invalid())
}
fn write_control(path: &std::ffi::CStr, bytes: &[u8]) -> io::Result<()> {
    let fd = call(
        libc::SYS_openat,
        [
            libc::AT_FDCWD as usize,
            path.as_ptr() as usize,
            (libc::O_WRONLY | libc::O_CLOEXEC) as usize,
            0,
            0,
            0,
        ],
    )? as RawFd;
    let result = call(
        libc::SYS_write,
        [fd as usize, bytes.as_ptr() as usize, bytes.len(), 0, 0, 0],
    );
    close_raw(fd);
    if result? != bytes.len() {
        return Err(invalid());
    }
    Ok(())
}
fn read_bounded(fd: RawFd, buffer: &mut [u8]) -> io::Result<usize> {
    let mut length = 0;
    loop {
        if length == buffer.len() {
            return Err(io::Error::from_raw_os_error(libc::EOVERFLOW));
        }
        let output = buffer.get_mut(length..).ok_or_else(invalid)?;
        let count = match call(
            libc::SYS_read,
            [
                fd as usize,
                output.as_mut_ptr() as usize,
                output.len(),
                0,
                0,
                0,
            ],
        ) {
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
            result => result?,
        };
        if count == 0 {
            return Ok(length);
        }
        length = length.checked_add(count).ok_or_else(invalid)?;
    }
}
fn object(fd: RawFd) -> io::Result<(Object, libc::statx)> {
    // SAFETY: both all-zero C ABI output buffers are valid before the syscalls.
    let mut stat: libc::statx = unsafe { std::mem::zeroed() };
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    let requested = REQUIRED_STATX
        | libc::STATX_SIZE
        | libc::STATX_MTIME
        | libc::STATX_CTIME
        | libc::STATX_UID
        | libc::STATX_MODE
        | libc::STATX_NLINK;
    call(
        libc::SYS_statx,
        [
            fd as usize,
            c"".as_ptr() as usize,
            libc::AT_EMPTY_PATH as usize,
            requested as usize,
            &mut stat as *mut libc::statx as usize,
            0,
        ],
    )?;
    if stat.stx_mask & requested != requested {
        return Err(invalid());
    }
    call(
        libc::SYS_fstatfs,
        [
            fd as usize,
            &mut fs as *mut libc::statfs as usize,
            0,
            0,
            0,
            0,
        ],
    )?;
    Ok((
        Object {
            device: (stat.stx_dev_major, stat.stx_dev_minor),
            inode: stat.stx_ino,
            kind: stat.stx_mode & libc::S_IFMT as u16,
            magic: fs.f_type as u32 as u64,
        },
        stat,
    ))
}

struct Mount<'a> {
    id: u64,
    point: &'a [u8],
    filesystem: &'a [u8],
    private: bool,
}
fn number(bytes: &[u8]) -> io::Result<u64> {
    if bytes.is_empty() {
        return Err(invalid());
    }
    bytes.iter().try_fold(0u64, |n, byte| {
        if !byte.is_ascii_digit() {
            return Err(invalid());
        }
        n.checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(byte - b'0')))
            .ok_or_else(invalid)
    })
}
fn mount_line(line: &[u8]) -> io::Result<Mount<'_>> {
    let mut fields = line.split(|byte| *byte == b' ');
    let id = number(fields.next().ok_or_else(invalid)?)?;
    number(fields.next().ok_or_else(invalid)?)?;
    let device = fields.next().ok_or_else(invalid)?;
    let mut parts = device.split(|byte| *byte == b':');
    number(parts.next().ok_or_else(invalid)?)?;
    number(parts.next().ok_or_else(invalid)?)?;
    if parts.next().is_some() {
        return Err(invalid());
    }
    fields
        .next()
        .filter(|root| root.starts_with(b"/"))
        .ok_or_else(invalid)?;
    let point = fields
        .next()
        .filter(|point| point.starts_with(b"/"))
        .ok_or_else(invalid)?;
    fields
        .next()
        .filter(|options| !options.is_empty())
        .ok_or_else(invalid)?;
    let mut private = true;
    loop {
        let field = fields.next().ok_or_else(invalid)?;
        if field == b"-" {
            break;
        }
        if field.is_empty() {
            return Err(invalid());
        }
        if field.starts_with(b"shared:")
            || field.starts_with(b"master:")
            || field.starts_with(b"propagate_from:")
        {
            private = false;
        }
    }
    let filesystem = fields
        .next()
        .filter(|fs| !fs.is_empty())
        .ok_or_else(invalid)?;
    fields
        .next()
        .filter(|source| !source.is_empty())
        .ok_or_else(invalid)?;
    fields
        .next()
        .filter(|options| !options.is_empty())
        .ok_or_else(invalid)?;
    if fields.next().is_some() {
        return Err(invalid());
    }
    Ok(Mount {
        id,
        point,
        filesystem,
        private,
    })
}
fn decoded(encoded: &[u8], output: &mut [u8]) -> io::Result<usize> {
    let mut cursor = 0;
    let mut length = 0;
    while let Some(byte) = encoded.get(cursor) {
        let value = if *byte == b'\\' {
            let digits = encoded.get(cursor + 1..cursor + 4).ok_or_else(invalid)?;
            if !digits.iter().all(|digit| (b'0'..=b'7').contains(digit)) {
                return Err(invalid());
            }
            cursor += 4;
            let [a, b, c] = digits else {
                return Err(invalid());
            };
            (a - b'0')
                .checked_mul(64)
                .and_then(|n| n.checked_add((b - b'0') * 8 + c - b'0'))
                .ok_or_else(invalid)?
        } else {
            cursor += 1;
            *byte
        };
        if value == 0 {
            return Err(invalid());
        }
        *output.get_mut(length).ok_or_else(invalid)? = value;
        length += 1;
    }
    *output.get_mut(length).ok_or_else(invalid)? = 0;
    Ok(length)
}
fn verify_source(source: &Source, table: &[u8], scratch: &mut [u8]) -> io::Result<()> {
    let root = open_raw(&source.path)?;
    let root_object = object(root);
    close_raw(root);
    let (root_object, root_stat) = root_object?;
    let expected = source
        .entries
        .iter()
        .find(|entry| entry.path == source.canonical)
        .ok_or_else(invalid)?;
    if !same(root_object, expected.object) {
        return Err(invalid());
    }
    let mut root_seen = false;
    let mut visible = 0usize;
    for line in table
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let mount = mount_line(line)?;
        if mount.id == root_stat.stx_mnt_id {
            if root_seen || !mount.private || mount.filesystem != expected.filesystem {
                return Err(invalid());
            }
            root_seen = true;
        }
        if !source.directory {
            continue;
        }
        let length = decoded(mount.point, scratch)?;
        let path = scratch.get(..length).ok_or_else(invalid)?;
        let canonical = source.canonical.as_bytes();
        if !path
            .strip_prefix(canonical)
            .is_some_and(|rest| rest.starts_with(b"/"))
        {
            continue;
        }
        let path_c =
            std::ffi::CStr::from_bytes_with_nul(scratch.get(..length + 1).ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
        let fd = open_raw(path_c)?;
        let current = object(fd);
        close_raw(fd);
        let (current, stat) = current?;
        if stat.stx_mnt_id != mount.id {
            continue;
        } // Covered, not visible.
        let entry = source
            .entries
            .iter()
            .find(|entry| entry.path.as_bytes() == path)
            .ok_or_else(invalid)?;
        if !mount.private || mount.filesystem != entry.filesystem || !same(current, entry.object) {
            return Err(invalid());
        }
        visible = visible.checked_add(1).ok_or_else(invalid)?;
    }
    if !root_seen || visible.checked_add(1) != Some(source.entries.len()) {
        return Err(invalid());
    }
    // Re-open every entry as well: a bind root replaced without changing its
    // mountinfo spelling must still match the pinned object, not just the ID.
    for entry in &source.entries {
        let fd = open_raw(&entry.path)?;
        let current = object(fd).map(|value| value.0);
        close_raw(fd);
        if !same(current?, entry.object) {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(path: &Path) -> SourceSnapshot {
        let file = open_path(&cpath(path).unwrap()).unwrap();
        let (object, stat) = object(file.as_raw_fd()).unwrap();
        let table = std::fs::read("/proc/self/mountinfo").unwrap();
        let mount = table
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| mount_line(line).unwrap())
            .find(|mount| mount.id == stat.stx_mnt_id)
            .unwrap();
        SourceSnapshot {
            entries: vec![SnapshotEntry {
                relative: PathBuf::new(),
                device: object.device,
                inode: object.inode,
                filesystem: std::str::from_utf8(mount.filesystem).unwrap().into(),
                filesystem_magic: object.magic,
            }],
            private: mount.private,
        }
    }

    #[test]
    fn private_bootstrap_snapshot_is_fixed_and_in_place_changes_are_refused() {
        let root = tempfile::tempdir_in("/dev/shm").unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("trusted-init");
        std::fs::write(&path, b"original-trusted-image").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let prepared = Prepared::new(
            vec![(path.clone(), snapshot(&path))],
            &path,
            &root.path().join("alias"),
        )
        .unwrap();
        prepared.verify_bootstrap().unwrap();
        assert_eq!(
            std::fs::read(prepared.bootstrap_alias()).unwrap(),
            b"original-trusted-image"
        );
        // SAFETY: geteuid has no pointer arguments.
        close_raw(prepared.verified_alias(unsafe { libc::geteuid() }).unwrap());
        std::fs::write(&path, b"changed in place after preparation").unwrap();
        assert_eq!(
            prepared.verify_bootstrap().unwrap_err().raw_os_error(),
            Some(libc::EACCES)
        );
        assert_eq!(
            prepared.bootstrap_snapshot().entries[0].inode,
            object(prepared._alias_anchor.as_raw_fd()).unwrap().0.inode
        );
        assert_eq!(
            std::fs::read(prepared.bootstrap_alias()).unwrap(),
            b"original-trusted-image"
        );
        std::fs::set_permissions(
            prepared.bootstrap_alias(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::write(prepared.bootstrap_alias(), b"changed private image").unwrap();
        assert_eq!(
            prepared
                .verified_alias(unsafe { libc::geteuid() })
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
    }

    #[test]
    fn captured_source_refuses_a_replacement_inode_before_exec() {
        let root = tempfile::tempdir_in("/dev/shm").unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("trusted-init");
        std::fs::write(&path, b"trusted").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let prepared = Prepared::new(
            vec![(path.clone(), snapshot(&path))],
            &path,
            &root.path().join("alias"),
        )
        .unwrap();
        let file = open_path(&cpath(&path).unwrap()).unwrap();
        let (_, stat) = object(file.as_raw_fd()).unwrap();
        let fs = std::str::from_utf8(&prepared.sources[0].entries[0].filesystem).unwrap();
        // A private mount view fixture; identities are read from real FDs.
        let table = format!("{} 1 0:1 / / rw - {fs} source rw\n", stat.stx_mnt_id);
        verify_source(
            &prepared.sources[0],
            table.as_bytes(),
            &mut [0; PATH_BYTES + 1],
        )
        .unwrap();
        std::fs::rename(&path, root.path().join("old-init")).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        assert_eq!(
            verify_source(
                &prepared.sources[0],
                table.as_bytes(),
                &mut [0; PATH_BYTES + 1]
            )
            .unwrap_err()
            .raw_os_error(),
            Some(libc::EACCES)
        );
    }

    #[test]
    fn mountinfo_overflow_never_returns_a_truncated_proof() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"1 1 0:1 / / rw - tmpfs source rw\n2 1 0:2 / /extra rw - proc source rw\n")
            .unwrap();
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut truncated = [0u8; 32];
        assert_eq!(
            read_bounded(file.as_raw_fd(), &mut truncated)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EOVERFLOW)
        );
    }

    #[test]
    fn mountinfo_parser_keeps_escapes_and_refuses_malformed_or_propagating_views() {
        let mount = mount_line(b"5 1 0:1 / /tmp/a\\040b rw master:2 - tmpfs tmpfs rw").unwrap();
        assert!(!mount.private);
        let mut path = [0u8; PATH_BYTES + 1];
        let length = decoded(mount.point, &mut path).unwrap();
        assert_eq!(&path[..length], b"/tmp/a b");
        for malformed in [
            b"5 1 nope / / rw - tmpfs tmpfs rw".as_slice(),
            b"5 1 0:1 / / rw missing-separator",
            b"5 1 0:1 / / rw - tmpfs tmpfs rw trailing",
        ] {
            assert!(mount_line(malformed).is_err());
        }
        assert!(decoded(b"/bad\\777", &mut path).is_err());
    }
}
