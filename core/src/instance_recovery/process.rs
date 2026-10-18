use super::{Decimal, InstanceError, InstanceState, StateRecord};
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_ticks: Decimal,
}
impl ProcessIdentity {
    pub(super) fn valid(self) -> bool {
        self.pid > 0 && self.pid <= i32::MAX as u32
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceIdentity {
    pub dev: Decimal,
    pub ino: Decimal,
}
impl NamespaceIdentity {
    fn from_file(file: &File) -> Result<Self, InstanceError> {
        let metadata = file.metadata()?;
        Ok(Self {
            dev: Decimal(metadata.dev()),
            ino: Decimal(metadata.ino()),
        })
    }
}

/// Neither /proc descriptors nor namespace FDs are inherited by the workload.
pub struct ProcessHandle {
    identity: ProcessIdentity,
    namespace: NamespaceIdentity,
    init: bool,
    pidfd: File,
    _proc: File,
    _namespace: File,
}
impl ProcessHandle {
    pub fn capture(pid: u32, require_init: bool) -> Result<Self, InstanceError> {
        let root = ProcRoot::open()?;
        let directory = root.process(pid)?;
        let identity = identity(&directory, pid)?;
        let (namespace_fd, namespace, is_init) = namespace(&directory, pid)?;
        if require_init && (!is_init || namespace == Context::current()?.observer_pidns) {
            return Err(InstanceError::Uncertain);
        }
        let pidfd = open_pidfd(pid)?;
        if identity != self::identity(&directory, pid)? {
            return Err(InstanceError::Uncertain);
        }
        let (again, ns_again, is_init_again) = self::namespace(&directory, pid)?;
        drop(again);
        if ns_again != namespace || is_init_again != is_init {
            return Err(InstanceError::Uncertain);
        }
        Ok(Self {
            identity,
            namespace,
            init: is_init,
            pidfd,
            _proc: directory,
            _namespace: namespace_fd,
        })
    }
    pub fn identity(&self) -> ProcessIdentity {
        self.identity
    }
    pub fn namespace(&self) -> NamespaceIdentity {
        self.namespace
    }
    pub fn is_init(&self) -> bool {
        self.init
    }
    pub fn is_exited(&self) -> Result<bool, InstanceError> {
        poll_exited(&self.pidfd, Duration::ZERO)
    }
    pub fn wait_exited(&self, deadline: Instant) -> Result<bool, InstanceError> {
        poll_exited(
            &self.pidfd,
            deadline.saturating_duration_since(Instant::now()),
        )
    }
    /// Normal supervision only: automatic recovery never invokes this method.
    pub fn signal(&self, signal: i32) -> Result<(), InstanceError> {
        // SAFETY: this pidfd pins the revalidated process, never a numeric PID.
        if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        } < 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error.into());
            }
        }
        Ok(())
    }
}
fn open_pidfd(pid: u32) -> Result<File, InstanceError> {
    // SAFETY: pidfd_open accepts a positive numeric PID and sets CLOEXEC.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: successful syscall returned this fresh owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}
fn poll_exited(file: &File, timeout: Duration) -> Result<bool, InstanceError> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let milliseconds = remaining
            .as_nanos()
            .div_ceil(1_000_000)
            .min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd: file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: the pollfd storage and its owned descriptor remain live.
        let result = unsafe { libc::poll(&mut descriptor, 1, milliseconds) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        if descriptor.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(InstanceError::Uncertain);
        }
        return Ok(descriptor.revents & (libc::POLLIN | libc::POLLHUP) != 0);
    }
}

struct ProcRoot {
    directory: File,
}
impl ProcRoot {
    fn open() -> Result<Self, InstanceError> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/proc")?;
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: statfs writes initialized storage for this live descriptor.
        if unsafe { libc::fstatfs(directory.as_raw_fd(), stat.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: successful fstatfs initialized the structure.
        if unsafe { stat.assume_init() }.f_type != libc::PROC_SUPER_MAGIC {
            return Err(InstanceError::Uncertain);
        }
        Ok(Self { directory })
    }
    fn process(&self, pid: u32) -> Result<File, InstanceError> {
        if pid == 0 || pid > i32::MAX as u32 {
            return Err(InstanceError::Invalid);
        }
        open_at(
            &self.directory,
            &pid.to_string(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
        .map_err(Into::into)
    }
}
fn open_at(directory: &File, name: &str, flags: i32) -> io::Result<File> {
    let name = CString::new(name).map_err(|_| io::Error::other("invalid proc name"))?;
    // SAFETY: the directory and NUL-terminated name remain valid.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a fresh descriptor owned by this File.
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn read_at(directory: &File, name: &str) -> Result<String, InstanceError> {
    let file = open_at(directory, name, libc::O_RDONLY | libc::O_NOFOLLOW)?;
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 {
        return Err(InstanceError::Uncertain);
    }
    String::from_utf8(bytes).map_err(|_| InstanceError::Uncertain)
}
fn identity(directory: &File, pid: u32) -> Result<ProcessIdentity, InstanceError> {
    parse_stat(&read_at(directory, "stat")?, pid)
}
fn parse_stat(value: &str, pid: u32) -> Result<ProcessIdentity, InstanceError> {
    let start = value.find('(').ok_or(InstanceError::Uncertain)?;
    let end = value.rfind(')').ok_or(InstanceError::Uncertain)?;
    if start >= end || value[..start].trim().parse::<u32>().ok() != Some(pid) {
        return Err(InstanceError::Uncertain);
    }
    let ticks = value[end + 1..]
        .split_ascii_whitespace()
        .nth(19)
        .ok_or(InstanceError::Uncertain)?
        .parse::<u64>()
        .map_err(|_| InstanceError::Uncertain)?;
    Ok(ProcessIdentity {
        pid,
        start_ticks: Decimal(ticks),
    })
}
fn namespace(directory: &File, pid: u32) -> Result<(File, NamespaceIdentity, bool), InstanceError> {
    // ns/pid is a kernel namespace magic link below the already pinned /proc
    // process directory. It is deliberately followed, never a sandbox import.
    let file = open_at(directory, "ns/pid", libc::O_RDONLY)?;
    let namespace = NamespaceIdentity::from_file(&file)?;
    let status = read_at(directory, "status")?;
    let line = status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))
        .ok_or(InstanceError::Uncertain)?;
    let pids = line
        .split_ascii_whitespace()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| InstanceError::Uncertain)?;
    if pids.first() != Some(&pid) || pids.contains(&0) {
        return Err(InstanceError::Uncertain);
    }
    Ok((file, namespace, pids.last() == Some(&1)))
}

pub(super) struct Context {
    pub boot_id: String,
    pub observer_pidns: NamespaceIdentity,
    pub owner: ProcessIdentity,
}
impl Context {
    pub fn current() -> Result<Self, InstanceError> {
        let root = ProcRoot::open()?;
        let boot_id = read_at(&root.directory, "sys/kernel/random/boot_id")?
            .trim()
            .to_owned();
        if !valid_boot(&boot_id) {
            return Err(InstanceError::Uncertain);
        }
        let pid = std::process::id();
        let directory = root.process(pid)?;
        let owner = identity(&directory, pid)?;
        let (_, observer_pidns, _) = namespace(&directory, pid)?;
        Ok(Self {
            boot_id,
            observer_pidns,
            owner,
        })
    }
    pub fn same_boot(&self, record: &StateRecord) -> bool {
        self.boot_id.eq_ignore_ascii_case(&record.boot_id)
    }
}
pub(super) fn valid_boot(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
pub(super) enum Observation {
    Gone,
    Live(ProcessHandle),
}
pub(super) fn observe(
    expected: ProcessIdentity,
    init: Option<NamespaceIdentity>,
) -> Result<Observation, InstanceError> {
    let root = ProcRoot::open()?;
    observe_at(&root, expected, init, open_pidfd)
}
fn observe_at(
    root: &ProcRoot,
    expected: ProcessIdentity,
    init: Option<NamespaceIdentity>,
    mut acquire: impl FnMut(u32) -> Result<File, InstanceError>,
) -> Result<Observation, InstanceError> {
    for _ in 0..3 {
        let directory = match root.process(expected.pid) {
            Ok(directory) => directory,
            Err(InstanceError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Observation::Gone);
            }
            Err(error) => return Err(error),
        };
        if identity(&directory, expected.pid)? != expected {
            return Ok(Observation::Gone);
        }
        let (namespace_fd, namespace, is_init) = namespace(&directory, expected.pid)?;
        if init.is_some_and(|expected| namespace != expected || !is_init) {
            return Err(InstanceError::Uncertain);
        }
        let pidfd = match acquire(expected.pid) {
            Ok(fd) => fd,
            Err(InstanceError::Io(error)) if error.raw_os_error() == Some(libc::ESRCH) => continue,
            Err(error) => return Err(error),
        };
        // The same proc FD cannot start representing a reused PID. A failed
        // reread discards the pidfd and retries through a fresh proc directory.
        if identity(&directory, expected.pid).ok() != Some(expected) {
            continue;
        }
        let Ok((_, again, again_init)) = self::namespace(&directory, expected.pid) else {
            continue;
        };
        if again != namespace || again_init != is_init {
            continue;
        }
        let handle = ProcessHandle {
            identity: expected,
            namespace,
            init: is_init,
            pidfd,
            _proc: directory,
            _namespace: namespace_fd,
        };
        return if handle.is_exited()? {
            Ok(Observation::Gone)
        } else {
            Ok(Observation::Live(handle))
        };
    }
    Err(InstanceError::Uncertain)
}
pub(super) fn confirm(record: &StateRecord, timeout: Duration) -> Result<bool, InstanceError> {
    match record.state {
        InstanceState::Prepared => Ok(true),
        InstanceState::Spawning => Ok(false),
        InstanceState::Armed => {
            let deadline = Instant::now() + timeout;
            let launcher = observe(record.launcher.ok_or(InstanceError::Invalid)?, None)?;
            let init = observe(
                record.init.ok_or(InstanceError::Invalid)?,
                record.sandbox_pidns,
            )?;
            for process in [launcher, init] {
                if let Observation::Live(process) = process
                    && !process.wait_exited(deadline)?
                {
                    return Ok(false);
                }
            }
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, fs};

    fn stat(pid: u32, ticks: u64) -> String {
        format!(
            "{pid} (name with ) parentheses) S {} {ticks} 0\n",
            ["0"; 18].join(" ")
        )
    }
    struct Fixture {
        root: tempfile::TempDir,
        pid: u32,
    }
    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let pid = std::process::id();
            let path = root.path().join(pid.to_string());
            fs::create_dir_all(path.join("ns")).unwrap();
            fs::write(path.join("stat"), stat(pid, 42)).unwrap();
            fs::write(path.join("status"), format!("NSpid:\t{pid}\t1\n")).unwrap();
            fs::write(path.join("ns/pid"), "fixture namespace inode").unwrap();
            Self { root, pid }
        }
        fn root(&self) -> ProcRoot {
            ProcRoot {
                directory: File::open(self.root.path()).unwrap(),
            }
        }
        fn path(&self, name: &str) -> std::path::PathBuf {
            self.root.path().join(self.pid.to_string()).join(name)
        }
        fn expected(&self) -> ProcessIdentity {
            ProcessIdentity {
                pid: self.pid,
                start_ticks: Decimal(42),
            }
        }
    }

    #[test]
    fn stat_parser_treats_comm_as_opaque_and_keeps_field_22_in_ticks() {
        assert_eq!(
            parse_stat(&stat(123, 987654321), 123).unwrap(),
            ProcessIdentity {
                pid: 123,
                start_ticks: Decimal(987654321)
            }
        );
        for malformed in [
            "",
            "123 (missing end",
            "123 () S 0",
            "124 (different pid) S 0",
        ] {
            assert!(parse_stat(malformed, 123).is_err());
        }
    }

    #[test]
    fn only_missing_process_or_different_ticks_prove_original_absence() {
        let fixture = Fixture::new();
        let root = fixture.root();
        let never = |_| panic!("must not acquire pidfd");
        fs::write(fixture.path("stat"), stat(fixture.pid, 43)).unwrap();
        assert!(matches!(
            observe_at(&root, fixture.expected(), None, never),
            Ok(Observation::Gone)
        ));
        fs::remove_file(fixture.path("stat")).unwrap();
        assert!(observe_at(&root, fixture.expected(), None, never).is_err());
        fs::remove_dir_all(fixture.root.path().join(fixture.pid.to_string())).unwrap();
        assert!(matches!(
            observe_at(&root, fixture.expected(), None, never),
            Ok(Observation::Gone)
        ));
    }

    #[test]
    fn pidfd_permission_failure_and_inconsistent_init_namespace_are_uncertain() {
        let fixture = Fixture::new();
        let root = fixture.root();
        let result = observe_at(&root, fixture.expected(), None, |_| {
            Err(io::Error::from_raw_os_error(libc::EPERM).into())
        });
        assert!(
            matches!(result,Err(InstanceError::Io(error)) if error.raw_os_error()==Some(libc::EPERM))
        );
        assert!(matches!(
            observe_at(
                &root,
                fixture.expected(),
                Some(NamespaceIdentity {
                    dev: Decimal(0),
                    ino: Decimal(0)
                }),
                |_| panic!("namespace mismatch must precede pidfd")
            ),
            Err(InstanceError::Uncertain)
        ));
    }

    #[test]
    fn race_at_pidfd_acquisition_discards_it_and_reopens_proc_before_deciding() {
        let fixture = Fixture::new();
        let root = fixture.root();
        let calls = Cell::new(0);
        let result = observe_at(&root, fixture.expected(), None, |pid| {
            calls.set(calls.get() + 1);
            let fd = open_pidfd(pid)?;
            fs::write(fixture.path("stat"), stat(pid, 43))?;
            Ok(fd)
        });
        assert!(matches!(result, Ok(Observation::Gone)));
        assert_eq!(calls.get(), 1);
        fs::write(fixture.path("stat"), stat(fixture.pid, 42)).unwrap();
        let result = observe_at(&root, fixture.expected(), None, |pid| {
            let fd = open_pidfd(pid)?;
            fs::remove_file(fixture.path("stat"))?;
            Ok(fd)
        });
        // A missing subfile after acquisition is not a missing process.
        assert!(result.is_err());
        assert!(
            !ProcessHandle::capture(std::process::id(), false)
                .unwrap()
                .is_exited()
                .unwrap()
        );
    }
}
