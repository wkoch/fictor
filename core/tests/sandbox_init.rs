//! Real bubblewrap acceptance tests. Missing bwrap/userns support is a failure.
//! Run on Fedora COSMIC Atomic or Ubuntu x86-64 CI.

use fictor::sandbox::{ProxyEndpoint, SandboxContext, SandboxPlan, SandboxProfile, Tier};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    os::unix::{fs::symlink, net::UnixListener},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::atomic::{AtomicI32, Ordering},
    time::{Duration, Instant},
};

const DEADLINE: Duration = Duration::from_secs(15);
const PROBE_ARGUMENTS: [&str; 4] = [
    "--exact",
    "sandbox_init_probe",
    "--nocapture",
    "--test-threads=1",
];

struct Fixture {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    _proxy: UnixListener,
    _plans: std::sync::Mutex<Vec<SandboxPlan>>,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        for directory in [
            "core/extensions/store/probe/1-hash",
            "core/extensions/data/probe",
            "core/run/k",
            "user/.ssh",
            "instance",
            "workspace",
            "outside",
        ] {
            std::fs::create_dir_all(root.join(directory)).unwrap();
        }
        for (path, content) in [
            ("core/extensions/store/probe/1-hash/code", "promoted"),
            ("core/config.toml", "core private"),
            ("user/.ssh/id_rsa", "fake private key"),
            ("workspace/input", "workspace"),
            ("outside/secret", "outside private"),
        ] {
            std::fs::write(root.join(path), content).unwrap();
        }
        let proxy = UnixListener::bind(root.join("core/run/proxy.sock")).unwrap();
        Self {
            _temporary: temporary,
            root,
            _proxy: proxy,
            _plans: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn plan(&self, mode: &str, extra: BTreeMap<String, String>) -> SandboxPlan {
        self.plan_with_kernel(mode, extra, None)
    }

    fn plan_with_kernel(
        &self,
        mode: &str,
        extra: BTreeMap<String, String>,
        kernel_socket: Option<PathBuf>,
    ) -> SandboxPlan {
        let runtime = std::env::current_exe().unwrap().canonicalize().unwrap();
        let context = SandboxContext {
            fictor_home: self.root.join("core"),
            real_home: self.root.join("user"),
            bundle_root: self.root.join("core/extensions/store/probe/1-hash"),
            ext_data: self.root.join("core/extensions/data/probe"),
            tmp_dir: self.root.join("instance"),
            runtime_root: runtime.parent().unwrap().to_path_buf(),
            runtime,
            fictor_exe: Path::new(env!("CARGO_BIN_EXE_fictor"))
                .canonicalize()
                .unwrap(),
            home_ro_files: vec![],
            allow_store_read: false,
        };
        let mut env = extra;
        env.insert("FX_LINUX_TEST_MODE".into(), mode.into());
        env.insert(
            "FX_LINUX_TEST_ROOT".into(),
            self.root.to_str().unwrap().into(),
        );
        env.insert(
            "HTTP_PROXY".into(),
            "http://fx:fake-test-token@127.0.0.1:3128".into(),
        );
        let profile = SandboxProfile {
            read_paths: vec![],
            write_paths: vec![self.root.join("workspace")],
            spawn: true,
            kernel_socket,
            proxy: ProxyEndpoint::Unix(self.root.join("core/run/proxy.sock")),
            env,
            cwd: self.root.join("workspace"),
            tier: Tier::Os,
        };
        SandboxPlan::new(profile, context, PROBE_ARGUMENTS.map(Into::into).to_vec()).unwrap()
    }

    fn command(&self, mode: &str, extra: BTreeMap<String, String>) -> Command {
        let plan = self.plan(mode, extra);
        let command = plan.command().unwrap_or_else(|error| panic!(
            "Linux sandbox prerequisite failed: {error}. Install bubblewrap and enable unprivileged user namespaces; run fictor doctor."
        ));
        self._plans.lock().unwrap().push(plan);
        command
    }
}

/// Always terminates a failed test's sandbox and waits for its outer monitor.
struct Running {
    child: Option<Child>,
}
impl Running {
    fn spawn(mut command: Command) -> Self {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        Self {
            child: Some(
                command
                    .spawn()
                    .expect("start bubblewrap; check bwrap/userns with fictor doctor"),
            ),
        }
    }
    fn pid(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }
    fn assert_running(&mut self) {
        if self.child.as_mut().unwrap().try_wait().unwrap().is_some() {
            let output = self.child.take().unwrap().wait_with_output().unwrap();
            panic!(
                "sandbox exited before readiness; bwrap/userns are required (run fictor doctor): {:?}\n{}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    fn finish(mut self) -> Output {
        let started = Instant::now();
        loop {
            if self.child.as_mut().unwrap().try_wait().unwrap().is_some() {
                return self.child.take().unwrap().wait_with_output().unwrap();
            }
            assert!(
                started.elapsed() < DEADLINE,
                "Linux sandbox timed out; check bwrap/userns with fictor doctor"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // SAFETY: positive owned child PID targets its launcher process group.
            // bwrap --die-with-parent also tears down the nested PID namespace.
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
fn assert_status(output: Output, expected: i32) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "Linux sandbox failed (bwrap/userns are required; run fictor doctor):\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn bubblewrap_confines_native_runtime_files_and_environment() {
    let fixture = Fixture::new();
    symlink(
        fixture.root.join("outside"),
        fixture.root.join("workspace/escape"),
    )
    .unwrap();
    assert_status(
        Running::spawn(fixture.command("files", BTreeMap::new())).finish(),
        0,
    );
    assert_eq!(
        std::fs::read_to_string(fixture.root.join("workspace/created")).unwrap(),
        "allowed"
    );
    assert!(!fixture.root.join("outside/created").exists());
    assert!(!fixture.root.join("instance/from-private-tmp").exists());
}

#[test]
fn sandbox_init_preserves_runtime_exit_status() {
    let fixture = Fixture::new();
    assert_status(
        Running::spawn(fixture.command("exit", BTreeMap::new())).finish(),
        37,
    );
}

#[test]
fn namespace_has_no_host_loopback_and_proxy_bridges_http_over_unix() {
    let fixture = Fixture::new();
    let direct = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let extra = BTreeMap::from([(
        "FX_LINUX_DENIED_ADDRESS".into(),
        direct.local_addr().unwrap().to_string(),
    )]);
    let proxy = fixture._proxy.try_clone().unwrap();
    proxy.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let started = Instant::now();
        let mut stream = loop {
            match proxy.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        started.elapsed() < DEADLINE,
                        "sandbox never reached the local Unix proxy"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("Unix proxy accept failed: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            assert!(request.len() < 8192);
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        assert!(request.starts_with(b"GET http://only-local-test.invalid/path HTTP/1.1\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nlocal-proxy",
            )
            .unwrap();
    });
    let output = Running::spawn(fixture.command("network", extra)).finish();
    assert_status(output, 0);
    server.join().unwrap();
    direct.set_nonblocking(true).unwrap();
    assert!(
        matches!(direct.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}

#[test]
fn kernel_bridge_is_available_and_reserved_before_the_workload_starts() {
    let fixture = Fixture::new();
    let socket = fixture.root.join("core/run/k/test.sock");
    let kernel = UnixListener::bind(&socket).unwrap();
    kernel.set_nonblocking(true).unwrap();
    let plan = fixture.plan_with_kernel("kernel", BTreeMap::new(), Some(socket));
    let server = std::thread::spawn(move || {
        let started = Instant::now();
        let mut stream = loop {
            match kernel.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        started.elapsed() < DEADLINE,
                        "kernel bridge did not reach its Unix endpoint"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("kernel Unix accept failed: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).unwrap();
        assert_eq!(request, b"kernel request");
        stream.write_all(b"kernel reply").unwrap();
    });
    assert_status(Running::spawn(plan.command().unwrap()).finish(), 0);
    server.join().unwrap();
}

#[derive(Clone)]
struct Process {
    pid: i32,
    parent: i32,
    namespace_pid: i32,
}
fn descendants(root: i32) -> Vec<Process> {
    let all: Vec<_> = std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let pid = entry.file_name().to_str()?.parse().ok()?;
            let status = std::fs::read_to_string(entry.path().join("status")).ok()?;
            let value = |name| status.lines().find_map(|line| line.strip_prefix(name));
            let parent = value("PPid:")?.trim().parse().ok()?;
            let namespace_pid = value("NSpid:")?.split_whitespace().last()?.parse().ok()?;
            Some(Process {
                pid,
                parent,
                namespace_pid,
            })
        })
        .collect();
    let mut result = Vec::new();
    let mut parents = vec![root];
    while let Some(parent) = parents.pop() {
        for process in all.iter().filter(|process| process.parent == parent) {
            parents.push(process.pid);
            result.push(process.clone());
        }
    }
    result
}

#[test]
fn sandbox_init_forwards_sigterm_and_reaps_orphan_descendants() {
    let fixture = Fixture::new();
    let mut running = Running::spawn(fixture.command("signals", BTreeMap::new()));
    let ready = fixture.root.join("workspace/ready");
    let started = Instant::now();
    let (init_pid, orphan_pid) = loop {
        running.assert_running();
        if let Ok(orphan_namespace_pid) = std::fs::read_to_string(&ready) {
            let processes = descendants(running.pid() as i32);
            let init = processes.iter().find(|process| process.namespace_pid == 1);
            let orphan_namespace_pid: i32 = orphan_namespace_pid.trim().parse().unwrap();
            let orphan = processes
                .iter()
                .find(|process| process.namespace_pid == orphan_namespace_pid);
            if let (Some(init), Some(orphan)) = (init, orphan) {
                break (init.pid, orphan.pid);
            }
        }
        assert!(
            started.elapsed() < DEADLINE,
            "no sandbox PID 1/descendant readiness; bwrap and userns are required"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    // SAFETY: PID comes from this test's bwrap subtree and identifies its private init.
    assert_eq!(unsafe { libc::kill(init_pid, libc::SIGTERM) }, 0);
    assert_status(running.finish(), 42);
    assert_eq!(
        std::fs::read_to_string(fixture.root.join("workspace/observed-signal")).unwrap(),
        libc::SIGTERM.to_string()
    );
    assert!(
        !Path::new("/proc").join(orphan_pid.to_string()).exists(),
        "init left its SIGTERM-ignoring orphan alive or unreaped"
    );
}

fn publish_ready(path: PathBuf, value: &str) {
    let temporary = path.with_extension("pending");
    std::fs::write(&temporary, value).unwrap();
    std::fs::rename(temporary, path).unwrap();
}

static OBSERVED_SIGNAL: AtomicI32 = AtomicI32::new(0);
extern "C" fn observe_term(signal: i32) {
    OBSERVED_SIGNAL.store(signal, Ordering::SeqCst);
}

/// Executed as the native runtime inside the Linux sandbox, with no shell dependency.
#[test]
fn sandbox_init_probe() {
    let Ok(mode) = std::env::var("FX_LINUX_TEST_MODE") else {
        return;
    };
    let root = PathBuf::from(std::env::var("FX_LINUX_TEST_ROOT").unwrap());
    match mode.as_str() {
        "files" => {
            assert_eq!(
                std::fs::read_to_string(root.join("workspace/input")).unwrap(),
                "workspace"
            );
            std::fs::write(root.join("workspace/created"), "allowed").unwrap();
            std::fs::write(root.join("core/extensions/data/probe/state"), "data").unwrap();
            let bundle = root.join("core/extensions/store/probe/1-hash/code");
            assert_eq!(std::fs::read_to_string(&bundle).unwrap(), "promoted");
            assert!(std::fs::write(bundle, "modified").is_err());
            for private in [
                "core/config.toml",
                "user/.ssh/id_rsa",
                "outside/secret",
                "workspace/escape/secret",
            ] {
                assert!(
                    std::fs::read(root.join(private)).is_err(),
                    "read escaped: {private}"
                );
            }
            assert!(std::fs::write(root.join("outside/created"), "forbidden").is_err());
            assert_eq!(std::env::var("HOME").unwrap(), "/tmp/home");
            assert_eq!(std::env::var("TMPDIR").unwrap(), "/tmp");
            assert!(std::env::var_os("USER").is_none());
            assert!(std::env::var_os("SSH_AUTH_SOCK").is_none());
            std::fs::write("/tmp/from-private-tmp", "private instance tmpfs").unwrap();
        }
        "exit" => std::process::exit(37),
        "network" => {
            assert!(std::env::var_os("FICTOR_KERNEL_URL").is_none());
            assert!(std::env::var_os("FICTOR_KERNEL_SOCKET").is_none());
            assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, 3128)).is_err());
            assert!(
                TcpListener::bind((Ipv4Addr::LOCALHOST, 3129)).is_ok(),
                "kernel port should remain unbound without kernel scopes"
            );
            let denied: SocketAddr = std::env::var("FX_LINUX_DENIED_ADDRESS")
                .unwrap()
                .parse()
                .unwrap();
            assert!(
                TcpStream::connect_timeout(&denied, Duration::from_millis(500)).is_err(),
                "direct host loopback escaped the network namespace"
            );
            let mut proxy = TcpStream::connect((Ipv4Addr::LOCALHOST, 3128)).unwrap();
            proxy
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            proxy.write_all(b"GET http://only-local-test.invalid/path HTTP/1.1\r\nHost: only-local-test.invalid\r\nConnection: close\r\n\r\n").unwrap();
            let mut response = String::new();
            proxy.read_to_string(&mut response).unwrap();
            assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(response.ends_with("local-proxy"));
        }
        "kernel" => {
            assert_eq!(
                std::env::var("FICTOR_KERNEL_URL").unwrap(),
                "tcp://127.0.0.1:3129"
            );
            assert!(std::env::var_os("FICTOR_KERNEL_SOCKET").is_none());
            for port in [3128, 3129] {
                assert!(
                    matches!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)), Err(error) if error.kind() == std::io::ErrorKind::AddrInUse),
                    "bridge port was not reserved before workload start"
                );
            }
            let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, 3129)).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            client.write_all(b"kernel request").unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).unwrap();
            assert_eq!(reply, b"kernel reply");
        }
        "signals" => {
            // SAFETY: a process-local signal handler only stores a lock-free atomic.
            assert_ne!(
                unsafe {
                    libc::signal(
                        libc::SIGTERM,
                        observe_term as *const () as libc::sighandler_t,
                    )
                },
                libc::SIG_ERR
            );
            let mut orphan = Command::new(std::env::current_exe().unwrap())
                .args(PROBE_ARGUMENTS)
                .env("FX_LINUX_TEST_MODE", "orphan")
                .spawn()
                .unwrap();
            let started = Instant::now();
            let orphan_pid = loop {
                if let Ok(pid) = std::fs::read_to_string(root.join("workspace/orphan-ready")) {
                    break pid;
                }
                assert!(started.elapsed() < DEADLINE, "orphan did not start");
                assert!(orphan.try_wait().unwrap().is_none());
                std::thread::sleep(Duration::from_millis(10));
            };
            publish_ready(root.join("workspace/ready"), &orphan_pid);
            while OBSERVED_SIGNAL.load(Ordering::SeqCst) == 0 {
                assert!(started.elapsed() < DEADLINE, "init did not forward SIGTERM");
                std::thread::sleep(Duration::from_millis(10));
            }
            std::fs::write(
                root.join("workspace/observed-signal"),
                OBSERVED_SIGNAL.load(Ordering::SeqCst).to_string(),
            )
            .unwrap();
            // Main process exits while its SIGTERM-ignoring descendant remains alive.
            // PID 1 must adopt, kill and reap that descendant.
            drop(orphan);
            std::process::exit(42);
        }
        "orphan" => {
            // SAFETY: this test descendant intentionally ignores TERM to exercise cleanup.
            assert_ne!(
                unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) },
                libc::SIG_ERR
            );
            publish_ready(
                root.join("workspace/orphan-ready"),
                &std::process::id().to_string(),
            );
            loop {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        _ => panic!("unknown Linux sandbox probe mode"),
    }
}
