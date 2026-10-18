use crate::config::Config;
use std::{
    env, fmt, fs,
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    Ok,
    Warn,
    Fail,
}
impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ok => "ok",
            Self::Warn => "aviso",
            Self::Fail => "falha",
        })
    }
}
pub struct Check {
    pub name: String,
    pub status: Status,
    pub detail: String,
}
fn check(name: &str, status: Status, detail: impl Into<String>) -> Check {
    Check {
        name: name.into(),
        status,
        detail: detail.into(),
    }
}

pub fn inspect(home: &Path) -> Vec<Check> {
    let mut checks = inspect_local(home);
    if let Ok(config) = Config::load(home)
        && let Ok(prefixes) = crate::proxy::nat64::Nat64Prefixes::new(&config.egress.nat64_prefixes)
    {
        checks.push(nat64_check_with(
            prefixes,
            Duration::from_secs(2),
            resolve_nat64_aaaa,
        ));
    }
    checks
}

/// Local diagnostics for callers/tests that must not initiate external DNS.
/// The CLI deliberately calls inspect(), which also performs the advisory NAT64 query.
pub fn inspect_local(home: &Path) -> Vec<Check> {
    let mut checks = Vec::new();
    let config = match Config::load(home) {
        Ok(config) => {
            checks.push(check("config", Status::Ok, "config.toml válido"));
            config
        }
        Err(error) => {
            checks.push(check("config", Status::Fail, error.to_string()));
            return checks;
        }
    };
    checks.extend(runtime_checks(find_executable));
    checks.push(sandbox_check());
    for (name, port) in [
        ("porta shell", config.server.listen.port()),
        ("porta surfaces", config.server.surface_port),
    ] {
        let available = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)).is_ok();
        checks.push(check(
            name,
            if available { Status::Ok } else { Status::Fail },
            format!(
                "127.0.0.1:{port} {}",
                if available {
                    "disponível"
                } else {
                    "ocupada ou indisponível"
                }
            ),
        ));
    }
    // Backend initialization only: never read/write native credential entries.
    let backend = config.secrets.backend;
    match crate::secrets::SecretStore::open(home, backend, Default::default()) {
        Ok(store) if store.backend_status() == crate::secrets::BackendStatus::Initialized => checks.push(check(
            "keyring/segredos", if backend == crate::secrets::BackendKind::File { Status::Warn } else { Status::Ok },
            if backend == crate::secrets::BackendKind::File { "backend file explícito: segredos em texto puro, modo 0600 verificado" } else { "backend nativo inicializado; acesso a credenciais não foi testado" },
        )),
        _ => checks.push(check("keyring/segredos", Status::Fail, "backend indisponível ou arquivo inválido; para optar por arquivo configure [secrets] backend = \"file\"")),
    }
    match crate::sandbox::sensitive::SensitivePaths::discover(
        &std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.into()),
    ) {
        Ok(paths) => {
            for warning in paths.warnings() {
                checks.push(check("caminhos sensíveis", Status::Warn, *warning));
            }
        }
        Err(_) => checks.push(check(
            "caminhos sensíveis",
            Status::Fail,
            "falha na descoberta de endpoints sensíveis",
        )),
    }
    checks
}

fn runtime_checks(resolve: impl Fn(&str) -> Option<PathBuf>) -> Vec<Check> {
    [("node", true), ("uv", false), ("python", false)]
        .into_iter()
        .map(|(name, required)| {
            let usable = resolve(name)
                .is_some_and(|path| succeeds(Command::new(path).arg("--version")));
            check(
                name,
                if usable {
                    Status::Ok
                } else if required {
                    Status::Fail
                } else {
                    Status::Warn
                },
                if usable {
                    "executável de desenvolvimento disponível; runtimes gerenciados pendentes (M0.9)"
                } else {
                    "ausente ou não executável; prepare o toolbx de desenvolvimento (M0.9 instalará runtimes gerenciados)"
                },
            )
        })
        .collect()
}

fn executable(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| {
        use std::os::unix::fs::PermissionsExt;
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
    })
}

fn find_executable(name: &str) -> Option<PathBuf> {
    if name == "node" {
        return executable(Path::new("/usr/bin/node")).then(|| "/usr/bin/node".into());
    }
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|path| executable(path))
    })
}

fn succeeds(command: &mut Command) -> bool {
    let Ok(mut child) = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if started.elapsed() < Duration::from_secs(3) => {
                thread::sleep(Duration::from_millis(20))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

fn sandbox_check() -> Check {
    let usable = probe_sandbox().unwrap_or(false);
    check(
        "bubblewrap/userns",
        if usable { Status::Ok } else { Status::Fail },
        if usable {
            "bubblewrap executou o perfil restritivo e __sandbox-init"
        } else {
            "instale bubblewrap e confira user namespaces; verifique negações SELinux (AVC) e AppArmor sem desativar o sandbox"
        },
    )
}

fn probe_sandbox() -> Result<bool, crate::sandbox::SandboxError> {
    use crate::sandbox::{ProxyEndpoint, SandboxContext, SandboxPlan, SandboxProfile, Tier};
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().canonicalize()?;
    let home = root.join("core");
    let bundle = home.join("extensions/store/doctor/0-probe");
    let data = home.join("extensions/data/doctor");
    let tmp = root.join("tmp");
    for path in [&bundle, &data, &tmp, &home.join("run")] {
        crate::home::private_dir(path)?;
    }
    let runtime = PathBuf::from("/usr/bin/true").canonicalize()?;
    let real_home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or(crate::sandbox::SandboxError::Invalid("HOME não definido"))?;
    let (_socket, proxy) = {
        let path = home.join("run/proxy.sock");
        let socket = std::os::unix::net::UnixListener::bind(&path)?;
        (socket, ProxyEndpoint::Unix(path))
    };
    let plan = SandboxPlan::new(
        SandboxProfile {
            read_paths: vec![],
            write_paths: vec![],
            spawn: false,
            kernel_socket: None,
            proxy,
            env: Default::default(),
            cwd: bundle.clone(),
            tier: Tier::Os,
        },
        SandboxContext {
            fictor_home: home,
            real_home,
            bundle_root: bundle,
            ext_data: data,
            tmp_dir: tmp,
            runtime_root: runtime
                .parent()
                .ok_or(crate::sandbox::SandboxError::Invalid(
                    "runtime sem diretório",
                ))?
                .into(),
            runtime,
            fictor_exe: std::env::current_exe()?,
            home_ro_files: vec![],
            allow_store_read: false,
        },
        vec![],
    )?;
    Ok(succeeds(&mut plan.command()?))
}

fn nat64_check_with(
    prefixes: crate::proxy::nat64::Nat64Prefixes,
    timeout: Duration,
    resolver: impl FnOnce() -> std::io::Result<Vec<std::net::Ipv6Addr>> + Send + 'static,
) -> Check {
    let (reply, result) = std::sync::mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = reply.send(resolver());
    });
    match result.recv_timeout(timeout) {
        Ok(Ok(addresses)) => {
            let suggestions = prefixes.suggestions(&addresses);
            if suggestions.is_empty() {
                check(
                    "NAT64",
                    Status::Ok,
                    "ipv4only.arpa: nenhum prefixo desconhecido detectado; configuração preservada",
                )
            } else {
                check(
                    "NAT64",
                    Status::Warn,
                    format!(
                        "DNS sugeriu prefixos NAT64 {suggestions:?}; confira a rede e configure manualmente: [egress] nat64_prefixes = {suggestions:?}. Nenhuma alteração aplicada."
                    ),
                )
            }
        }
        _ => check(
            "NAT64",
            Status::Warn,
            "consulta AAAA ipv4only.arpa falhou ou excedeu 2 s; prefixos configurados continuam inalterados",
        ),
    }
}

fn resolve_nat64_aaaa() -> std::io::Result<Vec<std::net::Ipv6Addr>> {
    use std::{mem, net::Ipv6Addr, ptr};
    // SAFETY: zero initializes the plain C hints struct; all pointers remain live
    // through getaddrinfo. AF_INET6 requests AAAA only, without AI_ADDRCONFIG.
    let mut hints: libc::addrinfo = unsafe { mem::zeroed() };
    hints.ai_family = libc::AF_INET6;
    hints.ai_socktype = libc::SOCK_STREAM;
    let mut results = ptr::null_mut();
    // The caller bounds how long doctor waits; OS resolver work may finish later.
    // Results are advisory and can never change the running authorization policy.
    // SAFETY: the hostname is a static NUL-terminated C string; output is valid.
    if unsafe { libc::getaddrinfo(c"ipv4only.arpa".as_ptr(), ptr::null(), &hints, &mut results) }
        != 0
    {
        return Err(std::io::Error::other("NAT64 DNS query failed"));
    }
    let mut addresses = Vec::new();
    let mut cursor = results;
    while !cursor.is_null() {
        // SAFETY: getaddrinfo returned this linked list; family/length are checked
        // before reading its sockaddr_in6, and freeaddrinfo runs after traversal.
        let current = unsafe { &*cursor };
        if current.ai_family == libc::AF_INET6
            && !current.ai_addr.is_null()
            && current.ai_addrlen as usize >= mem::size_of::<libc::sockaddr_in6>()
        {
            // SAFETY: the IPv6 sockaddr has the checked type and length above.
            let socket = unsafe { &*current.ai_addr.cast::<libc::sockaddr_in6>() };
            addresses.push(Ipv6Addr::from(socket.sin6_addr.s6_addr));
        }
        cursor = current.ai_next;
    }
    // SAFETY: results is exactly the list allocated by successful getaddrinfo.
    unsafe { libc::freeaddrinfo(results) };
    addresses.sort();
    addresses.dedup();
    Ok(addresses)
}

#[cfg(test)]
mod nat64_tests {
    use super::*;
    use crate::proxy::nat64::Nat64Prefixes;
    #[test]
    fn missing_node_is_required_and_optional_python_runtimes_warn() {
        let report = runtime_checks(|_| None);
        assert_eq!(report.len(), 3);
        assert_eq!(report[0].name, "node");
        assert_eq!(report[0].status, Status::Fail);
        assert!(report[1..].iter().all(|entry| entry.status == Status::Warn));
    }
    #[test]
    fn injected_dns_only_suggests_unknown_prefix_and_preserves_policy() {
        let policy = Nat64Prefixes::new(&["2001:db8:1::/96".into()]).unwrap();
        let check = nat64_check_with(policy.clone(), Duration::from_secs(2), || {
            Ok([
                "64:ff9b::c000:aa",
                "2001:db8:1::c000:ab",
                "2001:db8:2::c000:aa",
            ]
            .map(|address| address.parse().unwrap())
            .to_vec())
        });
        assert_eq!(check.status, Status::Warn);
        assert!(
            check
                .detail
                .contains("nat64_prefixes = [\"2001:db8:2::/96\"]")
        );
        assert!(!policy.is_translation("2001:db8:2::c000:aa".parse().unwrap()));
    }
    #[test]
    fn dns_failure_and_timeout_are_advisory_and_bounded() {
        let failed = nat64_check_with(Nat64Prefixes::default(), Duration::from_secs(2), || {
            Err(std::io::Error::other("fake local DNS failure"))
        });
        assert_eq!(failed.status, Status::Warn);
        let (release, wait) = std::sync::mpsc::channel();
        let start = Instant::now();
        let timed = nat64_check_with(
            Nat64Prefixes::default(),
            Duration::from_millis(20),
            move || {
                let _ = wait.recv();
                Ok(vec![])
            },
        );
        release.send(()).unwrap();
        assert_eq!(timed.status, Status::Warn);
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
