//! PID 1 for the Linux sandbox: proxy transport, signal forwarding and reaping.
use std::ffi::OsString;

use super::SandboxError;

pub async fn run(arguments: Vec<OsString>, mount_proof: &str) -> Result<i32, SandboxError> {
    // Transitional raw backend for direct sandbox tests/doctor. Production
    // uses the barrier entry once its journal integration is in place.
    run_inner(arguments, mount_proof, false).await
}

pub async fn run_with_admission(
    arguments: Vec<OsString>,
    mount_proof: &str,
) -> Result<i32, SandboxError> {
    run_inner(arguments, mount_proof, true).await
}

async fn run_inner(
    arguments: Vec<OsString>,
    mount_proof: &str,
    admission: bool,
) -> Result<i32, SandboxError> {
    // SAFETY: getpid has no arguments or memory-safety preconditions.
    if unsafe { libc::getpid() } != 1 {
        return Err(SandboxError::Invalid(
            "__sandbox-init exige PID 1 no sandbox Linux",
        ));
    }
    // This is core-generated metadata, consumed before any listener or workload
    // exists. It is never placed in the child's environment or argument list.
    super::attestation::Attestation::parse(mount_proof)?.verify()?;
    if admission {
        super::admission::wait_for_authorization().await?;
    }
    linux::run(arguments).await
}

async fn bridge(
    listener: tokio::net::TcpListener,
    socket: std::path::PathBuf,
) -> std::io::Result<()> {
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            connection = listener.accept() => {
                let (mut incoming, _) = connection?;
                let socket = socket.clone();
                connections.spawn(async move {
                    let mut outgoing = tokio::net::UnixStream::connect(socket).await?;
                    tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await?;
                    Ok::<(), std::io::Error>(())
                });
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    // Dropping JoinSet cancels all open transports when PID 1 exits.
}

struct BridgeListeners {
    proxy: tokio::net::TcpListener,
    kernel: Option<tokio::net::TcpListener>,
}

async fn bind_listeners(
    proxy: std::net::SocketAddr,
    kernel: Option<std::net::SocketAddr>,
) -> std::io::Result<BridgeListeners> {
    let proxy = tokio::net::TcpListener::bind(proxy).await?;
    let kernel = match kernel {
        Some(address) => Some(tokio::net::TcpListener::bind(address).await?),
        None => None,
    };
    Ok(BridgeListeners { proxy, kernel })
}

async fn bridges(
    listeners: BridgeListeners,
    proxy_socket: std::path::PathBuf,
    kernel_socket: Option<std::path::PathBuf>,
) -> std::io::Result<()> {
    match (listeners.kernel, kernel_socket) {
        (Some(listener), Some(socket)) => {
            tokio::try_join!(
                bridge(listeners.proxy, proxy_socket),
                bridge(listener, socket)
            )?;
            Ok(())
        }
        (None, None) => bridge(listeners.proxy, proxy_socket).await,
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "kernel listener and socket must agree",
        )),
    }
}

fn mounted_kernel(path: &std::path::Path) -> std::io::Result<bool> {
    use std::os::unix::fs::FileTypeExt;
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => Ok(true),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "kernel endpoint must be a Unix socket",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

mod linux {
    use super::*;
    use std::{io, os::unix::process::CommandExt, process::Command};
    use tokio::signal::unix::{SignalKind, signal};

    pub(super) async fn run(arguments: Vec<OsString>) -> Result<i32, SandboxError> {
        let (program, arguments) = arguments
            .split_first()
            .ok_or(SandboxError::Invalid("comando do sandbox ausente"))?;
        // Install handlers before spawning: PID 1 has special default signal behavior.
        let mut terminated = signal(SignalKind::terminate())?;
        let mut interrupted = signal(SignalKind::interrupt())?;
        let mut hung_up = signal(SignalKind::hangup())?;
        let mut children = signal(SignalKind::child())?;
        let kernel_socket = std::path::PathBuf::from("/fx/kernel.sock");
        let kernel = mounted_kernel(&kernel_socket)?;
        // Bind every advertised endpoint before starting untrusted code. If either
        // port is occupied, no workload runs and the other listener is dropped.
        let listeners = bind_listeners(
            (std::net::Ipv4Addr::LOCALHOST, 3128).into(),
            kernel.then_some((std::net::Ipv4Addr::LOCALHOST, 3129).into()),
        )
        .await?;
        let transport = bridges(
            listeners,
            "/fx/proxy.sock".into(),
            kernel.then_some(kernel_socket),
        );
        tokio::pin!(transport);
        async {
            let mut child_command = Command::new(program);
            child_command.args(arguments).process_group(0);
            let child = child_command.spawn()?;
            let child_pid = i32::try_from(child.id())
                .map_err(|_| SandboxError::Invalid("PID do filho inválido"))?;
            // waitpid below owns reaping. std::process::Child does not reap on drop.
            drop(child);
            let result = async { loop {
                if let Some(status) = reap(child_pid)? {
                    break Ok(status);
                }
                tokio::select! {
                    _ = terminated.recv() => forward(child_pid, libc::SIGTERM)?,
                    _ = interrupted.recv() => forward(child_pid, libc::SIGINT)?,
                    _ = hung_up.recv() => forward(child_pid, libc::SIGHUP)?,
                    _ = children.recv() => {},
                    result = &mut transport => {
                        break match result {
                            Err(error) => Err(error.into()),
                            Ok(()) => Err(SandboxError::Invalid("transporte do sandbox encerrou")),
                        };
                    }
                }
            }}.await;
            // PID namespace isolation and the PID 1 guard make -1 namespace-local.
            // SAFETY: kill uses a valid signal; no pointers are involved.
            if unsafe { libc::kill(-1, libc::SIGKILL) } == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error.into());
                }
            }
            reap_remaining()?;
            result
        }
        .await
    }

    fn forward(child_pid: i32, signal: i32) -> io::Result<()> {
        // SAFETY: child_pid is a positive PID; negative targets its process group.
        if unsafe { libc::kill(-child_pid, signal) } == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        Ok(())
    }

    fn reap(main_child: i32) -> io::Result<Option<i32>> {
        let mut main_status = None;
        loop {
            let mut status = 0;
            // SAFETY: status points to a live, aligned integer; -1 reaps any child.
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid > 0 {
                if pid == main_child {
                    main_status = Some(exit_code(status));
                }
            } else if pid == 0 {
                return Ok(main_status);
            } else {
                let error = io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(libc::ECHILD) => return Ok(main_status),
                    Some(libc::EINTR) => continue,
                    _ => return Err(error),
                }
            }
        }
    }

    fn reap_remaining() -> io::Result<()> {
        loop {
            let mut status = 0;
            // SAFETY: status is a live output integer; all namespace children were killed.
            if unsafe { libc::waitpid(-1, &mut status, 0) } >= 0 {
                continue;
            }
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::ECHILD) => return Ok(()),
                Some(libc::EINTR) => continue,
                _ => return Err(error),
            }
        }
    }

    fn exit_code(status: i32) -> i32 {
        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn refuses_execution_outside_linux_namespace_init() {
        assert!(run(vec!["/bin/true".into()], "{}").await.is_err());
        // Type-check the init entry without executing PID 1 operations.
        let _ = linux::run;
    }

    #[tokio::test]
    async fn binds_optional_kernel_before_workload_and_releases_proxy_on_collision() {
        let localhost = std::net::Ipv4Addr::LOCALHOST;
        let optional = bind_listeners((localhost, 0).into(), None).await.unwrap();
        assert!(optional.kernel.is_none());
        let occupied = tokio::net::TcpListener::bind((localhost, 0)).await.unwrap();
        let available = tokio::net::TcpListener::bind((localhost, 0)).await.unwrap();
        let proxy_address = available.local_addr().unwrap();
        drop(available);
        let result = bind_listeners(proxy_address, Some(occupied.local_addr().unwrap())).await;
        assert!(matches!(result, Err(error) if error.kind() == std::io::ErrorKind::AddrInUse));
        assert!(tokio::net::TcpListener::bind(proxy_address).await.is_ok());
    }

    #[tokio::test]
    async fn kernel_marker_requires_a_socket_and_bridge_reaches_its_own_endpoint() {
        let temporary = tempfile::tempdir().unwrap();
        let proxy_path = temporary.path().join("proxy.sock");
        let kernel_path = temporary.path().join("kernel.sock");
        assert!(!mounted_kernel(&kernel_path).unwrap());
        std::fs::write(&kernel_path, b"not a socket").unwrap();
        assert!(mounted_kernel(&kernel_path).is_err());
        std::fs::remove_file(&kernel_path).unwrap();
        let proxy = tokio::net::UnixListener::bind(&proxy_path).unwrap();
        let kernel = tokio::net::UnixListener::bind(&kernel_path).unwrap();
        assert!(mounted_kernel(&kernel_path).unwrap());
        let localhost = std::net::Ipv4Addr::LOCALHOST;
        let listeners = bind_listeners((localhost, 0).into(), Some((localhost, 0).into()))
            .await
            .unwrap();
        let kernel_address = listeners.kernel.as_ref().unwrap().local_addr().unwrap();
        let transport = tokio::spawn(bridges(listeners, proxy_path, Some(kernel_path)));
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut client = tokio::net::TcpStream::connect(kernel_address)
                .await
                .unwrap();
            client.write_all(b"kernel request").await.unwrap();
            client.shutdown().await.unwrap();
            let (mut endpoint, _) = kernel.accept().await.unwrap();
            let mut bytes = Vec::new();
            endpoint.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"kernel request");
            endpoint.write_all(b"kernel reply").await.unwrap();
            endpoint.shutdown().await.unwrap();
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"kernel reply");
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(50), proxy.accept())
                    .await
                    .is_err()
            );
        })
        .await
        .unwrap();
        transport.abort();
    }

    #[tokio::test]
    async fn bridges_loopback_to_unix_socket_bidirectionally() {
        let temporary = tempfile::tempdir().unwrap();
        let socket = temporary.path().join("proxy.sock");
        let unix = tokio::net::UnixListener::bind(&socket).unwrap();
        let tcp = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = tcp.local_addr().unwrap();
        let transport = tokio::spawn(bridge(tcp, socket));
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
            client.write_all(b"proxy request").await.unwrap();
            client.shutdown().await.unwrap();
            let (mut server, _) = unix.accept().await.unwrap();
            let mut request = Vec::new();
            server.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"proxy request");
            server.write_all(b"proxy response").await.unwrap();
            server.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"proxy response");
        })
        .await
        .unwrap();
        transport.abort();
    }
}
