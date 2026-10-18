//! Private spawn barrier, separate from Kernel Protocol. The caller releases
//! it only after `armed` is durable and the peer's PID 1 identity is pinned.
//! Closing either side, timing out, or dropping a pending admission never
//! authorizes a workload. Files remain for the journal's confirmed cleanup.
use super::SandboxError;
use std::{
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

const AUTHORIZE: u8 = 0xa5;
pub(crate) const INIT_TIMEOUT: Duration = Duration::from_secs(10);

fn denied() -> SandboxError {
    SandboxError::Invalid("barreira de admissão não autorizada")
}
fn uid() -> u32 {
    // SAFETY: geteuid has no arguments or memory-safety preconditions.
    unsafe { libc::geteuid() }
}

/// Core-owned endpoint, normally derived from run/instances/<id>. It is never
/// removed on Drop: channel closure does not prove that PID 1 has finished.
pub struct AdmissionListener {
    listener: UnixListener,
    directory: File,
    socket: File,
    path: PathBuf,
}
impl AdmissionListener {
    pub fn bind(path: &Path) -> Result<Self, SandboxError> {
        if !path.is_absolute() || path.file_name() != Some("admission.sock".as_ref()) {
            return Err(denied());
        }
        let parent = super::mounts::canonicalize(path.parent().ok_or_else(denied)?)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&parent)?;
        let metadata = directory.metadata()?;
        if !metadata.is_dir() || metadata.uid() != uid() || metadata.mode() & 0o7777 != 0o700 {
            return Err(denied());
        }
        // These proc references address our own private descriptor, never a
        // manifest path or a source granted to an extension.
        let anchored = PathBuf::from(format!(
            "/proc/self/fd/{}/admission.sock",
            directory.as_raw_fd()
        ));
        // bind refuses any existing object. Do not adopt, remove, or repair it.
        let listener = UnixListener::bind(&anchored)?;
        let socket = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&anchored)?;
        let metadata = socket.metadata()?;
        if !metadata.file_type().is_socket() || metadata.uid() != uid() || metadata.nlink() != 1 {
            return Err(denied());
        }
        // chmod the pinned inode, so a renamed/replaced directory entry cannot
        // redirect a permission change to another file.
        std::fs::set_permissions(
            format!("/proc/self/fd/{}", socket.as_raw_fd()),
            std::fs::Permissions::from_mode(0o600),
        )?;
        let endpoint = Self {
            listener,
            directory,
            socket,
            path: parent.join("admission.sock"),
        };
        endpoint.verify()?;
        Ok(endpoint)
    }

    pub fn socket_path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn verify(&self) -> Result<(), SandboxError> {
        let parent = self.directory.metadata()?;
        let current_parent = std::fs::metadata(self.path.parent().ok_or_else(denied)?)?;
        if (parent.dev(), parent.ino()) != (current_parent.dev(), current_parent.ino())
            || parent.uid() != uid()
            || parent.mode() & 0o7777 != 0o700
        {
            return Err(denied());
        }
        let pinned = self.socket.metadata()?;
        let current = std::fs::symlink_metadata(format!(
            "/proc/self/fd/{}/admission.sock",
            self.directory.as_raw_fd()
        ))?;
        if !current.file_type().is_socket()
            || (current.dev(), current.ino()) != (pinned.dev(), pinned.ino())
            || current.uid() != uid()
            || current.mode() & 0o7777 != 0o600
            || current.nlink() != 1
        {
            return Err(denied());
        }
        Ok(())
    }

    /// Accept exactly one peer. The PID is supplied by SO_PEERCRED in the
    /// observer's namespace, never by data sent from the sandbox. The caller
    /// still pins/revalidates it as PID 1 before persisting the armed journal.
    pub async fn accept(self, timeout: Duration) -> Result<PendingAdmission, SandboxError> {
        let (stream, _) = tokio::time::timeout(timeout, self.listener.accept())
            .await
            .map_err(|_| denied())??;
        let peer_pid = peer(&stream, uid())?;
        // Consume the listener: no later workload can reconnect and request a
        // second release. Keep private anchors until the accepted channel ends.
        drop(self.listener);
        Ok(PendingAdmission {
            stream,
            peer_pid,
            _anchors: (self.directory, self.socket),
        })
    }
}

fn peer(stream: &UnixStream, expected_uid: u32) -> Result<u32, SandboxError> {
    let credentials = stream.peer_cred()?;
    if credentials.uid() != expected_uid {
        return Err(denied());
    }
    credentials
        .pid()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid != 0)
        .ok_or_else(denied)
}

/// A connected, authenticated init remains blocked until the trusted caller
/// persists armed. Dropping this value sends no authorization byte.
pub struct PendingAdmission {
    stream: UnixStream,
    peer_pid: u32,
    _anchors: (File, File),
}
impl PendingAdmission {
    pub fn peer_pid(&self) -> u32 {
        self.peer_pid
    }

    /// Call only after the exact peer identity and launcher are pinned and
    /// journal.arm has durably succeeded. This API performs no journal writes.
    pub async fn release(mut self) -> Result<(), SandboxError> {
        tokio::time::timeout(INIT_TIMEOUT, async {
            self.stream.write_all(&[AUTHORIZE]).await?;
            self.stream.shutdown().await
        })
        .await
        .map_err(|_| denied())??;
        Ok(())
    }
}

pub(crate) async fn wait_for_authorization() -> Result<(), SandboxError> {
    wait_at(Path::new("/fx/admission.sock"), INIT_TIMEOUT).await
}

async fn wait_at(path: &Path, timeout: Duration) -> Result<(), SandboxError> {
    tokio::time::timeout(timeout, async {
        let mut stream = UnixStream::connect(path).await?;
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await?;
        if byte[0] != AUTHORIZE {
            return Err(denied());
        }
        // Require a complete, exact one-byte authorization, then close this
        // CLOEXEC channel before creating any workload process.
        if stream.read(&mut byte).await? != 0 {
            return Err(denied());
        }
        Ok(())
    })
    .await
    .map_err(|_| denied())?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    #[tokio::test]
    async fn only_explicit_release_unblocks_and_peer_pid_comes_from_the_kernel() {
        let root = root();
        let listener = AdmissionListener::bind(&root.path().join("admission.sock")).unwrap();
        let path = listener.socket_path().to_owned();
        let mut waiting = tokio::spawn(async move { wait_at(&path, INIT_TIMEOUT).await });
        let accepted = listener.accept(Duration::from_secs(1)).await.unwrap();
        assert_eq!(accepted.peer_pid(), std::process::id());
        assert!(peer(&accepted.stream, uid().wrapping_add(1)).is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(30), &mut waiting)
                .await
                .is_err()
        );
        accepted.release().await.unwrap();
        waiting.await.unwrap().unwrap();
        assert_eq!(
            std::fs::metadata(root.path().join("admission.sock"))
                .unwrap()
                .mode()
                & 0o7777,
            0o600
        );
    }

    #[tokio::test]
    async fn eof_invalid_byte_timeout_and_missing_channel_never_authorize() {
        for mode in ["eof", "invalid", "extra", "timeout"] {
            let root = root();
            let listener = AdmissionListener::bind(&root.path().join("admission.sock")).unwrap();
            let path = listener.socket_path().to_owned();
            let waiting =
                tokio::spawn(async move { wait_at(&path, Duration::from_millis(80)).await });
            let mut accepted = listener.accept(Duration::from_secs(1)).await.unwrap();
            match mode {
                "invalid" => {
                    accepted.stream.write_all(&[0]).await.unwrap();
                    accepted.stream.shutdown().await.unwrap();
                }
                "extra" => {
                    accepted
                        .stream
                        .write_all(&[AUTHORIZE, AUTHORIZE])
                        .await
                        .unwrap();
                    accepted.stream.shutdown().await.unwrap();
                }
                "timeout" => {}
                _ => {
                    drop(accepted);
                    assert!(waiting.await.unwrap().is_err());
                    continue;
                }
            }
            assert!(waiting.await.unwrap().is_err(), "{mode}");
        }
        let root = root();
        assert!(
            wait_at(&root.path().join("absent.sock"), Duration::from_millis(20))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn private_parent_and_unused_name_are_required_without_repair_or_drop_cleanup() {
        let root = root();
        let path = root.path().join("admission.sock");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(AdmissionListener::bind(&path).is_err());
        assert!(!path.exists());
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(&path, "existing").unwrap();
        assert!(AdmissionListener::bind(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"existing");
        std::fs::remove_file(&path).unwrap();
        let listener = AdmissionListener::bind(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, "replacement").unwrap();
        assert!(listener.verify().is_err());
        drop(listener);
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
    }
}
