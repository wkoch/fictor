//! ADR-041: one authenticated local request, one bounded response. This is
//! separate from Kernel Protocol and does not dispatch to extensions.
mod protocol;
use crate::{
    installer::listing::{self, ListingError, MAX_MESSAGE_BYTES, Snapshot, TIMEOUT},
    ownership::HomeLease,
};
pub use protocol::{
    AdminClientError, AdminMutationError, AdminMutationFuture, AdminMutationHandler, Effect,
    MutationReason,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::watch,
    task::{JoinHandle, JoinSet},
};
pub(crate) fn valid_method_params(method: &str, params: &Value) -> bool {
    params
        .as_object()
        .is_some_and(|params| protocol::valid_params(method, params))
}

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("ext.list failed: {0}")]
    Listing(#[from] ListingError),
    #[error("admin transport failed")]
    Transport,
    #[error("admin identity check failed")]
    Identity,
}

struct Bounded {
    bytes: Vec<u8>,
    overflow: bool,
}
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_MESSAGE_BYTES.saturating_sub(self.bytes.len()) {
            self.overflow = true;
            return Err(io::Error::other("admin frame limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(crate) fn bounded_json(value: &impl Serialize) -> Result<Vec<u8>, ListingError> {
    let mut output = Bounded {
        bytes: Vec::new(),
        overflow: false,
    };
    if serde_json::to_writer(&mut output, value).is_err() {
        return Err(if output.overflow {
            ListingError::TooLarge
        } else {
            ListingError::InvalidSnapshot
        });
    }
    Ok(output.bytes)
}

struct Run {
    directory: File,
}
impl Run {
    fn open(home: &Path) -> Result<Arc<Self>, AdminError> {
        let home = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(home)
            .map_err(|_| AdminError::Identity)?;
        private_directory(&home)?;
        // SAFETY: the live directory and static component remain valid.
        let fd = unsafe {
            libc::openat(
                home.as_raw_fd(),
                c"run".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(AdminError::Identity);
        }
        // SAFETY: successful openat returned this fresh owned descriptor.
        let directory = unsafe { File::from_raw_fd(fd) };
        private_directory(&directory)?;
        Ok(Arc::new(Self { directory }))
    }
    fn path(&self) -> PathBuf {
        PathBuf::from(format!(
            "/proc/self/fd/{}/admin.sock",
            self.directory.as_raw_fd()
        ))
    }
    fn socket(&self) -> Result<std::fs::Metadata, AdminError> {
        let metadata = std::fs::symlink_metadata(self.path()).map_err(|_| AdminError::Identity)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != uid()
            || metadata.mode() & 0o7777 != 0o600
        {
            return Err(AdminError::Identity);
        }
        Ok(metadata)
    }
}
fn uid() -> u32 {
    // SAFETY: geteuid has no arguments or memory-safety preconditions.
    unsafe { libc::geteuid() }
}
fn private_directory(file: &File) -> Result<(), AdminError> {
    let metadata = file.metadata().map_err(|_| AdminError::Identity)?;
    if !metadata.is_dir() || metadata.uid() != uid() || metadata.mode() & 0o7777 != 0o700 {
        return Err(AdminError::Identity);
    }
    Ok(())
}
fn authenticate(stream: &UnixStream, expected: u32) -> Result<(), AdminError> {
    if stream.peer_cred().map_err(|_| AdminError::Identity)?.uid() != expected {
        return Err(AdminError::Identity);
    }
    Ok(())
}
struct SocketOwner {
    run: Arc<Run>,
    identity: (u64, u64),
}
impl Drop for SocketOwner {
    fn drop(&mut self) {
        // Remove only our own endpoint; never repair/adopt a replaced entry.
        if std::fs::symlink_metadata(self.run.path()).is_ok_and(|metadata| {
            metadata.file_type().is_socket()
                && metadata.uid() == uid()
                && (metadata.dev(), metadata.ino()) == self.identity
        }) {
            // SAFETY: the pinned parent and static component remain live.
            unsafe {
                libc::unlinkat(self.run.directory.as_raw_fd(), c"admin.sock".as_ptr(), 0);
            }
        }
    }
}

pub struct AdminServer {
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}
#[derive(Clone, Default)]
struct Services {
    controls: Option<Arc<dyn AdminMutationHandler>>,
    installer: Option<Arc<dyn AdminMutationHandler>>,
}
pub struct AdminServerBuilder {
    owner: Arc<HomeLease>,
    services: Services,
}
impl AdminServerBuilder {
    pub fn with_controls(mut self, service: Arc<dyn AdminMutationHandler>) -> Self {
        self.services.controls = Some(service);
        self
    }
    pub fn with_installer(mut self, service: Arc<dyn AdminMutationHandler>) -> Self {
        self.services.installer = Some(service);
        self
    }
    pub async fn bind(self) -> Result<AdminServer, AdminError> {
        AdminServer::bind_services(self.owner, self.services).await
    }
}
impl AdminServer {
    pub fn builder(owner: Arc<HomeLease>) -> AdminServerBuilder {
        AdminServerBuilder {
            owner,
            services: Services::default(),
        }
    }
    pub async fn bind(owner: Arc<HomeLease>) -> Result<Self, AdminError> {
        Self::builder(owner).bind().await
    }
    async fn bind_services(owner: Arc<HomeLease>, services: Services) -> Result<Self, AdminError> {
        owner.verify().map_err(|_| AdminError::Identity)?;
        let run = Run::open(&owner.anchored_path().join("."))?;
        let listener = UnixListener::bind(run.path()).map_err(|_| AdminError::Transport)?;
        let metadata = std::fs::symlink_metadata(run.path()).map_err(|_| AdminError::Identity)?;
        let socket = SocketOwner {
            run: run.clone(),
            identity: (metadata.dev(), metadata.ino()),
        };
        std::fs::set_permissions(run.path(), std::fs::Permissions::from_mode(0o600))
            .map_err(|_| AdminError::Identity)?;
        run.socket()?;
        let (stop, mut stopped) = watch::channel(false);
        let task = tokio::spawn(async move {
            let _socket = socket;
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = stopped.changed() => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break; };
                        if authenticate(&stream, uid()).is_err() { continue; }
                        connections.spawn(serve(stream, owner.clone(),services.clone()));
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        Ok(Self {
            stop,
            task: Some(task),
        })
    }
    pub async fn shutdown(mut self) -> Result<(), AdminError> {
        self.stop.send_replace(true);
        if let Some(task) = self.task.take() {
            task.await.map_err(|_| AdminError::Transport)?;
        }
        Ok(())
    }
}
impl Drop for AdminServer {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}

async fn line(reader: &mut BufReader<UnixStream>) -> Result<Vec<u8>, AdminError> {
    let mut bytes = Vec::new();
    loop {
        let available = tokio::time::timeout(TIMEOUT, reader.fill_buf())
            .await
            .map_err(|_| AdminError::Transport)?
            .map_err(|_| AdminError::Transport)?;
        if available.is_empty() {
            return Err(AdminError::Transport);
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let count = newline.unwrap_or(available.len());
        if count > MAX_MESSAGE_BYTES.saturating_sub(bytes.len()) {
            return Err(ListingError::TooLarge.into());
        }
        bytes.extend_from_slice(&available[..count]);
        reader.consume(count + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(bytes);
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    jsonrpc: String,
    id: String,
    method: String,
    params: Map<String, Value>,
}
enum Parsed {
    Request(Request),
    Ignore,
    Error(Value),
}
fn rpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
fn failure(id: &str, reason: ListingError) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":"ext.list failed","data":{"reason":reason}}})
}
fn parse(bytes: &[u8]) -> Parsed {
    let ordinary: Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(_) => return Parsed::Error(rpc_error(Value::Null, -32700, "Parse error")),
    };
    if ordinary
        .as_object()
        .is_some_and(|object| !object.contains_key("id"))
    {
        return Parsed::Ignore;
    }
    let strict = match crate::strict_json::parse(bytes) {
        Ok(value) => value,
        Err(_) => return Parsed::Error(rpc_error(Value::Null, -32600, "Invalid Request")),
    };
    let id = strict
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty() && id.len() <= 128)
        .map(|id| Value::String(id.into()))
        .unwrap_or(Value::Null);
    let request: Request = match serde_json::from_value(strict) {
        Ok(request) => request,
        Err(_) => return Parsed::Error(rpc_error(id, -32600, "Invalid Request")),
    };
    if request.jsonrpc != "2.0" || request.id.is_empty() || request.id.len() > 128 {
        return Parsed::Error(rpc_error(id, -32600, "Invalid Request"));
    }
    if request.method != "ext.list"
        && !protocol::CONTROLS.contains(&request.method.as_str())
        && !protocol::INSTALL.contains(&request.method.as_str())
    {
        return Parsed::Error(rpc_error(id, -32601, "Method not found"));
    }
    if !protocol::valid_params(&request.method, &request.params) {
        return Parsed::Error(rpc_error(id, -32602, "Invalid params"));
    }
    Parsed::Request(request)
}
fn response_bytes(response: &Value) -> Result<Vec<u8>, ListingError> {
    match bounded_json(response) {
        Ok(bytes) => Ok(bytes),
        Err(reason) => bounded_json(&json!({
            "jsonrpc":"2.0", "id":response.get("id").cloned().unwrap_or(Value::Null),
            "error":{"code":-32000,"message":"ext.list failed","data":{"reason":reason}}
        })),
    }
}

async fn serve(stream: UnixStream, owner: Arc<HomeLease>, services: Services) {
    let mut reader = BufReader::new(stream);
    let Ok(bytes) = line(&mut reader).await else {
        return;
    };
    let parsed = parse(&bytes);
    let method = match &parsed {
        Parsed::Request(request) => Some(request.method.clone()),
        _ => None,
    };
    let response = match parsed {
        Parsed::Ignore => return,
        Parsed::Error(error) => error,
        Parsed::Request(request) if request.method == "ext.list" => {
            match listing::snapshot(owner).await {
                Ok(snapshot) => json!({"jsonrpc":"2.0","id":request.id,"result":snapshot}),
                Err(reason) => failure(&request.id, reason),
            }
        }
        Parsed::Request(request) => {
            let handler = if protocol::CONTROLS.contains(&request.method.as_str()) {
                services.controls
            } else {
                services.installer
            };
            let result = if let Some(handler) = handler {
                let method = request.method.clone();
                let params = Value::Object(request.params);
                // Once a trusted request reaches admission, disconnect/shutdown
                // cannot cancel its owner. The service enforces its 5s gate.
                tokio::spawn(async move { handler.call_mutation(&method, &params).await })
                    .await
                    .unwrap_or_else(|_| Err(AdminMutationError::unknown(MutationReason::IoError)))
            } else {
                Err(AdminMutationError::none(MutationReason::InvalidState))
            };
            match result {
                Ok(value) => json!({"jsonrpc":"2.0","id":request.id,"result":value}),
                Err(error) => {
                    json!({"jsonrpc":"2.0","id":request.id,"error":{"code":-32000,"message":format!("{} failed",request.method),"data":error}})
                }
            }
        }
    };
    let encoded = match method.as_deref() {
        Some(method) if method != "ext.list" => mutation_response_bytes(&response, method),
        _ => response_bytes(&response),
    };
    if let Ok(mut bytes) = encoded {
        bytes.push(b'\n');
        let _ = tokio::time::timeout(TIMEOUT, reader.get_mut().write_all(&bytes)).await;
    }
}
fn mutation_response_bytes(response: &Value, method: &str) -> Result<Vec<u8>, ListingError> {
    match bounded_json(response) {
        Ok(bytes) => Ok(bytes),
        Err(reason) => {
            // The generic transport cannot infer whether an admitted mutation
            // committed from an oversized result. Queries are always effectless.
            let effect = if matches!(method, "ext.install.status" | "secrets.list") {
                Effect::None
            } else {
                Effect::Unknown
            };
            bounded_json(
                &json!({"jsonrpc":"2.0","id":response.get("id").cloned().unwrap_or(Value::Null),"error":{"code":-32000,"message":format!("{method} failed"),"data":{"reason":MutationReason::from(reason),"effect":effect}}}),
            )
        }
    }
}

/// Called only after ownership was found busy. No fallback/retry is performed.
pub async fn request(home: &Path) -> Result<Snapshot, AdminError> {
    let run = Run::open(home)?;
    let before = run.socket()?;
    let stream = tokio::time::timeout(TIMEOUT, UnixStream::connect(run.path()))
        .await
        .map_err(|_| AdminError::Transport)?
        .map_err(|_| AdminError::Transport)?;
    authenticate(&stream, uid())?;
    let after = run.socket()?;
    if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
        return Err(AdminError::Identity);
    }
    let id = "cli-1";
    let mut reader = BufReader::new(stream);
    tokio::time::timeout(
        TIMEOUT,
        reader.get_mut().write_all(
            b"{\"jsonrpc\":\"2.0\",\"id\":\"cli-1\",\"method\":\"ext.list\",\"params\":{}}\n",
        ),
    )
    .await
    .map_err(|_| AdminError::Transport)?
    .map_err(|_| AdminError::Transport)?;
    let bytes = line(&mut reader).await?;
    let response = crate::strict_json::parse(&bytes).map_err(|_| AdminError::Transport)?;
    let object = response.as_object().ok_or(AdminError::Transport)?;
    if object.len() != 3
        || object.get("jsonrpc") != Some(&Value::String("2.0".into()))
        || object.get("id") != Some(&Value::String(id.into()))
    {
        return Err(AdminError::Transport);
    }
    let result = if let Some(result) = object.get("result") {
        let snapshot: Snapshot =
            serde_json::from_value(result.clone()).map_err(|_| AdminError::Transport)?;
        snapshot.validate()?;
        Ok(snapshot)
    } else if let Some(error) = object.get("error") {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Domain {
            code: i32,
            message: String,
            data: Reason,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Reason {
            reason: ListingError,
        }
        let error: Domain =
            serde_json::from_value(error.clone()).map_err(|_| AdminError::Transport)?;
        if error.code != -32000 || error.message != "ext.list failed" {
            return Err(AdminError::Transport);
        }
        Err(AdminError::Listing(error.data.reason))
    } else {
        return Err(AdminError::Transport);
    };
    let mut extra = [0; 1];
    if tokio::time::timeout(TIMEOUT, reader.read(&mut extra))
        .await
        .map_err(|_| AdminError::Transport)?
        .map_err(|_| AdminError::Transport)?
        != 0
    {
        return Err(AdminError::Transport);
    }
    result
}

/// Authenticate before transmitting administrative parameters (including a new
/// secret). A failed attempt after any write may have taken effect: never retry.
pub async fn request_method(
    home: &Path,
    method: &str,
    params: &Value,
) -> Result<Value, AdminClientError> {
    if !valid_method_params(method, params) {
        return Err(AdminClientError::Protocol {
            effect: Effect::None,
        });
    }
    let before_send = || AdminClientError::Transport {
        effect: Effect::None,
    };
    let after_send = || AdminClientError::Transport {
        effect: Effect::Unknown,
    };
    let malformed = || AdminClientError::Protocol {
        effect: Effect::Unknown,
    };
    let run = Run::open(home).map_err(|_| AdminClientError::Identity)?;
    let before = run.socket().map_err(|_| AdminClientError::Identity)?;
    let stream = tokio::time::timeout(TIMEOUT, UnixStream::connect(run.path()))
        .await
        .map_err(|_| before_send())?
        .map_err(|_| before_send())?;
    authenticate(&stream, uid()).map_err(|_| AdminClientError::Identity)?;
    let after = run.socket().map_err(|_| AdminClientError::Identity)?;
    if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
        return Err(AdminClientError::Identity);
    }
    let mut bytes =
        bounded_json(&json!({"jsonrpc":"2.0","id":"cli-1","method":method,"params":params}))
            .map_err(|_| {
                AdminClientError::Domain(AdminMutationError::none(MutationReason::TooLarge))
            })?;
    bytes.push(b'\n');
    let mut reader = BufReader::new(stream);
    tokio::time::timeout(TIMEOUT, reader.get_mut().write_all(&bytes))
        .await
        .map_err(|_| after_send())?
        .map_err(|_| after_send())?;
    let bytes = line(&mut reader).await.map_err(|_| after_send())?;
    let response = crate::strict_json::parse(&bytes).map_err(|_| malformed())?;
    let object = response.as_object().ok_or_else(malformed)?;
    if object.len() != 3
        || object.get("jsonrpc") != Some(&json!("2.0"))
        || object.get("id") != Some(&json!("cli-1"))
    {
        return Err(malformed());
    }
    let result = if let Some(result) = object.get("result") {
        Ok(result.clone())
    } else if let Some(error) = object.get("error") {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Domain {
            code: i32,
            message: String,
            data: AdminMutationError,
        }
        let error: Domain = serde_json::from_value(error.clone()).map_err(|_| malformed())?;
        if error.code != -32000 || error.message != format!("{method} failed") {
            return Err(malformed());
        }
        Err(AdminClientError::Domain(error.data))
    } else {
        return Err(malformed());
    };
    let mut extra = [0; 1];
    if tokio::time::timeout(TIMEOUT, reader.read(&mut extra))
        .await
        .map_err(|_| after_send())?
        .map_err(|_| after_send())?
        != 0
    {
        return Err(malformed());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_requests_reject_unknown_duplicate_and_invalid_fields() {
        for (bytes, code) in [
            (b"not json".as_slice(), -32700),
            (b"[{}]", -32600),
            (
                br#"{"jsonrpc":"2.0","id":"a","method":"ext.list","params":{},"extra":0}"#,
                -32600,
            ),
            (
                br#"{"jsonrpc":"2.0","id":"a","i\u0064":"b","method":"ext.list","params":{}}"#,
                -32600,
            ),
            (
                br#"{"jsonrpc":"2.0","id":"a","method":"ext.list","params":{"x":1,"x":2}}"#,
                -32600,
            ),
            (
                br#"{"jsonrpc":"2.0","id":null,"method":"ext.list","params":{}}"#,
                -32600,
            ),
            (
                br#"{"jsonrpc":"2.0","id":"","method":"ext.list","params":{}}"#,
                -32600,
            ),
            (
                br#"{"jsonrpc":"1.0","id":"a","method":"ext.list","params":{}}"#,
                -32600,
            ),
            (
                br#"{"jsonrpc":"2.0","id":"a","method":"ext.list","params":[]}"#,
                -32600,
            ),
            (
                br#"{"jsonrpc":"2.0","id":"a","method":"ext.list","params":{"extra":true}}"#,
                -32602,
            ),
            (
                br#"{"jsonrpc":"2.0","id":"a","method":"kernel.hello","params":{}}"#,
                -32601,
            ),
        ] {
            let Parsed::Error(error) = parse(bytes) else {
                panic!("invalid request accepted");
            };
            assert_eq!(error["error"]["code"], code);
        }
        assert!(matches!(
            parse(br#"{"jsonrpc":"2.0","method":"ext.list","params":{}}"#),
            Parsed::Ignore
        ));
        for (id, accepted) in [("é".repeat(64), true), ("é".repeat(64) + "a", false)] {
            let bytes = serde_json::to_vec(
                &json!({"jsonrpc":"2.0","id":id,"method":"ext.list","params":{}}),
            )
            .unwrap();
            assert_eq!(matches!(parse(&bytes), Parsed::Request(_)), accepted);
        }
    }

    #[test]
    fn response_budget_counts_escaped_envelope_and_falls_back_once() {
        let exact = "\n".repeat(MAX_MESSAGE_BYTES / 2 - 1);
        assert_eq!(bounded_json(&exact).unwrap().len(), MAX_MESSAGE_BYTES);
        assert_eq!(
            bounded_json(&(exact.clone() + "x")).unwrap_err(),
            ListingError::TooLarge
        );
        let response = json!({"jsonrpc":"2.0","id":"correlated","result":exact});
        let bytes = response_bytes(&response).unwrap();
        assert!(bytes.len() < 1024);
        let fallback: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(fallback["id"], "correlated");
        assert_eq!(fallback["error"]["data"]["reason"], "too_large");
        assert!(fallback.get("result").is_none());
    }

    #[tokio::test]
    async fn peer_credentials_are_checked_against_the_effective_uid() {
        let (left, _right) = UnixStream::pair().unwrap();
        authenticate(&left, uid()).unwrap();
        assert!(matches!(
            authenticate(&left, uid().wrapping_add(1)),
            Err(AdminError::Identity)
        ));
    }

    #[test]
    fn admin_paths_require_exact_private_directory_mode() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let file = File::open(directory.path()).unwrap();
        private_directory(&file).unwrap();
        for mode in [0o000, 0o600, 0o750, 0o1700, 0o2700, 0o4700] {
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(mode))
                .unwrap();
            assert!(private_directory(&file).is_err(), "mode {mode:o}");
        }
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}
