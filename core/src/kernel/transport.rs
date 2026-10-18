use super::*;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use std::{
    fmt, fs, io,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::Path,
    sync::atomic::Ordering,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::watch,
    task::{JoinHandle, JoinSet},
};

pub struct KernelServer {
    state: Arc<State>,
    socket_path: PathBuf,
    cleanup: Option<PathBuf>,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}
impl KernelServer {
    pub async fn bind(
        home: &Path,
        identity: KernelIdentity,
        store: Arc<Store>,
        mut provider_ids: Vec<String>,
    ) -> Result<Self, KernelError> {
        identity.validate()?;
        if !home.is_absolute()
            || home
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(KernelError::Invalid);
        }
        if let Some(session) = &identity.session_id {
            store.session(session.clone()).await?;
        }
        let home = home.canonicalize()?;
        let run = home.join("run");
        let parent = run.join("k");
        // Check every core-owned component; an existing symlink is never adopted.
        crate::home::private_dir(&run)?;
        crate::home::private_dir(&parent)?;
        let socket_path = parent.join(format!("{}.sock", identity.instance_id));
        // sockaddr_un reserves one byte for NUL. Never fall back outside run/k.
        // SAFETY: sockaddr_un contains only integer fields and a byte array, all
        // of which admit zero. It is used only to inspect the array capacity.
        let address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        let capacity = std::mem::size_of_val(&address.sun_path);
        if socket_path.as_os_str().as_bytes().len() >= capacity {
            return Err(KernelError::Invalid);
        }
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|_| KernelError::Random)?;
        let token = random.iter().map(|b| format!("{b:02x}")).collect();
        provider_ids.sort();
        provider_ids.dedup();
        let state = Arc::new(State {
            identity,
            token,
            revoked: AtomicBool::new(false),
            home,
            store,
            provider_ids,
        });
        // bind refuses an existing path; no stale socket or other file is removed.
        let listener = UnixListener::bind(&socket_path)?;
        if let Err(error) = fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)) {
            drop(listener);
            let _ = fs::remove_file(&socket_path);
            return Err(error.into());
        }
        let (stop, rx) = watch::channel(false);
        let shared = state.clone();
        let task = tokio::spawn(async move { accept(listener, shared, rx).await });
        Ok(Self {
            state,
            socket_path: socket_path.clone(),
            cleanup: Some(socket_path),
            stop,
            task: Some(task),
        })
    }
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
    pub fn url(&self) -> String {
        format!("unix://{}", self.socket_path.display())
    }
    /// Secret supervisor handoff only. This type intentionally has no Debug.
    pub fn token(&self) -> &str {
        &self.state.token
    }
    /// End the transport gracefully without removing its socket or revoking
    /// the instance token. The supervisor revokes tokens after its grace period
    /// and removes resources only after confirming the PID namespace has exited.
    pub fn notify_shutdown(&self) {
        let _ = self.stop.send(true);
    }
    pub fn revoke(&self) {
        self.state.revoked.store(true, Ordering::Release);
        self.notify_shutdown();
    }
    pub async fn shutdown(&mut self) -> Result<(), KernelError> {
        self.revoke();
        if let Some(task) = self.task.take() {
            task.await.map_err(|_| KernelError::Task)?;
        }
        if let Some(path) = self.cleanup.take() {
            fs::remove_file(path)?;
        }
        Ok(())
    }
}
impl Drop for KernelServer {
    fn drop(&mut self) {
        self.revoke();
        if let Some(task) = self.task.take() {
            task.abort();
        }
        if let Some(path) = self.cleanup.take() {
            let _ = fs::remove_file(path);
        }
    }
}
// Bound aggregate message buffers and file descriptors per instance, including
// connections that have not authenticated or completed their first line.
const MAX_CONNECTIONS: usize = 4;
async fn accept(listener: UnixListener, state: Arc<State>, mut stop: watch::Receiver<bool>) {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {biased;
            _=stop.changed()=>break,
            result=listener.accept()=>match result {
                Ok((stream,_))=>{
                    while tasks.try_join_next().is_some() {}
                    if tasks.len() < MAX_CONNECTIONS {
                        tasks.spawn(connection(stream,state.clone(),stop.clone()));
                    } // Otherwise the new stream drops here; existing channels remain intact.
                },
                Err(_)=>break,
            },
            _=tasks.join_next(),if !tasks.is_empty()=>{},
        }
    }
    drop(listener);
    // Connections observe revocation in every read, dispatch and write phase.
    while tasks.join_next().await.is_some() {}
}
async fn shutdown_notice(stream: &mut UnixStream) {
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        stream
            .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"shutdown\",\"params\":{}}\n")
            .await?;
        stream.shutdown().await
    })
    .await;
}
async fn connection(stream: UnixStream, state: Arc<State>, mut stop: watch::Receiver<bool>) {
    let mut reader = BufReader::new(stream);
    let mut authenticated = false;
    loop {
        if state.revoked.load(Ordering::Acquire) {
            shutdown_notice(reader.get_mut()).await;
            return;
        }
        let line = tokio::select! {biased;
            _=stop.changed()=>{shutdown_notice(reader.get_mut()).await;return;},
            value=read_line(&mut reader)=>value,
        };
        let bytes = match line {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return,
            Err(error) => {
                let _ = write_response(reader.get_mut(), None, Err(error), None).await;
                return;
            }
        };
        let request = parse(&bytes);
        let request = match request {
            Ok(request) => request,
            Err(error) => {
                if write_response(reader.get_mut(), None, Err(error), Some(&mut stop))
                    .await
                    .is_err()
                {
                    return;
                }
                if !authenticated {
                    return;
                } else {
                    continue;
                }
            }
        };
        let id = request.id;
        if !authenticated {
            if request.method != "kernel.hello" || id.is_none() {
                let _ = write_response(reader.get_mut(), id, Err(RpcError::AUTH), Some(&mut stop))
                    .await;
                return;
            }
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Hello {
                protocol: u32,
                token: String,
            }
            let hello: Hello = match params(request.params) {
                Ok(hello) => hello,
                Err(error) => {
                    let _ = write_response(reader.get_mut(), id, Err(error), Some(&mut stop)).await;
                    return;
                }
            };
            if !constant_time_token(&state.token, &hello.token)
                || state.revoked.load(Ordering::Acquire)
            {
                let _ = write_response(reader.get_mut(), id, Err(RpcError::AUTH), Some(&mut stop))
                    .await;
                return;
            }
            if hello.protocol != 1 {
                let mut response =
                    json!({"jsonrpc":"2.0","id":id,"error":RpcError::INVALID.value()});
                response["error"]["data"] = json!({"supported":[1]});
                let _ = write_value(reader.get_mut(), &response, Some(&mut stop)).await;
                return;
            }
            let mut result = json!({"protocol":1,"ext_id":state.identity.ext_id,"instance_id":state.identity.instance_id,"scopes":state.identity.scopes});
            if let Some(session) = &state.identity.session_id {
                let current = tokio::select! {biased;
                    _=stop.changed()=>{shutdown_notice(reader.get_mut()).await;return;},
                    current=state.store.session(session.clone())=>current,
                };
                match current {
                    Ok(session) => {
                        result["session"] = match serde_json::to_value(session) {
                            Ok(value) => value,
                            Err(_) => return,
                        }
                    }
                    Err(error) => {
                        let _ = write_response(
                            reader.get_mut(),
                            id,
                            Err(error.into()),
                            Some(&mut stop),
                        )
                        .await;
                        return;
                    }
                }
            }
            authenticated = true;
            if write_response(reader.get_mut(), id, Ok(result), Some(&mut stop))
                .await
                .is_err()
            {
                return;
            }
            continue;
        }
        if request.method == "kernel.hello" {
            if id.is_some()
                && write_response(
                    reader.get_mut(),
                    id,
                    Err(RpcError::INVALID),
                    Some(&mut stop),
                )
                .await
                .is_err()
            {
                return;
            }
            continue;
        }
        // This infrastructure has no log sink yet. Never acknowledge arbitrary
        // notifications as successful calls or record their potentially secret fields.
        if id.is_none() {
            continue;
        }
        let result = tokio::select! {biased;
            _=stop.changed()=>{shutdown_notice(reader.get_mut()).await;return;},
            result=dispatch::call(&state,&request.method,request.params)=>result,
        };
        if state.revoked.load(Ordering::Acquire) {
            shutdown_notice(reader.get_mut()).await;
            return;
        }
        if write_response(reader.get_mut(), id, result, Some(&mut stop))
            .await
            .is_err()
        {
            return;
        }
    }
}
fn constant_time_token(expected: &str, provided: &str) -> bool {
    let supplied = provided.as_bytes();
    let mut difference = expected.len() ^ supplied.len();
    for (index, byte) in expected.bytes().enumerate() {
        difference |= usize::from(byte ^ supplied.get(index).copied().unwrap_or(0));
    }
    difference == 0
}
async fn read_line(reader: &mut BufReader<UnixStream>) -> Result<Option<Vec<u8>>, RpcError> {
    let mut result = Vec::new();
    loop {
        let available = reader.fill_buf().await.map_err(|_| RpcError::INTERNAL)?;
        if available.is_empty() {
            return if result.is_empty() {
                Ok(None)
            } else {
                Err(RpcError {
                    code: -32600,
                    message: "INVALID_REQUEST",
                })
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let count = newline.unwrap_or(available.len());
        if count > MAX_MESSAGE_BYTES.saturating_sub(result.len()) {
            return Err(RpcError::TOO_LARGE);
        }
        result.extend_from_slice(&available[..count]);
        reader.consume(count + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(Some(result));
        }
    }
}
async fn write_response(
    stream: &mut UnixStream,
    id: Option<Value>,
    result: Result<Value, RpcError>,
    stop: Option<&mut watch::Receiver<bool>>,
) -> io::Result<()> {
    let value = match result {
        Ok(result) => json!({"jsonrpc":"2.0","id":id,"result":result}),
        Err(error) => json!({"jsonrpc":"2.0","id":id,"error":error.value()}),
    };
    write_value(stream, &value, stop).await
}
async fn write_value(
    stream: &mut UnixStream,
    value: &Value,
    stop: Option<&mut watch::Receiver<bool>>,
) -> io::Result<()> {
    let frame = match encode(value) {
        Ok(frame) => frame,
        Err(_) => {
            let error =
                json!({"jsonrpc":"2.0","id":value.get("id"),"error":RpcError::TOO_LARGE.value()});
            match encode(&error){Ok(frame)=>frame,Err(_)=>b"{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32010,\"message\":\"TOO_LARGE\"}}\n".to_vec()}
        }
    };
    if let Some(stop) = stop {
        tokio::select! {biased;
            _=stop.changed()=>Err(io::Error::new(io::ErrorKind::Interrupted,"kernel revoked")),
            result=stream.write_all(&frame)=>result,
        }
    } else {
        tokio::time::timeout(Duration::from_secs(1), stream.write_all(&frame))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "kernel closed"))?
    }
}
struct Bounded(Vec<u8>);
impl io::Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_MESSAGE_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::other("message too large"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode(value: &Value) -> Result<Vec<u8>, serde_json::Error> {
    let mut out = Bounded(Vec::new());
    serde_json::to_writer(&mut out, value)?;
    out.0.push(b'\n');
    Ok(out.0)
}
fn parse(bytes: &[u8]) -> Result<Request, RpcError> {
    let StrictValue(value) = serde_json::from_slice(bytes).map_err(|_| RpcError {
        code: -32700,
        message: "PARSE_ERROR",
    })?;
    let request: Request = serde_json::from_value(value).map_err(|_| RpcError {
        code: -32600,
        message: "INVALID_REQUEST",
    })?;
    if request.jsonrpc != "2.0"
        || request.method.is_empty()
        || !request.params.is_object()
        || request
            .id
            .as_ref()
            .is_some_and(|id| !matches!(id, Value::Null | Value::String(_) | Value::Number(_)))
    {
        return Err(RpcError {
            code: -32600,
            message: "INVALID_REQUEST",
        });
    }
    Ok(request)
}
/// Reject duplicate keys before converting to Value, including nested params.
/// serde_json's default recursion limit remains enabled.
struct StrictValue(Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Strict;
        impl<'de> Visitor<'de> for Strict {
            type Value = StrictValue;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON value without duplicate keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|v| StrictValue(Value::Number(v)))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(v.into())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(v)))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(StrictValue(v)) = a.next_element()? {
                    values.push(v);
                }
                Ok(StrictValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((key, StrictValue(value))) = a.next_entry::<String, StrictValue>()? {
                    if values.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate key"));
                    }
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(Strict)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn token_and_json_boundaries() {
        assert!(constant_time_token("abc", "abc"));
        assert!(!constant_time_token("abc", "ab"));
        assert!(!constant_time_token("abc", "abcd"));
        assert!(!constant_time_token("abc", "abd"));
        assert!(
            parse(br#"{"jsonrpc":"2.0","id":null,"method":"x","params":{}}"#)
                .unwrap()
                .id
                .is_some()
        );
        assert!(
            parse(br#"{"jsonrpc":"2.0","id":1,"method":"x","params":{"key":1,"key":2}}"#).is_err()
        );
        assert!(parse(br#"{"jsonrpc":"2.0","id":1,"method":"x","unknown":1}"#).is_err());
        assert!(encode(&json!({"large":"x".repeat(MAX_MESSAGE_BYTES)})).is_err());
    }
}
