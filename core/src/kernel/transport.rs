use super::*;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde_json::value::RawValue;
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
        provider_ids: Vec<String>,
    ) -> Result<Self, KernelError> {
        Self::bind_with_log(home, identity, store, provider_ids, None).await
    }

    /// Bind the instance's authenticated log destination along with its identity.
    /// Low-level protocol endpoints may omit it; extension launches supply it.
    pub async fn bind_with_log(
        home: &Path,
        identity: KernelIdentity,
        store: Arc<Store>,
        mut provider_ids: Vec<String>,
        log: Option<Arc<dyn LogSink>>,
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
        let controls = Arc::new(crate::control_files::ControlFiles::open(&home)?);
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
            controls,
            store,
            provider_ids,
            log,
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
    /// Transfer pathname cleanup to the durable instance journal. Closing or
    /// dropping this transport then leaves the socket until both pidfds prove
    /// exit. Call immediately after bind, before launching any child.
    pub fn defer_socket_cleanup(&mut self) {
        self.cleanup = None;
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
        write_value(
            stream,
            &json!({"jsonrpc":"2.0","method":"shutdown","params":{}}),
        )
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
                // Oversized frames are refused before any request is admitted.
                if error.code != RpcError::TOO_LARGE.code {
                    let _ = write_response(reader.get_mut(), None, Err(error), None).await;
                }
                return;
            }
        };
        let request = parse(&bytes);
        let request = match request {
            Ok(request) => request,
            Err(ParseFailure::Close) => return,
            Err(ParseFailure::Reply { id, error }) => {
                if write_response(reader.get_mut(), id.as_ref(), Err(error), Some(&mut stop))
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
        let id = request.id.as_ref();
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
                let mut error = RpcError::INVALID.value();
                error["data"] = json!({"supported":[1]});
                let _ = write_reply(
                    reader.get_mut(),
                    id,
                    ReplyBody::Error { error },
                    Some(&mut stop),
                )
                .await;
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
        if id.is_none() {
            if request.method == "log"
                && let Ok(record) = params::<LogRecord>(request.params)
                && let Some(sink) = &state.log
            {
                let result = tokio::select! {biased;
                    _=stop.changed()=>{shutdown_notice(reader.get_mut()).await;return;},
                    result=sink.write(record)=>result,
                };
                if result.is_err() {
                    // No extension-controlled fields or raw errors reach core logs.
                    tracing::warn!(
                        ext_id = state.identity.ext_id,
                        instance_id = state.identity.instance_id,
                        "extension log unavailable"
                    );
                    return;
                }
            }
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
                Err(RpcError::new(-32600, "INVALID_REQUEST"))
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
    id: Option<&RequestId>,
    result: Result<Value, RpcError>,
    stop: Option<&mut watch::Receiver<bool>>,
) -> io::Result<()> {
    let body = match result {
        Ok(result) => ReplyBody::Result { result },
        Err(error) => ReplyBody::Error {
            error: error.value(),
        },
    };
    write_reply(stream, id, body, stop).await
}
#[derive(Serialize)]
#[serde(untagged)]
enum ReplyBody {
    Result { result: Value },
    Error { error: Value },
}
#[derive(Serialize)]
struct Reply<'a> {
    jsonrpc: &'static str,
    id: Option<&'a RequestId>,
    #[serde(flatten)]
    body: ReplyBody,
}
async fn write_reply(
    stream: &mut UnixStream,
    id: Option<&RequestId>,
    body: ReplyBody,
    stop: Option<&mut watch::Receiver<bool>>,
) -> io::Result<()> {
    let frame = reply_frame(id, body, MAX_MESSAGE_BYTES)?;
    write_frame(stream, &frame, stop).await
}
fn reply_frame(id: Option<&RequestId>, body: ReplyBody, limit: usize) -> io::Result<Vec<u8>> {
    let reply = Reply {
        jsonrpc: "2.0",
        id,
        body,
    };
    let frame = match encode_with_limit(&reply, limit) {
        Ok(frame) => frame,
        Err(_) => {
            // Correlation is immutable after admission, including on a second
            // serialization failure. No bytes of the normal reply were sent.
            let fallback = Reply {
                jsonrpc: "2.0",
                id,
                body: ReplyBody::Error {
                    error: RpcError::TOO_LARGE.value(),
                },
            };
            encode_with_limit(&fallback, limit).map_err(io::Error::other)?
        }
    };
    Ok(frame)
}
async fn write_frame(
    stream: &mut UnixStream,
    frame: &[u8],
    stop: Option<&mut watch::Receiver<bool>>,
) -> io::Result<()> {
    if let Some(stop) = stop {
        tokio::select! {biased;
            _=stop.changed()=>Err(io::Error::new(io::ErrorKind::Interrupted,"kernel revoked")),
            result=stream.write_all(frame)=>result,
        }
    } else {
        tokio::time::timeout(Duration::from_secs(1), stream.write_all(frame))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "kernel closed"))?
    }
}
/// Notifications have no correlation identity and cannot become error replies.
async fn write_value(stream: &mut UnixStream, value: &Value) -> io::Result<()> {
    let frame = encode_with_limit(value, MAX_MESSAGE_BYTES).map_err(io::Error::other)?;
    write_frame(stream, &frame, None).await
}
struct Bounded {
    bytes: Vec<u8>,
    limit: usize,
}
impl io::Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("message too large"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode_with_limit(value: &impl Serialize, limit: usize) -> Result<Vec<u8>, serde_json::Error> {
    let mut out = Bounded {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut out, value)?;
    out.bytes.push(b'\n');
    Ok(out.bytes)
}
#[derive(Debug)]
enum ParseFailure {
    Close,
    Reply {
        id: Option<RequestId>,
        error: RpcError,
    },
}
fn unidentified(error: RpcError) -> ParseFailure {
    ParseFailure::Reply { id: None, error }
}
const MAX_ID_BYTES: usize = 256;
fn parse(bytes: &[u8]) -> Result<Request, ParseFailure> {
    let invalid = RpcError::new(-32600, "INVALID_REQUEST");
    let parse_error = RpcError::new(-32700, "PARSE_ERROR");
    // Validate the complete JSON before identifying a request. RawValue keeps
    // number tokens opaque and lets us reject a batch without visiting members.
    let raw: &RawValue = serde_json::from_slice(bytes).map_err(|_| unidentified(parse_error))?;
    if !raw.get().starts_with('{') {
        return Err(unidentified(invalid));
    }
    let envelope: Envelope<'_> =
        serde_json::from_str(raw.get()).map_err(|_| unidentified(parse_error))?;
    if envelope.duplicate_id {
        return Err(unidentified(invalid));
    }
    let id = match envelope.id {
        None => None,
        Some(raw) if raw.get() == "null" => Some(RequestId::Null),
        Some(raw) if raw.get().starts_with('"') => {
            let value: String =
                serde_json::from_str(raw.get()).map_err(|_| unidentified(invalid))?;
            if value.len() > MAX_ID_BYTES {
                return Err(ParseFailure::Close);
            }
            Some(RequestId::String(value))
        }
        Some(raw)
            if raw
                .get()
                .starts_with(|c: char| c == '-' || c.is_ascii_digit()) =>
        {
            if raw.get().len() > MAX_ID_BYTES {
                return Err(ParseFailure::Close);
            }
            Some(RequestId::Number(raw.to_owned()))
        }
        Some(_) => return Err(unidentified(invalid)),
    };
    if envelope.invalid_fields {
        return Err(ParseFailure::Reply { id, error: invalid });
    }
    let mut values = serde_json::Map::new();
    for (key, raw) in envelope.fields {
        let StrictValue(value) = match serde_json::from_str(raw.get()) {
            Ok(value) => value,
            // The complete JSON and unique ID are already established. A
            // parameter that cannot become an application Value (including its
            // numeric range or depth) cannot erase that known correlation.
            Err(_) => return Err(ParseFailure::Reply { id, error: invalid }),
        };
        values.insert(key, value);
    }
    let method = values.remove("method");
    let params = values.remove("params").unwrap_or_else(|| json!({}));
    match method {
        Some(Value::String(method))
            if !method.is_empty()
                && values.get("jsonrpc") == Some(&Value::String("2.0".into()))
                && params.is_object() =>
        {
            Ok(Request { id, method, params })
        }
        _ => Err(ParseFailure::Reply { id, error: invalid }),
    }
}
/// Inspect every decoded key before choosing a correlation ID, retaining only
/// the four recognized fields. Repeating/unknown keys cannot grow retained
/// state. `id` and `i\u0064` are duplicates too.
#[derive(Default)]
struct Envelope<'a> {
    id: Option<&'a RawValue>,
    duplicate_id: bool,
    invalid_fields: bool,
    fields: Vec<(String, &'a RawValue)>,
}
impl<'de> Deserialize<'de> for Envelope<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Envelope<'de>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut envelope = Envelope::default();
                while let Some((key, raw)) = map.next_entry::<String, &'de RawValue>()? {
                    if key == "id" {
                        envelope.duplicate_id |= envelope.id.replace(raw).is_some();
                    } else if matches!(key.as_str(), "jsonrpc" | "method" | "params")
                        && !envelope.fields.iter().any(|(existing, _)| existing == &key)
                    {
                        envelope.fields.push((key, raw));
                    } else {
                        envelope.invalid_fields = true;
                    }
                }
                Ok(envelope)
            }
        }
        deserializer.deserialize_map(Fields)
    }
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
        assert!(
            encode_with_limit(
                &json!({"large":"x".repeat(MAX_MESSAGE_BYTES)}),
                MAX_MESSAGE_BYTES
            )
            .is_err()
        );
    }

    #[test]
    fn escaped_envelope_counts_exact_json_bytes_and_lf_is_outside_the_limit() {
        let id = RequestId::String("boundary".into());
        let base = Reply {
            jsonrpc: "2.0",
            id: Some(&id),
            body: ReplyBody::Result { result: json!("") },
        };
        let overhead = encode_with_limit(&base, MAX_MESSAGE_BYTES).unwrap().len() - 1;
        let remaining = MAX_MESSAGE_BYTES - overhead;
        let text = format!(
            "{}{}",
            "\0".repeat(remaining / 6),
            "x".repeat(remaining % 6)
        );
        let reply = Reply {
            jsonrpc: "2.0",
            id: Some(&id),
            body: ReplyBody::Result {
                result: json!(text),
            },
        };
        let frame = encode_with_limit(&reply, MAX_MESSAGE_BYTES).unwrap();
        assert_eq!(frame.len(), MAX_MESSAGE_BYTES + 1);
        assert_eq!(frame.last(), Some(&b'\n'));
        assert!(encode_with_limit(&reply, MAX_MESSAGE_BYTES - 1).is_err());
        let response: Value = serde_json::from_slice(&frame).unwrap();
        assert_eq!(response["id"], "boundary");
    }

    #[tokio::test]
    async fn oversized_error_fallback_retains_id_and_failure_never_creates_a_null_reply() {
        use tokio::io::AsyncReadExt;
        let id = RequestId::String("\0".repeat(256));
        let frame = reply_frame(
            Some(&id),
            ReplyBody::Error {
                error: json!({"code":-32603,"message":"x".repeat(MAX_MESSAGE_BYTES)}),
            },
            MAX_MESSAGE_BYTES,
        )
        .unwrap();
        assert!(frame.len() - 1 <= 1607);
        let response: Value = serde_json::from_slice(&frame).unwrap();
        assert_eq!(response["id"], "\0".repeat(256));
        assert_eq!(response["error"], RpcError::TOO_LARGE.value());
        // A smaller injectable encoding budget exercises the otherwise
        // unreachable second failure without any alternate identity or frame.
        assert!(
            reply_frame(
                Some(&id),
                ReplyBody::Result {
                    result: json!("large")
                },
                1
            )
            .is_err()
        );

        let (mut sender, receiver) = UnixStream::pair().unwrap();
        drop(receiver);
        assert!(
            write_response(
                &mut sender,
                Some(&id),
                Ok(json!("x".repeat(MAX_MESSAGE_BYTES))),
                None
            )
            .await
            .is_err()
        );

        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        assert!(write_value(&mut sender, &json!({"jsonrpc":"2.0","method":"test","params":{"text":"x".repeat(MAX_MESSAGE_BYTES)}})).await.is_err());
        drop(sender);
        let mut received = Vec::new();
        receiver.read_to_end(&mut received).await.unwrap();
        assert!(
            received.is_empty(),
            "an oversized notification must emit no invented response"
        );
    }
}
