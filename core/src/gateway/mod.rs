//! MCP stdio client, rmcp 3.5.1 (protocol 2026-07-28 compatibility).
//! https://docs.rs/rmcp/3.5.1/rmcp/
//! Tools are pinned using RFC 8785; annotations never authorize execution.
pub(crate) mod admission;
pub mod registry;
mod transport;
use crate::store::{AppendEvent, Provenance, Store};
use rmcp::{
    ClientHandler, RoleClient, ServiceExt,
    model::*,
    service::{NotificationContext, PeerRequestOptions, RequestContext, RunningService},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::watch,
    task::JoinHandle,
    time::Instant,
};

const CANCEL_ATTEMPT_BUDGET: Duration = Duration::from_millis(100);

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("catálogo MCP inválido")]
    InvalidCatalog,
    #[error("definições de tools divergem do lock")]
    ToolsChanged,
    #[error("extensão MCP indisponível")]
    Unavailable,
    #[error("chamada MCP excedeu o prazo")]
    Timeout,
    #[error("chamada MCP cancelada")]
    Cancelled,
    #[error("argumentos da tool inválidos")]
    InvalidArguments,
    #[error("tool não encontrada")]
    NotFound,
    #[error("falha na auditoria MCP")]
    Audit,
}
impl From<rmcp::ServiceError> for GatewayError {
    fn from(error: rmcp::ServiceError) -> Self {
        match error {
            rmcp::ServiceError::Timeout { .. } => Self::Timeout,
            _ => Self::Unavailable,
        }
    }
}

/// Raw JSON fields retain their canonical representation independently of object order.
#[derive(Clone)]
pub struct PinnedCatalog {
    tools: Vec<Value>,
    hash: String,
}
impl PinnedCatalog {
    pub fn new(tools: Vec<Value>) -> Result<Self, GatewayError> {
        let tools = canonical_tools(&tools)?;
        for tool in &tools {
            let schema = tool
                .get("inputSchema")
                .ok_or(GatewayError::InvalidCatalog)?;
            jsonschema::options()
                .offline()
                .build(schema)
                .map_err(|_| GatewayError::InvalidCatalog)?;
        }
        let bytes =
            serde_json_canonicalizer::to_vec(&tools).map_err(|_| GatewayError::InvalidCatalog)?;
        let hash = format!(
            "sha256:{}",
            Sha256::digest(bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        Ok(Self { tools, hash })
    }
    pub fn hash(&self) -> &str {
        &self.hash
    }
    pub fn tools(&self) -> &[Value] {
        &self.tools
    }
    pub fn validate_arguments(&self, name: &str, arguments: &Value) -> Result<(), GatewayError> {
        let tool = self
            .tools
            .iter()
            .find(|tool| tool["name"].as_str() == Some(name))
            .ok_or(GatewayError::NotFound)?;
        let validator = jsonschema::options()
            .offline()
            .build(&tool["inputSchema"])
            .map_err(|_| GatewayError::InvalidCatalog)?;
        if !arguments.is_object() || !validator.is_valid(arguments) {
            return Err(GatewayError::InvalidArguments);
        }
        Ok(())
    }
}
fn canonical_tools(tools: &[Value]) -> Result<Vec<Value>, GatewayError> {
    let mut names = BTreeSet::new();
    let mut result = Vec::with_capacity(tools.len());
    for tool in tools {
        let name = tool
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or(GatewayError::InvalidCatalog)?;
        if !names.insert(name.to_owned()) || !tool.get("inputSchema").is_some_and(Value::is_object)
        {
            return Err(GatewayError::InvalidCatalog);
        }
        let mut fields = serde_json::Map::new();
        for key in [
            "name",
            "title",
            "description",
            "inputSchema",
            "outputSchema",
            "annotations",
            "_meta",
        ] {
            if let Some(value) = tool.get(key) {
                check_numbers(value)?;
                fields.insert(key.into(), value.clone());
            }
        }
        result.push(Value::Object(fields));
    }
    result.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(result)
}
fn check_numbers(value: &Value) -> Result<(), GatewayError> {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::Number(number) => {
                // JCS uses IEEE754. Reject integers it would round, avoiding pin collisions.
                if number
                    .as_i64()
                    .is_some_and(|n| !(-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&n))
                    || number.as_u64().is_some_and(|n| n > 9_007_199_254_740_991)
                {
                    return Err(GatewayError::InvalidCatalog);
                }
            }
            Value::Array(values) => pending.extend(values),
            Value::Object(values) => pending.extend(values.values()),
            _ => {}
        }
    }
    Ok(())
}

#[derive(Clone)]
pub struct AuditIdentity {
    pub store: Arc<Store>,
    pub ext_id: String,
    pub key: String,
    pub instance_id: String,
}
impl AuditIdentity {
    async fn changed(&self) -> Result<(), GatewayError> {
        self.store.append(AppendEvent{session_id:"sys".into(),parent_id:None,kind:"ext.tools_changed".into(),actor:"core".into(),payload:json!({"ext_id":self.ext_id,"key":self.key,"instance_id":self.instance_id}),blob_refs:vec![],provenance:Provenance::core()}).await.map_err(|_|GatewayError::Audit)?;
        Ok(())
    }
}
struct Client {
    root: Option<String>,
    changed: watch::Sender<u64>,
    generation: Arc<AtomicU64>,
    disabled: Arc<AtomicBool>,
    verification: Arc<Mutex<()>>,
}

/// A terminal catalog failure belongs to the process owner. The owner stops
/// the namespace and records the change while retaining its instance resources.
#[derive(Clone)]
pub(crate) struct CatalogInvalidation {
    invalidated: Arc<AtomicBool>,
    stop: watch::Sender<bool>,
    admission: admission::InstanceAdmission,
}
impl CatalogInvalidation {
    pub(crate) fn new(stop: watch::Sender<bool>) -> Self {
        Self {
            invalidated: Arc::new(AtomicBool::new(false)),
            admission: admission::InstanceAdmission::new(stop.clone()),
            stop,
        }
    }
    pub(crate) fn admission(&self) -> admission::InstanceAdmission {
        self.admission.clone()
    }
    pub(crate) fn is_invalidated(&self) -> bool {
        self.invalidated.load(Ordering::Acquire)
    }
    pub(crate) fn invalidate(&self) {
        self.invalidated.store(true, Ordering::Release);
        self.stop.send_replace(true);
    }
}
// The architect's phase-0 contract still requires roots, deprecated by SEP-2577.
#[allow(deprecated)]
impl ClientHandler for Client {
    fn get_info(&self) -> ClientConfig {
        let capabilities = if self.root.is_some() {
            {
                let mut capabilities = ClientCapabilities::default();
                capabilities.roots = Some(RootsCapabilities::default());
                capabilities
            }
        } else {
            ClientCapabilities::default()
        };
        ClientConfig::new(
            capabilities,
            Implementation::new("fictor", env!("CARGO_PKG_VERSION")),
        )
    }
    async fn list_roots(
        &self,
        _context: RequestContext<RoleClient>,
    ) -> Result<ListRootsResult, rmcp::ErrorData> {
        Ok(ListRootsResult::new(
            self.root.iter().map(|uri| Root::new(uri.clone())).collect(),
        ))
    }
    async fn on_tool_list_changed(&self, _context: NotificationContext<RoleClient>) {
        let Ok(_guard) = self.verification.lock() else {
            self.disabled.store(true, Ordering::Release);
            return;
        };
        self.disabled.store(true, Ordering::Release);
        let next = self
            .generation
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        self.changed.send_replace(next);
    }
}
pub struct McpConnection {
    service: Option<RunningService<RoleClient, Client>>,
    catalog: PinnedCatalog,
    pinned: bool,
    disabled: Arc<AtomicBool>,
    watcher: JoinHandle<()>,
    admission: Option<admission::InstanceAdmission>,
}
impl McpConnection {
    pub async fn connect<R, W>(
        reader: R,
        writer: W,
        workspace: Option<&Path>,
        pin: Option<PinnedCatalog>,
        audit: AuditIdentity,
    ) -> Result<Self, GatewayError>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        Self::connect_monitored(reader, writer, workspace, pin, audit, None).await
    }

    pub(crate) async fn connect_monitored<R, W>(
        reader: R,
        writer: W,
        workspace: Option<&Path>,
        pin: Option<PinnedCatalog>,
        audit: AuditIdentity,
        invalidation: Option<CatalogInvalidation>,
    ) -> Result<Self, GatewayError>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let root = workspace.map(root_uri).transpose()?;
        let (changed, mut changes) = watch::channel(0u64);
        let generation = Arc::new(AtomicU64::new(0));
        let disabled = Arc::new(AtomicBool::new(true));
        let verification = Arc::new(Mutex::new(()));
        let client = Client {
            root,
            changed,
            generation: generation.clone(),
            disabled: disabled.clone(),
            verification: verification.clone(),
        };
        let setup = async {
            let service = client
                .serve((transport::LimitedRead::new(reader), writer))
                .await
                .map_err(|_| GatewayError::Unavailable)?;
            let tools = enumerate(service.peer()).await?;
            let catalog = PinnedCatalog::new(tools)?;
            Ok::<_, GatewayError>((service, catalog))
        };
        let (service, catalog) = tokio::time::timeout(Duration::from_secs(15), setup)
            .await
            .map_err(|_| GatewayError::Timeout)??;
        if let Some(pin) = &pin
            && catalog.hash() != pin.hash()
        {
            if let Some(invalidation) = &invalidation {
                invalidation.invalidate();
            }
            service.cancellation_token().cancel();
            if invalidation.is_none() {
                audit.changed().await?;
            }
            return Err(GatewayError::ToolsChanged);
        }
        let pinned = pin.is_some();
        let catalog = pin.unwrap_or(catalog);
        let peer = service.peer().clone();
        let expected = catalog.hash.clone();
        let blocked = disabled.clone();
        let cancel = service.cancellation_token();
        // Even an identical notification suspends calls until verification finishes.
        {
            let _guard = verification.lock().map_err(|_| GatewayError::Unavailable)?;
            let initial = generation.load(Ordering::Acquire);
            disabled.store(initial != 0, Ordering::Release);
        }
        let admission = invalidation.as_ref().map(CatalogInvalidation::admission);
        let watcher = tokio::spawn(async move {
            loop {
                if *changes.borrow_and_update() == 0 && changes.changed().await.is_err() {
                    break;
                }
                let before = generation.load(Ordering::Acquire);
                let result = tokio::time::timeout(Duration::from_secs(15), enumerate(&peer)).await;
                let matches = match result {
                    Ok(Ok(tools)) => {
                        PinnedCatalog::new(tools).is_ok_and(|catalog| catalog.hash == expected)
                    }
                    _ => false,
                };
                if !matches {
                    blocked.store(true, Ordering::Release);
                    if let Some(invalidation) = &invalidation {
                        invalidation.invalidate();
                    }
                    cancel.cancel();
                    if invalidation.is_none() {
                        let _ = audit.changed().await;
                    }
                    break;
                }
                let stable = {
                    let Ok(_guard) = verification.lock() else {
                        blocked.store(true, Ordering::Release);
                        cancel.cancel();
                        break;
                    };
                    let stable = before == generation.load(Ordering::Acquire);
                    if stable {
                        blocked.store(false, Ordering::Release);
                    }
                    stable
                };
                if stable && changes.changed().await.is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            service: Some(service),
            catalog,
            pinned,
            disabled,
            watcher,
            admission,
        })
    }
    pub fn catalog(&self) -> &PinnedCatalog {
        &self.catalog
    }
    pub fn is_disabled(&self) -> bool {
        self.disabled.load(Ordering::Acquire)
            || self
                .service
                .as_ref()
                .is_none_or(|service| service.is_closed())
    }
    /// Transport primitive for the trusted gateway; policy/audit must precede this call.
    pub async fn call(
        &self,
        name: &str,
        arguments: Value,
        timeout: Duration,
        mut cancelled: watch::Receiver<bool>,
    ) -> Result<CallToolResult, GatewayError> {
        let deadline = Instant::now() + timeout.min(Duration::from_secs(600));
        if !self.pinned || self.is_disabled() {
            return Err(GatewayError::Unavailable);
        }
        let _call = self
            .admission
            .as_ref()
            .map(|admission| admission.admit())
            .transpose()?;
        // A cancelled session must not acquire a fresh external side effect.
        // Only requests already issued may receive notifications/cancelled.
        if *cancelled.borrow() || cancelled.has_changed().is_err() {
            return Err(GatewayError::Cancelled);
        }
        self.catalog.validate_arguments(name, &arguments)?;
        let args = arguments
            .as_object()
            .cloned()
            .ok_or(GatewayError::InvalidArguments)?;
        let request = ClientRequest::CallToolRequest(CallToolRequest::new(
            CallToolRequestParams::new(name.to_owned()).with_arguments(args),
        ));
        if Instant::now() >= deadline {
            return Err(GatewayError::Timeout);
        }
        let peer = self
            .service
            .as_ref()
            .ok_or(GatewayError::Unavailable)?
            .peer();
        // rmcp's response timer excludes queueing and waits indefinitely for a
        // cancellation write. Own the single deadline and cancellation instead.
        let handle = tokio::select! { biased;
            _ = call_cancelled(&mut cancelled) => return Err(GatewayError::Cancelled),
            _ = tokio::time::sleep_until(deadline) => return Err(GatewayError::Timeout),
            handle = peer.send_cancellable_request(request, PeerRequestOptions::no_options()) => handle?,
        };
        let id = handle.id.clone();
        let result = tokio::select! { biased;
            _ = call_cancelled(&mut cancelled) => Err(GatewayError::Cancelled),
            _ = tokio::time::sleep_until(deadline) => Err(GatewayError::Timeout),
            result = handle.await_response() => result.map_err(GatewayError::from),
        };
        let result = match result {
            Err(error @ (GatewayError::Cancelled | GatewayError::Timeout)) => {
                let reason = if matches!(error, GatewayError::Cancelled) {
                    "session cancelled"
                } else {
                    "request timeout"
                };
                cancel_before_deadline(peer, id, reason, deadline).await;
                return Err(error);
            }
            result => result?,
        };
        match result {
            ServerResult::CallToolResult(result) => Ok(result),
            _ => Err(GatewayError::Unavailable),
        }
    }
    pub async fn resources(&self) -> Result<Vec<Resource>, GatewayError> {
        let _call = self
            .admission
            .as_ref()
            .map(|admission| admission.admit())
            .transpose()?;
        let peer = self
            .service
            .as_ref()
            .ok_or(GatewayError::Unavailable)?
            .peer();
        tokio::time::timeout(Duration::from_secs(15), async {
            let mut cursor = None;
            let mut cursors = BTreeSet::new();
            let mut resources = Vec::new();
            let mut bytes = 0usize;
            let mut pages = 0usize;
            loop {
                let page = match peer
                    .send_request(ClientRequest::ListResourcesRequest(
                        ListResourcesRequest::with_param(
                            PaginatedRequestParams::default().with_cursor(cursor.clone()),
                        ),
                    ))
                    .await?
                {
                    ServerResult::ListResourcesResult(page) => page,
                    _ => return Err(GatewayError::InvalidCatalog),
                };
                pages += 1;
                bytes += serde_json::to_vec(&page)
                    .map_err(|_| GatewayError::InvalidCatalog)?
                    .len();
                if pages > 10000 || bytes > 16 * 1024 * 1024 {
                    return Err(GatewayError::InvalidCatalog);
                }
                for resource in page.resources {
                    if bytes > 16 * 1024 * 1024 || resources.len() >= 10000 {
                        return Err(GatewayError::InvalidCatalog);
                    }
                    resources.push(resource);
                }
                match page.next_cursor {
                    Some(next) => {
                        if !cursors.insert(next.clone()) {
                            return Err(GatewayError::InvalidCatalog);
                        }
                        cursor = Some(next);
                    }
                    None => break,
                }
            }
            Ok(resources)
        })
        .await
        .map_err(|_| GatewayError::Timeout)?
    }
    pub async fn shutdown(mut self) -> Result<(), GatewayError> {
        self.watcher.abort();
        if let Some(service) = self.service.take() {
            service
                .cancel()
                .await
                .map_err(|_| GatewayError::Unavailable)?;
        }
        Ok(())
    }
}

async fn call_cancelled(cancelled: &mut watch::Receiver<bool>) {
    loop {
        if *cancelled.borrow_and_update() {
            return;
        }
        if cancelled.changed().await.is_err() {
            return;
        }
    }
}

async fn cancel_before_deadline(
    peer: &rmcp::Peer<RoleClient>,
    id: RequestId,
    reason: &str,
    deadline: Instant,
) {
    let notification = peer.notify_cancelled(CancelledNotificationParam::new(
        Some(id),
        Some(reason.into()),
    ));
    tokio::pin!(notification);
    let now = Instant::now();
    if now >= deadline {
        // Best effort: poll exactly once to enqueue a known ID if space exists.
        // Delivery cannot be guaranteed under backpressure without extending
        // the tool's deadline; rmcp owns any notification already enqueued.
        std::future::poll_fn(|context| {
            let _ = notification.as_mut().poll(context);
            std::task::Poll::Ready(())
        })
        .await;
    } else {
        let until = deadline.min(now + CANCEL_ATTEMPT_BUDGET);
        let _ = tokio::time::timeout_at(until, notification).await;
    }
}
impl Drop for McpConnection {
    fn drop(&mut self) {
        self.watcher.abort();
    }
}
async fn enumerate(peer: &rmcp::Peer<RoleClient>) -> Result<Vec<Value>, GatewayError> {
    // Bound pagination, duplicate cursors and catalog size before building its hash.
    let mut cursor = None;
    let mut cursors = BTreeSet::new();
    let mut tools = vec![];
    let mut bytes = 0usize;
    let mut pages = 0usize;
    loop {
        // Bypass SDK response caches and stale fallback when checking a security pin.
        let params = cursor
            .clone()
            .map(|cursor| PaginatedRequestParams::default().with_cursor(Some(cursor)));
        let page = match peer
            .send_request(ClientRequest::ListToolsRequest(
                ListToolsRequest::with_param(params.unwrap_or_default()),
            ))
            .await?
        {
            ServerResult::ListToolsResult(page) => page,
            _ => return Err(GatewayError::InvalidCatalog),
        };
        pages += 1;
        bytes += serde_json::to_vec(&page)
            .map_err(|_| GatewayError::InvalidCatalog)?
            .len();
        if pages > 10000 || bytes > 16 * 1024 * 1024 {
            return Err(GatewayError::InvalidCatalog);
        }
        for tool in page.tools {
            let value = serde_json::to_value(tool).map_err(|_| GatewayError::InvalidCatalog)?;
            if bytes > 16 * 1024 * 1024 || tools.len() >= 10000 {
                return Err(GatewayError::InvalidCatalog);
            }
            tools.push(value);
        }
        match page.next_cursor {
            Some(next) => {
                if !cursors.insert(next.clone()) {
                    return Err(GatewayError::InvalidCatalog);
                }
                cursor = Some(next);
            }
            None => break,
        }
    }
    Ok(tools)
}
fn root_uri(path: &Path) -> Result<String, GatewayError> {
    if !path.is_absolute() {
        return Err(GatewayError::InvalidCatalog);
    }
    let path = path.to_str().ok_or(GatewayError::InvalidCatalog)?;
    let mut uri = "file://".to_owned();
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || b"/-._~".contains(&byte) {
            uri.push(byte as char);
        } else {
            uri.push_str(&format!("%{byte:02X}"));
        }
    }
    Ok(uri)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    fn tool(description: &str) -> Value {
        json!({"name":"echo","description":description,"inputSchema":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"],"additionalProperties":false}})
    }
    #[test]
    fn pins_use_canonical_json_selected_fields_and_reject_rounding_and_external_refs() {
        let first = PinnedCatalog::new(vec![tool("fixed")]).unwrap();
        let mut second = tool("fixed");
        second["icons"] = json!([{"src":"ignored"}]);
        assert_eq!(
            first.hash(),
            PinnedCatalog::new(vec![second]).unwrap().hash()
        );
        assert_ne!(
            first.hash(),
            PinnedCatalog::new(vec![tool("changed")]).unwrap().hash()
        );
        assert!(PinnedCatalog::new(vec![tool("fixed"), tool("fixed")]).is_err());
        let mut invalid = tool("fixed");
        invalid["inputSchema"] = json!({"$ref":"http://127.0.0.1:1/private"});
        assert!(PinnedCatalog::new(vec![invalid]).is_err());
        let mut invalid = tool("fixed");
        invalid["_meta"] = json!({"n":9007199254740993u64});
        assert!(PinnedCatalog::new(vec![invalid]).is_err());
        assert!(
            first
                .validate_arguments("echo", &json!({"text":"ok"}))
                .is_ok()
        );
        assert!(matches!(
            first.validate_arguments("echo", &json!({"text":1})),
            Err(GatewayError::InvalidArguments)
        ));
        assert_eq!(
            root_uri(Path::new("/workspace/a b#ç")).unwrap(),
            "file:///workspace/a%20b%23%C3%A7"
        );
    }
    async fn audit() -> (tempfile::TempDir, AuditIdentity) {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        crate::initialize(dir.path()).await.unwrap();
        let store = Arc::new(Store::open(dir.path()).await.unwrap());
        (
            dir,
            AuditIdentity {
                store,
                ext_id: "test".into(),
                key: "0.1.0-fixed".into(),
                instance_id: ulid::Ulid::generate().to_string(),
            },
        )
    }
    async fn mock_server(
        stream: tokio::io::DuplexStream,
        mut change: tokio::sync::mpsc::Receiver<()>,
        seen: tokio::sync::mpsc::Sender<Value>,
    ) {
        let (reader, mut writer) = tokio::io::split(stream);
        let mut lines = BufReader::new(reader).lines();
        let mut description = "fixed";
        loop {
            tokio::select! {
                line=lines.next_line()=>{
                    let Ok(Some(line))=line else{break;};let request:Value=serde_json::from_str(&line).unwrap();let method=request["method"].as_str().unwrap_or("");
                    if method=="notifications/cancelled" {let _=seen.send(request).await;continue;}
                    let Some(id)=request.get("id")else{continue;};
                    let result=match method{
                        "initialize"=>{let _=seen.send(request.clone()).await;json!({"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":true},"resources":{}},"serverInfo":{"name":"fake","version":"1"}})},
                        "tools/list"=>json!({"tools":[tool(description)]}),
                        "resources/list"=>{let _=seen.send(request.clone()).await;json!({"resources":[]})},
                        "tools/call"=>{
                            let _=seen.send(request.clone()).await;
                            if request["params"]["arguments"]["text"]=="wait"{continue;}
                            json!({"content":[{"type":"text","text":"ok"}],"isError":false})
                        },_=>json!({}),
                    };
                    writer.write_all(format!("{}\n",json!({"jsonrpc":"2.0","id":id,"result":result})).as_bytes()).await.unwrap();
                }
                Some(())=change.recv()=>{description="changed";writer.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n").await.unwrap();}
            }
        }
    }

    #[derive(Default)]
    struct WriteGate {
        blocked: AtomicBool,
        entered: tokio::sync::Notify,
        waker: Mutex<Option<std::task::Waker>>,
    }
    struct BlockedWrite(Arc<WriteGate>);
    impl Drop for BlockedWrite {
        fn drop(&mut self) {
            self.0.release();
        }
    }
    impl WriteGate {
        fn block(self: &Arc<Self>) -> BlockedWrite {
            self.blocked.store(true, Ordering::Release);
            BlockedWrite(self.clone())
        }
        fn release(&self) {
            let waker = {
                let mut waker = self.waker.lock().unwrap();
                self.blocked.store(false, Ordering::Release);
                waker.take()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }
        fn poll(&self, context: &std::task::Context<'_>) -> bool {
            let mut waker = self.waker.lock().unwrap();
            if self.blocked.load(Ordering::Acquire) {
                *waker = Some(context.waker().clone());
                self.entered.notify_one();
                true
            } else {
                false
            }
        }
    }
    struct GatedWrite<W> {
        inner: W,
        gate: Arc<WriteGate>,
    }
    impl<W: AsyncWrite + Unpin> AsyncWrite for GatedWrite<W> {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
            bytes: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if self.gate.poll(context) {
                return std::task::Poll::Pending;
            }
            std::pin::Pin::new(&mut self.inner).poll_write(context, bytes)
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.gate.poll(context) {
                return std::task::Poll::Pending;
            }
            std::pin::Pin::new(&mut self.inner).poll_flush(context)
        }
        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(context)
        }
    }
    struct BackpressureFixture {
        _root: tempfile::TempDir,
        connection: McpConnection,
        gate: Arc<WriteGate>,
        received: tokio::sync::mpsc::Receiver<Value>,
        server: JoinHandle<()>,
    }
    impl BackpressureFixture {
        async fn new() -> Self {
            let (root, audit) = audit().await;
            let (client, server) = tokio::io::duplex(65536);
            let (_change, changes) = tokio::sync::mpsc::channel(1);
            let (seen, mut received) = tokio::sync::mpsc::channel(2048);
            let server = tokio::spawn(mock_server(server, changes, seen));
            let (read, write) = tokio::io::split(client);
            let gate = Arc::new(WriteGate::default());
            let connection = McpConnection::connect(
                read,
                GatedWrite {
                    inner: write,
                    gate: gate.clone(),
                },
                None,
                Some(PinnedCatalog::new(vec![tool("fixed")]).unwrap()),
                audit,
            )
            .await
            .unwrap();
            assert_eq!(received.recv().await.unwrap()["method"], "initialize");
            Self {
                _root: root,
                connection,
                gate,
                received,
                server,
            }
        }
        async fn finish(mut self) {
            self.gate.release();
            self.connection.resources().await.unwrap();
            assert_eq!(
                self.received.recv().await.unwrap()["method"],
                "resources/list"
            );
            self.connection.shutdown().await.unwrap();
            self.server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn call_timeout_is_bounded_while_request_and_cancel_writes_are_blocked() {
        let mut fixture = BackpressureFixture::new().await;
        let _blocked = fixture.gate.block();
        let (_cancel, cancelled) = watch::channel(false);
        let mut call = Box::pin(fixture.connection.call(
            "echo",
            json!({"text":"wait"}),
            Duration::from_millis(20),
            cancelled,
        ));
        tokio::select! {
            result = &mut call => panic!("request did not reach the controlled writer: {result:?}"),
            _ = fixture.gate.entered.notified() => {}
        }
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), &mut call).await,
            Ok(Err(GatewayError::Timeout))
        ));
        fixture.gate.release();
        let request = fixture.received.recv().await.unwrap();
        assert_eq!(request["method"], "tools/call");
        let cancel = fixture.received.recv().await.unwrap();
        assert_eq!(cancel["method"], "notifications/cancelled");
        assert_eq!(cancel["params"]["requestId"], request["id"]);
        drop(call);
        fixture.finish().await;
    }

    #[tokio::test]
    async fn call_cancellation_is_bounded_while_the_cancel_write_is_blocked() {
        let mut fixture = BackpressureFixture::new().await;
        let (cancel, cancelled) = watch::channel(false);
        let mut call = Box::pin(fixture.connection.call(
            "echo",
            json!({"text":"wait"}),
            Duration::from_secs(5),
            cancelled,
        ));
        let request = tokio::select! {
            result = &mut call => panic!("call completed before dispatch: {result:?}"),
            request = fixture.received.recv() => request.unwrap()
        };
        assert_eq!(request["method"], "tools/call");
        let _blocked = fixture.gate.block();
        cancel.send(true).unwrap();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), &mut call).await,
            Ok(Err(GatewayError::Cancelled))
        ));
        fixture.gate.release();
        let notification = fixture.received.recv().await.unwrap();
        assert_eq!(notification["method"], "notifications/cancelled");
        assert_eq!(notification["params"]["requestId"], request["id"]);
        drop(call);
        fixture.finish().await;
    }

    #[tokio::test]
    async fn queue_backpressure_cannot_bypass_cancellation_or_an_expired_deadline() {
        let mut fixture = BackpressureFixture::new().await;
        let peer = fixture.connection.service.as_ref().unwrap().peer();
        // rmcp 3.5.1 has a 1024-entry peer queue. Do not yield/cooperate while
        // filling it, so the service cannot consume entries before the checks.
        let handles = tokio::task::unconstrained(async {
            let mut handles = Vec::new();
            for _ in 0..1024 {
                handles.push(
                    peer.send_cancellable_request(
                        ClientRequest::ListResourcesRequest(ListResourcesRequest::default()),
                        PeerRequestOptions::no_options(),
                    )
                    .await
                    .unwrap(),
                );
            }
            handles
        })
        .await;
        let (cancel, cancelled) = watch::channel(false);
        let mut call = Box::pin(tokio::task::unconstrained(fixture.connection.call(
            "echo",
            json!({"text":"wait"}),
            Duration::from_secs(5),
            cancelled,
        )));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(call.as_mut().poll(&mut context).is_pending());
        cancel.send(true).unwrap();
        assert!(matches!(
            call.as_mut().poll(&mut context),
            std::task::Poll::Ready(Err(GatewayError::Cancelled))
        ));
        drop(call);
        let (_cancel, cancelled) = watch::channel(false);
        let mut expired = Box::pin(tokio::task::unconstrained(fixture.connection.call(
            "echo",
            json!({"text":"wait"}),
            Duration::from_millis(20),
            cancelled,
        )));
        assert!(expired.as_mut().poll(&mut context).is_pending());
        // The call already passed preflight and is waiting for queue capacity.
        // Keep it unpolled until its positive deadline expires; a newly free
        // queue slot must not turn that expired request into a late dispatch.
        tokio::time::sleep_until(Instant::now() + Duration::from_millis(20)).await;
        assert!(matches!(
            expired.as_mut().poll(&mut context),
            std::task::Poll::Ready(Err(GatewayError::Timeout))
        ));
        drop(expired);
        fixture.connection.resources().await.unwrap();
        for _ in 0..1025 {
            assert_eq!(
                fixture.received.recv().await.unwrap()["method"],
                "resources/list"
            );
        }
        drop(handles);
        fixture.finish().await;
    }
    #[tokio::test]
    async fn mcp_pins_catalog_announces_only_roots_validates_and_disables_on_changes() {
        let (_root, audit) = audit().await;
        let store = audit.store.clone();
        let (client, server) = tokio::io::duplex(65536);
        let (change, changes) = tokio::sync::mpsc::channel(1);
        let (seen, mut received) = tokio::sync::mpsc::channel(8);
        let fake = tokio::spawn(mock_server(server, changes, seen));
        let (read, write) = tokio::io::split(client);
        let connection = McpConnection::connect(
            read,
            write,
            Some(Path::new("/workspace/a b")),
            Some(PinnedCatalog::new(vec![tool("fixed")]).unwrap()),
            audit,
        )
        .await
        .unwrap();
        let initialize = received.recv().await.unwrap();
        assert!(initialize["params"]["capabilities"].get("roots").is_some());
        assert!(
            initialize["params"]["capabilities"]
                .get("sampling")
                .is_none()
        );
        assert!(
            initialize["params"]["capabilities"]
                .get("elicitation")
                .is_none()
        );
        let (cancel, _) = watch::channel(false);
        assert!(matches!(
            connection
                .call(
                    "echo",
                    json!({"text":7}),
                    Duration::from_secs(2),
                    cancel.subscribe()
                )
                .await,
            Err(GatewayError::InvalidArguments)
        ));
        assert!(
            connection
                .call(
                    "echo",
                    json!({"text":"ok"}),
                    Duration::from_secs(2),
                    cancel.subscribe()
                )
                .await
                .is_ok()
        );
        assert_eq!(received.recv().await.unwrap()["method"], "tools/call");
        change.send(()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if connection.is_disabled() {
                    let events = store
                        .query_events(crate::store::EventQuery {
                            kinds: vec!["ext.tools_changed".into()],
                            ..Default::default()
                        })
                        .await
                        .unwrap();
                    if events.len() == 1 {
                        break;
                    }
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(matches!(
            connection
                .call(
                    "echo",
                    json!({"text":"ok"}),
                    Duration::from_secs(2),
                    cancel.subscribe()
                )
                .await,
            Err(GatewayError::Unavailable)
        ));
        connection.shutdown().await.unwrap();
        fake.await.unwrap();
    }
    #[tokio::test]
    async fn cancellation_prevents_dispatch_and_notifies_only_an_inflight_request() {
        let (_root, audit) = audit().await;
        let (client, server) = tokio::io::duplex(65536);
        let (_change, changes) = tokio::sync::mpsc::channel(1);
        let (seen, mut received) = tokio::sync::mpsc::channel(8);
        let fake = tokio::spawn(mock_server(server, changes, seen));
        let (read, write) = tokio::io::split(client);
        let connection = McpConnection::connect(
            read,
            write,
            None,
            Some(PinnedCatalog::new(vec![tool("fixed")]).unwrap()),
            audit,
        )
        .await
        .unwrap();
        assert_eq!(received.recv().await.unwrap()["method"], "initialize");
        for already_cancelled in [true, false] {
            let (cancel, cancelled) = watch::channel(already_cancelled);
            // A lost cancellation owner is also refused before dispatch.
            let _owner = already_cancelled.then_some(cancel);
            assert!(matches!(
                connection
                    .call(
                        "echo",
                        json!({"text":"wait"}),
                        Duration::from_secs(2),
                        cancelled
                    )
                    .await,
                Err(GatewayError::Cancelled)
            ));
            // The reply is an ordered barrier: no tool call or spurious cancel
            // notification may precede this later request at the server.
            connection.resources().await.unwrap();
            assert_eq!(received.recv().await.unwrap()["method"], "resources/list");
        }
        {
            let (cancel, cancelled) = watch::channel(false);
            let request = connection.call(
                "echo",
                json!({"text":"wait"}),
                Duration::from_secs(2),
                cancelled,
            );
            tokio::pin!(request);
            let sent = tokio::select! {
                result = &mut request => panic!("call completed before dispatch: {result:?}"),
                request = received.recv() => request.unwrap(),
            };
            assert_eq!(sent["method"], "tools/call");
            cancel.send(true).unwrap();
            assert!(matches!(request.await, Err(GatewayError::Cancelled)));
            let notification = received.recv().await.unwrap();
            assert_eq!(notification["method"], "notifications/cancelled");
            assert_eq!(notification["params"]["requestId"], sent["id"]);
        }
        connection.shutdown().await.unwrap();
        fake.await.unwrap();
    }

    #[tokio::test]
    async fn timeout_sends_mcp_cancelled_and_global_client_has_no_roots() {
        let (_root, audit) = audit().await;
        let (client, server) = tokio::io::duplex(65536);
        let (_change, changes) = tokio::sync::mpsc::channel(1);
        let (seen, mut received) = tokio::sync::mpsc::channel(8);
        let fake = tokio::spawn(mock_server(server, changes, seen));
        let (read, write) = tokio::io::split(client);
        let connection = McpConnection::connect(
            read,
            write,
            None,
            Some(PinnedCatalog::new(vec![tool("fixed")]).unwrap()),
            audit,
        )
        .await
        .unwrap();
        assert!(
            received.recv().await.unwrap()["params"]["capabilities"]
                .get("roots")
                .is_none()
        );
        let (cancel, _) = watch::channel(false);
        assert!(matches!(
            connection
                .call(
                    "echo",
                    json!({"text":"wait"}),
                    Duration::from_millis(30),
                    cancel.subscribe()
                )
                .await,
            Err(GatewayError::Timeout)
        ));
        assert_eq!(received.recv().await.unwrap()["method"], "tools/call");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), received.recv())
                .await
                .unwrap()
                .unwrap()["method"],
            "notifications/cancelled"
        );
        connection.shutdown().await.unwrap();
        fake.await.unwrap();
    }
}
