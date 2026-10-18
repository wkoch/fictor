//! MCP stdio client, rmcp 3.5.1 (protocol 2026-07-28 compatibility).
//! https://docs.rs/rmcp/3.5.1/rmcp/
//! Tools are pinned using RFC 8785; annotations never authorize execution.
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
};

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
            audit.changed().await?;
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
                    let _ = audit.changed().await;
                    cancel.cancel();
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
        if !self.pinned || self.is_disabled() {
            return Err(GatewayError::Unavailable);
        }
        self.catalog.validate_arguments(name, &arguments)?;
        let args = arguments
            .as_object()
            .cloned()
            .ok_or(GatewayError::InvalidArguments)?;
        let request = ClientRequest::CallToolRequest(CallToolRequest::new(
            CallToolRequestParams::new(name.to_owned()).with_arguments(args),
        ));
        let handle = self
            .service
            .as_ref()
            .ok_or(GatewayError::Unavailable)?
            .peer()
            .send_cancellable_request(
                request,
                PeerRequestOptions::with_timeout(timeout.min(Duration::from_secs(600))),
            )
            .await?;
        let id = handle.id.clone();
        let result = tokio::select! {
            result=handle.await_response()=>result?,
            _=async {if !*cancelled.borrow(){let _=cancelled.changed().await;}}=>{
                let _=self.service.as_ref().ok_or(GatewayError::Unavailable)?.peer().notify_cancelled(CancelledNotificationParam::new(Some(id),Some("session cancelled".into()))).await;
                return Err(GatewayError::Cancelled);
            }
        };
        match result {
            ServerResult::CallToolResult(result) => Ok(result),
            _ => Err(GatewayError::Unavailable),
        }
    }
    pub async fn resources(&self) -> Result<Vec<Resource>, GatewayError> {
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
        let dir = tempfile::tempdir().unwrap();
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
                        "resources/list"=>json!({"resources":[]}),
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
