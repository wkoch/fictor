//! HTTP/1 egress with a single DNS resolution followed by address validation.
//! Hyper's streaming bodies and copy_bidirectional provide bounded backpressure.
use super::{
    Body, ProxyError,
    allowlist::{Allowlist, AllowlistError, AuthorizedTarget, RequestKind},
    nat64::Nat64Prefixes,
};
use crate::store::{AppendEvent, Provenance, Store};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    header::{HeaderMap, HeaderName, HeaderValue},
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream, UnixListener},
    sync::watch,
    task::{JoinHandle, JoinSet},
};

const MAX_DENIAL_BUCKETS: usize = 4096;
const MAX_CONNECTIONS: usize = 1024;
trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Transport for T {}
type Stream = Box<dyn Transport>;

#[derive(Clone, Debug)]
pub struct ProxyIdentity {
    pub instance_id: String,
    pub ext_id: String,
    pub session_id: Option<String>,
}

/// Intentionally has no Debug/Display implementation: credentials must stay out of logs.
pub struct ProxyToken(String);
impl ProxyToken {
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn basic_header(&self) -> String {
        format!("Basic {}", STANDARD.encode(format!("fx:{}", self.0)))
    }
}
struct Registration {
    identity: ProxyIdentity,
    allowlist: Allowlist,
    models: Vec<String>,
    revoked: watch::Sender<bool>,
}
struct Denial {
    ext_id: String,
    host: String,
    port: u16,
    count: u64,
}
type Buckets = HashMap<(String, String, u16, u64), Denial>;
struct State {
    store: Arc<Store>,
    trusted: HashSet<String>,
    nat64: Nat64Prefixes,
    models: Mutex<Option<Arc<super::model_proxy::ModelProxy>>>,
    registrations: Mutex<HashMap<String, Arc<Registration>>>,
    denials: tokio::sync::Mutex<Buckets>,
    shutdown: watch::Sender<bool>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}
impl State {
    fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) -> Result<(), ProxyError> {
        let mut tasks = self.tasks.lock().map_err(|_| ProxyError::Closed)?;
        tasks.retain(|task| !task.is_finished());
        if tasks.len() >= MAX_CONNECTIONS {
            return Err(ProxyError::Invalid("active upstream capacity exhausted"));
        }
        tasks.push(tokio::spawn(future));
        Ok(())
    }
    fn authenticate(&self, headers: &HeaderMap) -> Option<Arc<Registration>> {
        let mut values = headers.get_all("proxy-authorization").iter();
        let value = values.next()?.to_str().ok()?;
        if values.next().is_some() {
            return None;
        }
        let (scheme, encoded) = value.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("Basic") {
            return None;
        }
        let decoded = STANDARD.decode(encoded).ok()?;
        let token = std::str::from_utf8(&decoded).ok()?.strip_prefix("fx:")?;
        let registrations = self.registrations.lock().ok()?;
        registrations
            .get(token)
            .filter(|entry| !*entry.revoked.borrow())
            .cloned()
    }
    async fn flush(&self, all: bool) -> Result<(), ProxyError> {
        let mut buckets = self.denials.lock().await;
        let current = minute()?;
        let keys: Vec<_> = buckets
            .keys()
            .filter(|key| all || key.3 != current)
            .cloned()
            .collect();
        for key in keys {
            if let Some(bucket) = buckets.get(&key) {
                let result = self.store.append(AppendEvent {
                    session_id: "sys".into(), parent_id: None, kind: "net.denied".into(), actor: "core".into(),
                    payload: serde_json::json!({"ext_id":bucket.ext_id,"host":bucket.host,"port":bucket.port,"count":bucket.count}),
                    blob_refs: vec![], provenance: Provenance::core(),
                }).await;
                if let Err(error) = result {
                    self.shutdown.send_replace(true);
                    return Err(error.into());
                }
            }
            buckets.remove(&key);
        }
        Ok(())
    }
    async fn deny(
        &self,
        identity: &ProxyIdentity,
        host: &str,
        port: u16,
    ) -> Result<(), ProxyError> {
        // Persistence belongs to the timer/shutdown tasks, which are awaited to
        // completion. Canceling an HTTP request must never interrupt an audit commit.
        let mut buckets = self.denials.lock().await;
        // Read the bucket minute while holding the ledger lock, so a delayed
        // request cannot recreate a minute already flushed by the timer.
        let key = (
            identity.instance_id.clone(),
            host.to_ascii_lowercase(),
            port,
            minute()?,
        );
        if *self.shutdown.borrow() {
            return Err(ProxyError::Closed);
        }
        // Keep one reserved overflow record, then close instead of dropping audit.
        // No later request can add another bucket after the shutdown flag is set.
        let exhausted = !buckets.contains_key(&key) && buckets.len() >= MAX_DENIAL_BUCKETS;
        let bucket = buckets.entry(key).or_insert_with(|| Denial {
            ext_id: identity.ext_id.clone(),
            host: host.to_ascii_lowercase(),
            port,
            count: 0,
        });
        bucket.count = bucket.count.saturating_add(1);
        if exhausted {
            self.shutdown.send_replace(true);
            return Err(ProxyError::Invalid("denial audit capacity exhausted"));
        }
        Ok(())
    }
    async fn taint(&self, identity: &ProxyIdentity, host: &str) -> Result<(), ProxyError> {
        if !self.trusted.contains(host)
            && let Some(session) = &identity.session_id
            && let Err(error) = self
                .store
                .taint_from_network(session.clone(), host.into())
                .await
        {
            self.shutdown.send_replace(true);
            return Err(error.into());
        }
        Ok(())
    }
}

pub struct EgressProxy {
    state: Arc<State>,
    listener: Option<JoinHandle<()>>,
    tcp: Option<SocketAddr>,
    unix: Option<UnixEndpoint>,
}
struct UnixEndpoint {
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl Drop for UnixEndpoint {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path)
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
enum Listener {
    Tcp(TcpListener),
    Unix(UnixListener),
}
impl Listener {
    async fn accept(&self) -> std::io::Result<Stream> {
        match self {
            Self::Tcp(listener) => Ok(Box::new(listener.accept().await?.0)),
            Self::Unix(listener) => Ok(Box::new(listener.accept().await?.0)),
        }
    }
}
impl EgressProxy {
    pub async fn bind_tcp(
        store: Arc<Store>,
        trusted_domains: Vec<String>,
    ) -> Result<Self, ProxyError> {
        Self::bind_tcp_with_nat64(store, trusted_domains, Nat64Prefixes::default()).await
    }
    pub async fn bind_tcp_with_nat64(
        store: Arc<Store>,
        trusted_domains: Vec<String>,
        nat64: Nat64Prefixes,
    ) -> Result<Self, ProxyError> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        Ok(Self::start(
            Listener::Tcp(listener),
            store,
            trusted_domains,
            Some(address),
            None,
            nat64,
        ))
    }
    pub async fn bind_unix(
        path: PathBuf,
        store: Arc<Store>,
        trusted_domains: Vec<String>,
    ) -> Result<Self, ProxyError> {
        Self::bind_unix_with_nat64(path, store, trusted_domains, Nat64Prefixes::default()).await
    }
    pub async fn bind_unix_with_nat64(
        path: PathBuf,
        store: Arc<Store>,
        trusted_domains: Vec<String>,
        nat64: Nat64Prefixes,
    ) -> Result<Self, ProxyError> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if !path.is_absolute() {
            return Err(ProxyError::Invalid("Unix socket path must be absolute"));
        }
        let parent = path
            .parent()
            .ok_or(ProxyError::Invalid("Unix socket has no parent"))?
            .canonicalize()?;
        if std::fs::metadata(&parent)?.permissions().mode() & 0o077 != 0 {
            return Err(ProxyError::Invalid("Unix socket parent must be private"));
        }
        let path = parent.join(
            path.file_name()
                .ok_or(ProxyError::Invalid("Unix socket has no filename"))?,
        );
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let metadata = std::fs::symlink_metadata(&path)?;
        let unix = UnixEndpoint {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        Ok(Self::start(
            Listener::Unix(listener),
            store,
            trusted_domains,
            None,
            Some(unix),
            nat64,
        ))
    }
    fn start(
        listener: Listener,
        store: Arc<Store>,
        trusted_domains: Vec<String>,
        tcp: Option<SocketAddr>,
        unix: Option<UnixEndpoint>,
        nat64: Nat64Prefixes,
    ) -> Self {
        let (shutdown, _) = watch::channel(false);
        let state = Arc::new(State {
            store,
            trusted: trusted_domains
                .into_iter()
                .map(|host| host.to_ascii_lowercase())
                .collect(),
            registrations: Mutex::new(HashMap::new()),
            nat64,
            models: Mutex::new(None),
            denials: tokio::sync::Mutex::new(HashMap::new()),
            shutdown,
            tasks: Mutex::new(vec![]),
        });
        let task_state = state.clone();
        let task = tokio::spawn(async move {
            accept_loop(listener, task_state).await;
        });
        Self {
            state,
            listener: Some(task),
            tcp,
            unix,
        }
    }
    pub fn tcp_addr(&self) -> Option<SocketAddr> {
        self.tcp
    }
    pub fn unix_path(&self) -> Option<&Path> {
        self.unix.as_ref().map(|endpoint| endpoint.path.as_path())
    }
    pub fn register(
        &self,
        identity: ProxyIdentity,
        patterns: &[String],
    ) -> Result<ProxyToken, ProxyError> {
        self.register_with_models(identity, patterns, &[])
    }
    pub fn set_model_proxy(
        &self,
        models: Arc<super::model_proxy::ModelProxy>,
    ) -> Result<(), ProxyError> {
        let mut slot = self.state.models.lock().map_err(|_| ProxyError::Closed)?;
        if slot.is_some() {
            return Err(ProxyError::Invalid("model proxy already configured"));
        }
        *slot = Some(models);
        Ok(())
    }
    pub fn register_with_models(
        &self,
        identity: ProxyIdentity,
        patterns: &[String],
        models: &[String],
    ) -> Result<ProxyToken, ProxyError> {
        if *self.state.shutdown.borrow() {
            return Err(ProxyError::Closed);
        }
        if identity.instance_id.is_empty() || identity.ext_id.is_empty() {
            return Err(ProxyError::Invalid("identity must be nonempty"));
        }
        let allowlist = Allowlist::new_with_nat64(patterns, &self.state.nat64)?;
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| ProxyError::Random)?;
        let token: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        let (revoked, _) = watch::channel(false);
        self.state
            .registrations
            .lock()
            .map_err(|_| ProxyError::Closed)?
            .insert(
                token.clone(),
                Arc::new(Registration {
                    identity,
                    allowlist,
                    models: models.to_vec(),
                    revoked,
                }),
            );
        Ok(ProxyToken(token))
    }
    pub fn revoke(&self, token: &ProxyToken) -> Result<(), ProxyError> {
        if let Some(registration) = self
            .state
            .registrations
            .lock()
            .map_err(|_| ProxyError::Closed)?
            .remove(token.expose())
        {
            registration.revoked.send_replace(true);
        }
        Ok(())
    }
    pub async fn shutdown(mut self) -> Result<(), ProxyError> {
        self.state.shutdown.send_replace(true);
        if let Some(task) = self.listener.take() {
            task.await.map_err(|_| ProxyError::Task)?;
        }
        let tasks =
            { std::mem::take(&mut *self.state.tasks.lock().map_err(|_| ProxyError::Closed)?) };
        for task in tasks {
            task.await.map_err(|_| ProxyError::Task)?;
        }
        let models = self
            .state
            .models
            .lock()
            .map_err(|_| ProxyError::Closed)?
            .clone();
        if let Some(models) = models {
            models.shutdown().await?;
        }
        self.state.flush(true).await
    }
}
impl Drop for EgressProxy {
    fn drop(&mut self) {
        self.state.shutdown.send_replace(true);
    }
}
async fn stopped(receiver: &mut watch::Receiver<bool>) {
    if *receiver.borrow() {
        return;
    }
    let _ = receiver.changed().await;
}
fn minute() -> Result<u64, ProxyError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProxyError::Invalid("system clock precedes epoch"))?
        .as_secs()
        / 60)
}
async fn accept_loop(listener: Listener, state: Arc<State>) {
    let mut shutdown = state.shutdown.subscribe();
    let mut connections = JoinSet::new();
    let mut timer = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = stopped(&mut shutdown) => break,
            accepted = listener.accept() => {
                let Ok(stream) = accepted else { state.shutdown.send_replace(true); break; };
                if connections.len() >= MAX_CONNECTIONS { continue; }
                let state = state.clone();
                connections.spawn(async move {
                    let mut shutdown = state.shutdown.subscribe();
                    let service_state = state.clone();
                    let service = service_fn(move |request| {
                        let state = service_state.clone();
                        async move { Ok::<_,Infallible>(handle(request,state).await) }
                    });
                    let connection = hyper::server::conn::http1::Builder::new().timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(10)).max_buf_size(32 * 1024).serve_connection(TokioIo::new(stream),service).with_upgrades();
                    tokio::pin!(connection);
                    tokio::select! { _ = &mut connection => {}, _ = stopped(&mut shutdown) => {} }
                });
            }
            _ = connections.join_next(), if !connections.is_empty() => {},
            _ = timer.tick() => { if state.flush(false).await.is_err() { state.shutdown.send_replace(true); break; } },
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}
fn response(status: StatusCode, text: &'static str) -> Response<Body> {
    let mut response = Response::new(
        Full::new(Bytes::from_static(text.as_bytes()))
            .map_err(|never| match never {})
            .boxed(),
    );
    *response.status_mut() = status;
    response
}
async fn handle(request: Request<Incoming>, state: Arc<State>) -> Response<Body> {
    if *state.shutdown.borrow() {
        return response(StatusCode::SERVICE_UNAVAILABLE, "proxy unavailable");
    }
    let Some(registration) = state.authenticate(request.headers()) else {
        let mut result = response(
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            "proxy authentication required",
        );
        result.headers_mut().insert(
            "proxy-authenticate",
            HeaderValue::from_static("Basic realm=\"fictor\""),
        );
        return result;
    };
    let connect = request.method() == Method::CONNECT;
    let authority = if connect {
        if request.uri().scheme().is_some() {
            return response(StatusCode::BAD_REQUEST, "invalid CONNECT authority");
        }
        request.uri().authority().cloned()
    } else {
        if request.uri().scheme_str() != Some("http") {
            return response(StatusCode::BAD_REQUEST, "absolute http URI required");
        }
        request.uri().authority().cloned()
    };
    let Some(authority) = authority else {
        return response(StatusCode::BAD_REQUEST, "destination authority required");
    };
    if authority.as_str().contains('@') {
        return response(StatusCode::BAD_REQUEST, "userinfo forbidden");
    }
    let host = authority.host();
    if host
        .trim_end_matches('.')
        .eq_ignore_ascii_case("models.fictor.internal")
    {
        let models = state.models.lock().ok().and_then(|models| models.clone());
        if models.is_some()
            && (connect
                || !matches!(
                    authority.as_str(),
                    "models.fictor.internal" | "models.fictor.internal:80"
                ))
        {
            return response(StatusCode::BAD_REQUEST, "invalid model proxy authority");
        }
        return match models {
            Some(models) => {
                models
                    .handle(
                        request,
                        registration.identity.clone(),
                        registration.models.clone(),
                        registration.revoked.subscribe(),
                    )
                    .await
            }
            None => response(StatusCode::SERVICE_UNAVAILABLE, "model proxy unavailable"),
        };
    }
    // http::Authority::port() also returns None for an invalid explicit port.
    // Compare the authority syntax to its host, so invalid ports never default to 80.
    let explicit_port = authority.as_str().len() != host.len();
    let port = match authority.port_u16() {
        Some(port) if port != 0 => port,
        None if !explicit_port && !connect => 80,
        _ => {
            return response(
                StatusCode::BAD_REQUEST,
                "invalid or missing destination port",
            );
        }
    };
    let kind = if connect {
        RequestKind::Connect
    } else {
        RequestKind::Http
    };
    let target = match registration.allowlist.authorize(host, port, kind) {
        Ok(target) => target,
        Err(AllowlistError::Denied) => {
            return deny(&state, &registration.identity, host, port).await;
        }
        Err(_) => return response(StatusCode::BAD_REQUEST, "invalid destination host"),
    };
    let mut revoked = registration.revoked.subscribe();
    let mut shutdown = state.shutdown.subscribe();
    tokio::select! {
        _ = stopped(&mut revoked) => response(StatusCode::PROXY_AUTHENTICATION_REQUIRED,"revoked proxy token"),
        _ = stopped(&mut shutdown) => response(StatusCode::SERVICE_UNAVAILABLE,"proxy unavailable"),
        result = forward(request,state.clone(),registration.clone(),target,connect) => result,
    }
}
async fn deny(state: &State, identity: &ProxyIdentity, host: &str, port: u16) -> Response<Body> {
    if state.deny(identity, host, port).await.is_err() {
        response(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable")
    } else {
        response(StatusCode::FORBIDDEN, "egress denied")
    }
}
async fn resolve(target: &AuthorizedTarget) -> std::io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = target.host().parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, target.port())]);
    }
    Ok(tokio::net::lookup_host((target.host(), target.port()))
        .await?
        .collect())
}
async fn forward(
    mut request: Request<Incoming>,
    state: Arc<State>,
    registration: Arc<Registration>,
    target: AuthorizedTarget,
    connect: bool,
) -> Response<Body> {
    let addresses = match tokio::time::timeout(Duration::from_secs(10), resolve(&target)).await {
        Ok(Ok(addresses)) => addresses,
        _ => return response(StatusCode::BAD_GATEWAY, "DNS resolution failed"),
    };
    if target
        .validate_resolved(&addresses.iter().map(SocketAddr::ip).collect::<Vec<_>>())
        .is_err()
    {
        return deny(&state, &registration.identity, target.host(), target.port()).await;
    }
    let stream = match tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(addresses.as_slice()),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        _ => return response(StatusCode::BAD_GATEWAY, "upstream connection failed"),
    };
    if state
        .taint(&registration.identity, target.host())
        .await
        .is_err()
    {
        return response(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable");
    }
    if connect {
        let upgrade = hyper::upgrade::on(&mut request);
        let mut revoked = registration.revoked.subscribe();
        let mut shutdown = state.shutdown.subscribe();
        if state.spawn(async move {
            let copy=async move {
                if let Ok(upgraded)=upgrade.await {
                    let mut client=TokioIo::new(upgraded);
                    let mut upstream=stream;
                    let _=tokio::io::copy_bidirectional(&mut client,&mut upstream).await;
                }
            };
            tokio::select! { _=copy=>{},_=stopped(&mut revoked)=>{},_=stopped(&mut shutdown)=>{} }
        }).is_err() { return response(StatusCode::SERVICE_UNAVAILABLE,"proxy unavailable"); }
        return response(StatusCode::OK, "");
    }
    let (mut sender, connection) =
        match hyper::client::conn::http1::handshake(TokioIo::new(stream)).await {
            Ok(parts) => parts,
            Err(_) => return response(StatusCode::BAD_GATEWAY, "upstream handshake failed"),
        };
    let mut revoked = registration.revoked.subscribe();
    let mut shutdown = state.shutdown.subscribe();
    if state.spawn(async move { tokio::select! { _=connection=>{},_=stopped(&mut revoked)=>{},_=stopped(&mut shutdown)=>{} } }).is_err() { return response(StatusCode::SERVICE_UNAVAILABLE,"proxy unavailable"); }
    strip_hop_headers(request.headers_mut());
    let host = if target.host().contains(':') {
        format!("[{}]:{}", target.host(), target.port())
    } else {
        format!("{}:{}", target.host(), target.port())
    };
    let Ok(host) = HeaderValue::from_str(&host) else {
        return response(StatusCode::BAD_REQUEST, "invalid Host");
    };
    request.headers_mut().insert("host", host);
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", |path| path.as_str());
    let Ok(uri) = path.parse() else {
        return response(StatusCode::BAD_REQUEST, "invalid request path");
    };
    *request.uri_mut() = uri;
    match sender.send_request(request).await {
        Ok(mut upstream) if upstream.status() != StatusCode::SWITCHING_PROTOCOLS => {
            strip_hop_headers(upstream.headers_mut());
            upstream.map(|body| {
                body.map_err(|error| -> super::BoxError { Box::new(error) })
                    .boxed()
            })
        }
        _ => response(StatusCode::BAD_GATEWAY, "upstream request failed"),
    }
}
fn strip_hop_headers(headers: &mut HeaderMap) {
    let nominated: Vec<HeaderName> = headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|value| HeaderName::from_bytes(value.trim().as_bytes()).ok())
        .collect();
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authorization",
        "proxy-authenticate",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

#[cfg(test)]
mod nat64_tests {
    use super::*;
    #[tokio::test]
    async fn configured_bind_applies_nat64_policy_when_registering_instances() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        crate::initialize(root.path()).await.unwrap();
        let store = Arc::new(Store::open(root.path()).await.unwrap());
        let prefixes = Nat64Prefixes::new(&["2001:4860:64::/96".into()]).unwrap();
        let proxy = EgressProxy::bind_tcp_with_nat64(store, vec![], prefixes)
            .await
            .unwrap();
        let identity = ProxyIdentity {
            instance_id: "nat64-test".into(),
            ext_id: "test".into(),
            session_id: None,
        };
        assert!(
            proxy
                .register(identity.clone(), &["[2001:4860:64::a00:1]:443".into()])
                .is_err()
        );
        assert!(proxy.register(identity, &["10.0.0.1:443".into()]).is_ok());
        proxy.shutdown().await.unwrap();
    }
}
