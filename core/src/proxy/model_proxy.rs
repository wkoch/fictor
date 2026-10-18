//! Core-owned model transport with durable admission and streaming capture (ADR-017).
use super::{Body, BoxError, ProxyError, ProxyIdentity, models};
use crate::{
    config::{Budget, Provider},
    secrets::SecretStore,
    store::{
        AppendEvent, Provenance, Store,
        blobs::{BlobError, Capture},
    },
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Request, Response, StatusCode,
    body::{Frame, Incoming},
};
use hyper_util::rt::TokioIo;
use rustls_platform_verifier::ConfigVerifierExt;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::{Semaphore, mpsc, oneshot, watch},
    task::JoinHandle,
};
const MAX_REQUEST: usize = 64 * 1024 * 1024;
// Body admission buffers at most 64 MiB, plus a transient blob-write copy.
// Bound simultaneous model calls independently from the streaming egress limit.
const MAX_MODEL_CALLS: usize = 4;
trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Transport for T {}
pub struct ModelProxy {
    store: Arc<Store>,
    providers: BTreeMap<String, Provider>,
    secrets: Arc<SecretStore>,
    budget: Budget,
    tls: Arc<rustls::ClientConfig>,
    closed: AtomicBool,
    stop: watch::Sender<bool>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    capacity: Arc<Semaphore>,
}
struct Call {
    provider: String,
    method: String,
    path: String,
    outcome: &'static str,
    error: Option<&'static str>,
    status: Option<u16>,
    req_blob: Option<String>,
    req_bytes: usize,
    resp_blob: Option<String>,
    resp_bytes: usize,
    ttfb_ms: Option<u64>,
    start: Instant,
    capture: Option<Capture>,
    output: Option<mpsc::Sender<Result<Frame<Bytes>, BoxError>>>,
    terminal: Option<Arc<Mutex<Option<BoxError>>>>,
}
impl Call {
    fn payload(&self) -> Value {
        json!({"provider":self.provider,"method":self.method,"path":self.path,"outcome":self.outcome,"error":self.error,"status":self.status,"req_blob":self.req_blob,"req_bytes":self.req_bytes,"resp_blob":self.resp_blob,"resp_bytes":self.resp_bytes,"resp_complete":self.outcome=="complete","duration_ms":self.start.elapsed().as_millis() as u64,"ttfb_ms":self.ttfb_ms})
    }
    fn reject(&mut self, status: StatusCode, error: &'static str) -> Response<Body> {
        self.outcome = "rejected";
        self.error = Some(error);
        self.status = Some(status.as_u16());
        json_response(status, json!({"error":error}))
    }
}
impl ModelProxy {
    pub fn new(
        store: Arc<Store>,
        providers: BTreeMap<String, Provider>,
        secrets: Arc<SecretStore>,
        budget: Budget,
    ) -> Result<Arc<Self>, ProxyError> {
        for provider in providers.values() {
            models::validate_provider(provider)
                .map_err(|_| ProxyError::Invalid("invalid model provider"))?;
        }
        // No insecure mode: rustls delegates certificate validation to the platform trust store.
        let tls = rustls::ClientConfig::with_platform_verifier()
            .map_err(|_| ProxyError::Invalid("system TLS verifier unavailable"))?;
        let (stop, _) = watch::channel(false);
        Ok(Arc::new(Self {
            store,
            providers,
            secrets,
            budget,
            tls: Arc::new(tls),
            closed: AtomicBool::new(false),
            stop,
            tasks: Mutex::new(vec![]),
            capacity: Arc::new(Semaphore::new(MAX_MODEL_CALLS)),
        }))
    }
    pub(super) async fn handle(
        self: Arc<Self>,
        request: Request<Incoming>,
        identity: ProxyIdentity,
        allowed: Vec<String>,
        mut revoked: watch::Receiver<bool>,
    ) -> Response<Body> {
        if self.closed.load(Ordering::Acquire) || *self.stop.borrow() {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"fictor_proxy_unavailable"}),
            );
        }
        let (reply, result) = oneshot::channel();
        let (client_state, mut client_gone) = watch::channel(false);
        let mut client_guard = ClientGuard {
            state: client_state.clone(),
            armed: true,
        };
        {
            let mut tasks = match self.tasks.lock() {
                Ok(tasks) => tasks,
                Err(_) => {
                    return json_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        json!({"error":"fictor_proxy_unavailable"}),
                    );
                }
            };
            tasks.retain(|task| !task.is_finished());
            if self.closed.load(Ordering::Acquire) || *self.stop.borrow() {
                return json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    json!({"error":"fictor_proxy_unavailable"}),
                );
            }
            let worker = self.clone();
            tasks.push(tokio::spawn(async move {
                let _client_keepalive = client_state;
                let uri_path = request
                    .uri()
                    .path_and_query()
                    .map_or("/", |p| p.as_str())
                    .to_owned();
                let route = uri_path.strip_prefix("/p/").and_then(|p| p.split_once('/'));
                let (provider, path) = route.map_or((String::new(), "/".into()), |(id, path)| {
                    (id.to_owned(), format!("/{path}"))
                });
                let mut call = Call {
                    provider,
                    method: request.method().as_str().into(),
                    path,
                    outcome: "client_cancelled",
                    error: None,
                    status: None,
                    req_blob: None,
                    req_bytes: 0,
                    resp_blob: None,
                    resp_bytes: 0,
                    ttfb_ms: None,
                    start: Instant::now(),
                    capture: None,
                    output: None,
                    terminal: None,
                };
                let mut reply = Some(reply);
                let mut stop = worker.stop.subscribe();
                // Cancellation drops transport work, while capture and audit remain owned here.
                let permit = worker.capacity.clone().try_acquire_owned();
                let response = if permit.is_err() { Some(call.reject(StatusCode::SERVICE_UNAVAILABLE, "fictor_proxy_unavailable")) } else { tokio::select! {
                    response=worker.run(request,&identity,&allowed,&mut call,&mut reply)=>response,
                    _=cancelled(&mut revoked)=>None,
                    _=cancelled(&mut stop)=>None,
                    _=cancelled(&mut client_gone)=>None,
                }};
                if let Some(capture) = call.capture.take() {
                    call.resp_bytes = capture.len();
                    match worker.store.finish_capture(capture).await {
                        Ok(hash) => call.resp_blob = Some(hash),
                        Err(_) => {
                            call.outcome = "capture_failed";
                            call.error = Some("fictor_capture_failed");
                        }
                    }
                }
                let refs = [call.req_blob.clone(), call.resp_blob.clone()]
                    .into_iter()
                    .flatten()
                    .collect();
                let event = AppendEvent {
                    session_id: identity.session_id.unwrap_or_else(|| "sys".into()),
                    parent_id: None,
                    kind: "model.call".into(),
                    actor: "core".into(),
                    payload: call.payload(),
                    blob_refs: refs,
                    provenance: Provenance::core(),
                };
                let audit_ok = worker.store.append(event).await.is_ok();
                if !audit_ok {
                    worker.closed.store(true, Ordering::Release);
                    worker.stop.send_replace(true);
                }
                // A clean downstream EOF requires both the capture and its audit commit.
                if audit_ok && call.outcome == "complete" && let Some(terminal) = &call.terminal && let Ok(mut error) = terminal.lock() {
                    *error = None;
                }
                drop(call.output.take());
                if let (Some(response), Some(reply)) = (response, reply) {
                    let _ = reply.send(response);
                }
            }));
        }
        let response = result.await.unwrap_or_else(|_| {
            json_response(
                StatusCode::BAD_GATEWAY,
                json!({"error":"fictor_upstream_error"}),
            )
        });
        client_guard.armed = false;
        response
    }
    async fn run(
        &self,
        request: Request<Incoming>,
        identity: &ProxyIdentity,
        allowed: &[String],
        call: &mut Call,
        reply: &mut Option<oneshot::Sender<Response<Body>>>,
    ) -> Option<Response<Body>> {
        let provider = match self
            .providers
            .get(&call.provider)
            .filter(|_| allowed.iter().any(|id| id == "*" || id == &call.provider))
        {
            Some(provider) => provider,
            None => return Some(call.reject(StatusCode::FORBIDDEN, "fictor_provider_not_allowed")),
        };
        let secret =
            match &provider.secret {
                Some(name) => {
                    let secrets = self.secrets.clone();
                    let name = name.clone();
                    match tokio::task::spawn_blocking(move || secrets.get(&name)).await {
                        Ok(Ok(secret)) => Some(secret),
                        _ => {
                            return Some(call.reject(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "fictor_secret_unavailable",
                            ));
                        }
                    }
                }
                None => None,
            };
        let (parts, mut incoming) = request.into_parts();
        let mut body = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_secs(600), incoming.frame()).await {
                Ok(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data() {
                        call.req_bytes = call.req_bytes.saturating_add(data.len());
                        if data.len() > MAX_REQUEST.saturating_sub(body.len()) {
                            return Some(call.reject(
                                StatusCode::PAYLOAD_TOO_LARGE,
                                "fictor_request_too_large",
                            ));
                        }
                        body.extend_from_slice(&data);
                    }
                }
                Ok(None) => break,
                _ => return Some(call.reject(StatusCode::BAD_REQUEST, "fictor_request_failed")),
            }
        }
        call.req_bytes = body.len();
        match self
            .store
            .reserve_model_budget(
                identity.session_id.clone(),
                self.budget.max_model_requests_per_day,
                self.budget.max_model_requests_per_session,
            )
            .await
        {
            Ok(Ok(())) => {}
            Ok(Err(exceeded)) => {
                call.outcome = "rejected";
                call.error = Some("fictor_budget_exceeded");
                call.status = Some(429);
                return Some(json_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    json!({"error":"fictor_budget_exceeded","scope":exceeded.scope,"limit":exceeded.limit}),
                ));
            }
            Err(_) => {
                return Some(call.reject(StatusCode::SERVICE_UNAVAILABLE, "fictor_capture_failed"));
            }
        }
        call.req_blob = match self.store.put_blob(body.clone()).await {
            Ok(hash) => Some(hash),
            Err(_) => {
                return Some(call.reject(StatusCode::SERVICE_UNAVAILABLE, "fictor_capture_failed"));
            }
        };
        let request = Request::from_parts(parts, Full::new(Bytes::from(body)));
        let mut request = match models::prepare(
            request,
            provider,
            &call.path,
            secret.as_ref().map(|s| s.expose()),
        ) {
            Ok(request) => request,
            Err(_) => return Some(call.reject(StatusCode::BAD_REQUEST, "fictor_invalid_request")),
        };
        call.capture = match self.store.begin_capture() {
            Ok(capture) => Some(capture),
            Err(_) => {
                return Some(call.reject(StatusCode::SERVICE_UNAVAILABLE, "fictor_capture_failed"));
            }
        };
        let destination = request.uri().clone();
        let connection = tokio::select! {
            _=reply_closed(reply)=>return None,
            result=tokio::time::timeout(Duration::from_secs(30),self.connect(&destination))=>result,
        };
        let stream = match connection {
            Ok(Ok(stream)) => stream,
            _ => {
                call.outcome = "upstream_error";
                call.error = Some(if connection.is_err() {
                    "connect_timeout"
                } else {
                    "connection_reset"
                });
                return Some(json_response(
                    StatusCode::BAD_GATEWAY,
                    json!({"error":"fictor_upstream_error"}),
                ));
            }
        };
        let (mut sender, driver) =
            match hyper::client::conn::http1::handshake(TokioIo::new(stream)).await {
                Ok(pair) => pair,
                Err(_) => {
                    call.outcome = "upstream_error";
                    call.error = Some("connection_reset");
                    return Some(json_response(
                        StatusCode::BAD_GATEWAY,
                        json!({"error":"fictor_upstream_error"}),
                    ));
                }
            };
        // One connection per call, killed on every cancellation or completed stream.
        let driver = AbortDriver(tokio::spawn(async move {
            let _ = driver.await;
        }));
        if let Some(path) = destination.path_and_query() {
            if let Ok(uri) = path.as_str().parse() {
                *request.uri_mut() = uri;
            } else {
                return Some(call.reject(StatusCode::BAD_REQUEST, "fictor_invalid_request"));
            }
        }
        let upstream = tokio::select! {_=reply_closed(reply)=>return None,result=tokio::time::timeout(Duration::from_secs(600),sender.send_request(request))=>result};
        let mut upstream = match upstream {
            Ok(Ok(response)) if response.status() != StatusCode::SWITCHING_PROTOCOLS => response,
            _ => {
                call.outcome = "upstream_error";
                call.error = Some(if upstream.is_err() {
                    "idle_timeout"
                } else {
                    "connection_reset"
                });
                return Some(json_response(
                    StatusCode::BAD_GATEWAY,
                    json!({"error":"fictor_upstream_error"}),
                ));
            }
        };
        call.status = Some(upstream.status().as_u16());
        models::strip_hop(upstream.headers_mut());
        // Force framing whose clean EOF can wait for durable capture/audit.
        upstream.headers_mut().remove("content-length");
        let (parts, mut incoming) = upstream.into_parts();
        if call.method == "HEAD"
            || matches!(parts.status.as_u16(), 204 | 304)
            || hyper::body::Body::is_end_stream(&incoming)
        {
            // Hyper discards downstream bodies for HEAD/204/304. Audit a normal
            // empty completion before returning headers, rather than interpreting
            // that body drop as a disconnected client.
            call.outcome = "complete";
            return Some(Response::from_parts(
                parts,
                Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            ));
        }
        let (output, receiver) = mpsc::channel(1);
        let terminal = Arc::new(Mutex::new(Some(
            std::io::Error::other("model stream interrupted").into(),
        )));
        call.output = Some(output.clone());
        call.terminal = Some(terminal.clone());
        if reply.take().is_none_or(|reply| {
            reply
                .send(Response::from_parts(
                    parts,
                    ChannelBody {
                        receiver,
                        terminal: terminal.clone(),
                    }
                    .boxed(),
                ))
                .is_err()
        }) {
            return None;
        }
        loop {
            let frame = tokio::select! {_=output.closed()=>{call.outcome="client_cancelled";break;},result=tokio::time::timeout(Duration::from_secs(600),incoming.frame())=>result};
            match frame {
                Ok(Some(Ok(frame))) => {
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    if call.ttfb_ms.is_none() {
                        call.ttfb_ms = Some(call.start.elapsed().as_millis() as u64);
                    }
                    let Some(capture) = call.capture.as_mut() else {
                        call.outcome = "capture_failed";
                        break;
                    };
                    // Every data frame is written before it can reach the extension.
                    if let Err(error) = capture.append(&data) {
                        call.outcome = if matches!(error, BlobError::TooLarge) {
                            "capture_limit"
                        } else {
                            "capture_failed"
                        };
                        break;
                    }
                    call.resp_bytes = capture.len();
                    if !matches!(
                        tokio::time::timeout(
                            Duration::from_secs(600),
                            output.send(Ok(Frame::data(data)))
                        )
                        .await,
                        Ok(Ok(()))
                    ) {
                        call.outcome = "client_cancelled";
                        break;
                    }
                }
                Ok(None) => {
                    call.outcome = "complete";
                    break;
                }
                _ => {
                    call.outcome = "upstream_error";
                    call.error = Some(if frame.is_err() {
                        "idle_timeout"
                    } else {
                        "connection_reset"
                    });
                    break;
                }
            }
        }
        drop(driver);
        None
    }
    async fn connect(&self, uri: &hyper::Uri) -> Result<Box<dyn Transport>, BoxError> {
        let host = uri
            .host()
            .ok_or("missing provider host")?
            .trim_start_matches('[')
            .trim_end_matches(']');
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("https") {
                443
            } else {
                80
            });
        let stream = TcpStream::connect((host, port)).await?;
        if uri.scheme_str() == Some("https") {
            let name = rustls::pki_types::ServerName::try_from(host.to_owned())?;
            Ok(Box::new(
                tokio_rustls::TlsConnector::from(self.tls.clone())
                    .connect(name, stream)
                    .await?,
            ))
        } else {
            Ok(Box::new(stream))
        }
    }
    pub async fn shutdown(&self) -> Result<(), ProxyError> {
        self.stop.send_replace(true);
        let tasks = std::mem::take(&mut *self.tasks.lock().map_err(|_| ProxyError::Closed)?);
        for task in tasks {
            task.await.map_err(|_| ProxyError::Task)?;
        }
        Ok(())
    }
}
struct ClientGuard {
    state: watch::Sender<bool>,
    armed: bool,
}
impl Drop for ClientGuard {
    fn drop(&mut self) {
        if self.armed {
            self.state.send_replace(true);
        }
    }
}
struct AbortDriver(JoinHandle<()>);
impl Drop for AbortDriver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct ChannelBody {
    receiver: mpsc::Receiver<Result<Frame<Bytes>, BoxError>>,
    terminal: Arc<Mutex<Option<BoxError>>>,
}
impl hyper::body::Body for ChannelBody {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match self.receiver.poll_recv(cx) {
            Poll::Ready(None) => match self.terminal.lock() {
                Ok(mut error) => Poll::Ready(error.take().map(Err)),
                Err(_) => Poll::Ready(Some(Err(
                    std::io::Error::other("capture unavailable").into()
                ))),
            },
            other => other,
        }
    }
}
fn json_response(status: StatusCode, value: Value) -> Response<Body> {
    let mut response = Response::new(
        Full::new(Bytes::from(value.to_string()))
            .map_err(|never| match never {})
            .boxed(),
    );
    *response.status_mut() = status;
    response.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("application/json"),
    );
    response
}
async fn cancelled(receiver: &mut watch::Receiver<bool>) {
    if !*receiver.borrow() {
        let _ = receiver.changed().await;
    }
}
async fn reply_closed(reply: &mut Option<oneshot::Sender<Response<Body>>>) {
    if let Some(reply) = reply {
        reply.closed().await;
    } else {
        std::future::pending::<()>().await;
    }
}
