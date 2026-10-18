use fictor::{
    config::{Budget, Config, DEFAULT_CONFIG, Provider},
    proxy::{EgressProxy, ProxyIdentity, ProxyToken, model_proxy::ModelProxy},
    secrets::{BackendKind, SecretStore},
    store::{EventQuery, NewSession, Store, Trust},
};
use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
async fn fixture() -> (tempfile::TempDir, Arc<Store>, String) {
    let root = tempfile::tempdir().unwrap();
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let home = root.path().join("core");
    fictor::initialize(&home).await.unwrap();
    let store = Arc::new(Store::open(&home).await.unwrap());
    let session = store
        .create_session(NewSession {
            title: "models".into(),
            workspace,
            workspace_trust: Trust::Trusted,
            harness: "harness".into(),
            mode: fictor::config::Mode::Default,
            model: None,
        })
        .await
        .unwrap();
    (root, store, session.id)
}
fn identity(session: &str) -> ProxyIdentity {
    ProxyIdentity {
        instance_id: "instance".into(),
        ext_id: "harness".into(),
        session_id: Some(session.into()),
    }
}
async fn headers(stream: &mut TcpStream) -> String {
    let mut bytes = vec![];
    tokio::time::timeout(Duration::from_secs(5), async {
        while !bytes.ends_with(b"\r\n\r\n") {
            let mut b = [0];
            stream.read_exact(&mut b).await.unwrap();
            bytes.push(b[0]);
        }
    })
    .await
    .unwrap();
    String::from_utf8(bytes).unwrap()
}
#[derive(Default)]
struct ModelOptions {
    secret_required: bool,
    secret_available: bool,
    permissions: Vec<String>,
}

async fn setup(
    store: Arc<Store>,
    session: &str,
    home: &std::path::Path,
    url: String,
    limit: u64,
    secret: bool,
) -> (EgressProxy, ProxyToken) {
    setup_options(
        store,
        session,
        home,
        url,
        limit,
        ModelOptions {
            secret_required: secret,
            secret_available: secret,
            permissions: vec!["fake".into()],
        },
    )
    .await
}

async fn setup_options(
    store: Arc<Store>,
    session: &str,
    _home: &std::path::Path,
    url: String,
    limit: u64,
    options: ModelOptions,
) -> (EgressProxy, ProxyToken) {
    let secrets = Arc::new(
        SecretStore::open_with_lease(store.owner().clone(), BackendKind::File, Default::default())
            .unwrap(),
    );
    if options.secret_available {
        secrets.set("test_key", "fake-core-key").unwrap();
    }
    let provider = Provider {
        base_url: url,
        auth_header: Some("x-api-key".into()),
        auth_prefix: None,
        secret: options.secret_required.then(|| "test_key".into()),
        extra_headers: BTreeMap::new(),
    };
    let model = ModelProxy::new(
        store.clone(),
        BTreeMap::from([("fake".into(), provider)]),
        secrets,
        Budget {
            max_model_requests_per_day: limit,
            max_model_requests_per_session: 100,
        },
    )
    .unwrap();
    let proxy = EgressProxy::bind_tcp(store, vec![]).await.unwrap();
    proxy.set_model_proxy(model).unwrap();
    let token = proxy
        .register_with_models(identity(session), &[], &options.permissions)
        .unwrap();
    (proxy, token)
}
async fn call(address: SocketAddr, token: &ProxyToken) -> String {
    let mut client = connect(address, token).await;
    let mut result = String::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_string(&mut result))
        .await
        .unwrap()
        .unwrap();
    result
}
async fn connect(address: SocketAddr, token: &ProxyToken) -> TcpStream {
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(format!("POST http://models.fictor.internal/p/fake/v1/messages HTTP/1.1\r\nHost: ignored\r\nProxy-Authorization: {}\r\nAuthorization: attacker\r\nX-Api-Key: attacker\r\nContent-Length: 7\r\nConnection: close\r\n\r\nopaque!",token.basic_header()).as_bytes()).await.unwrap();
    client
}
async fn events(store: &Store, session: &str) -> Vec<fictor::store::Event> {
    store
        .query_events(EventQuery {
            session_id: Some(session.into()),
            kinds: vec!["model.call".into()],
            ..Default::default()
        })
        .await
        .unwrap()
}
#[test]
fn cleartext_providers_are_validated_at_config_load() {
    for host in [
        "localhost",
        "127.0.0.2",
        "127.1.2.3",
        "192.168.1.2",
        "example.com",
        "[::ffff:127.0.0.1]",
    ] {
        assert!(
            Config::parse(
                &DEFAULT_CONFIG.replace("http://127.0.0.1:11434", &format!("http://{host}:11434"))
            )
            .is_err(),
            "{host}"
        );
    }
    assert!(
        Config::parse(&DEFAULT_CONFIG.replace("http://127.0.0.1:11434", "http://[::1]:11434"))
            .is_ok()
    );
}
#[tokio::test]
async fn streams_opaque_bytes_and_injects_only_core_credentials() {
    let (root, store, session) = fixture().await;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        let request = headers(&mut client).await;
        assert!(request.starts_with("POST /v1/messages "));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("x-api-key: fake-core-key")
        );
        assert!(!request.contains("attacker"));
        assert!(!request.to_ascii_lowercase().contains("proxy-authorization"));
        let mut body = [0; 7];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"opaque!");
        client
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nfirst\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        client.write_all(b"6\r\nsecond\r\n0\r\n\r\n").await.unwrap();
    });
    let (proxy, token) = setup(
        store.clone(),
        &session,
        &root.path().join("core"),
        format!("http://{address}"),
        20,
        true,
    )
    .await;
    let response = call(proxy.tcp_addr().unwrap(), &token).await;
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains("first"));
    assert!(response.contains("second"));
    assert!(!response.contains("fake-core-key"));
    upstream.await.unwrap();
    proxy.shutdown().await.unwrap();
    let calls = events(&store, &session).await;
    assert_eq!(calls.len(), 1);
    let payload = &calls[0].payload;
    assert_eq!(payload["outcome"], "complete");
    assert_eq!(payload["resp_complete"], true);
    assert_eq!(
        store
            .get_blob(payload["req_blob"].as_str().unwrap().into())
            .await
            .unwrap(),
        b"opaque!"
    );
    assert_eq!(
        store
            .get_blob(payload["resp_blob"].as_str().unwrap().into())
            .await
            .unwrap(),
        b"firstsecond"
    );
    assert!(!store.session(session).await.unwrap().flags.untrusted);
}
#[tokio::test]
async fn provider_reset_keeps_partial_capture_and_failure_outcome() {
    let (root, store, session) = fixture().await;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        headers(&mut client).await;
        let mut body = [0; 7];
        client.read_exact(&mut body).await.unwrap();
        client
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
    });
    let (proxy, token) = setup(
        store.clone(),
        &session,
        &root.path().join("core"),
        format!("http://{address}"),
        20,
        false,
    )
    .await;
    let mut client = connect(proxy.tcp_addr().unwrap(), &token).await;
    let mut response = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), client.read_to_string(&mut response))
        .await
        .unwrap();
    upstream.await.unwrap();
    proxy.shutdown().await.unwrap();
    let calls = events(&store, &session).await;
    assert_eq!(calls.len(), 1);
    let payload = &calls[0].payload;
    assert_eq!(payload["outcome"], "upstream_error");
    assert_eq!(payload["resp_complete"], false);
    assert_eq!(
        store
            .get_blob(payload["resp_blob"].as_str().unwrap().into())
            .await
            .unwrap(),
        b"partial"
    );
}
#[tokio::test]
async fn cancelling_client_closes_provider_and_records_partial_blob() {
    let (root, store, session) = fixture().await;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        headers(&mut client).await;
        let mut body = [0; 7];
        client.read_exact(&mut body).await.unwrap();
        client
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\npartial\r\n")
            .await
            .unwrap();
        let mut b = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), client.read(&mut b))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    });
    let (proxy, token) = setup(
        store.clone(),
        &session,
        &root.path().join("core"),
        format!("http://{address}"),
        20,
        false,
    )
    .await;
    let mut client = connect(proxy.tcp_addr().unwrap(), &token).await;
    assert!(headers(&mut client).await.contains("200"));
    let mut part = [0; 10];
    client.read_exact(&mut part).await.unwrap();
    drop(client);
    upstream.await.unwrap();
    proxy.shutdown().await.unwrap();
    let calls = events(&store, &session).await;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].payload["outcome"], "client_cancelled");
    assert_eq!(calls[0].payload["resp_complete"], false);
    assert_eq!(
        store
            .get_blob(calls[0].payload["resp_blob"].as_str().unwrap().into())
            .await
            .unwrap(),
        b"partial"
    );
}
#[tokio::test]
async fn admitted_failures_consume_budget_after_restart() {
    let (root, store, session) = fixture().await;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let (proxy, token) = setup(
        store.clone(),
        &session,
        &root.path().join("core"),
        format!("http://{address}"),
        2,
        false,
    )
    .await;
    for _ in 0..2 {
        assert!(
            call(proxy.tcp_addr().unwrap(), &token)
                .await
                .starts_with("HTTP/1.1 502")
        );
    }
    proxy.shutdown().await.unwrap();
    let calls = events(&store, &session).await;
    assert_eq!(calls.len(), 2);
    Arc::try_unwrap(store)
        .ok()
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    let store = Arc::new(Store::open(&root.path().join("core")).await.unwrap());
    let (proxy, token) = setup(
        store.clone(),
        &session,
        &root.path().join("core"),
        format!("http://{address}"),
        2,
        false,
    )
    .await;
    let response = call(proxy.tcp_addr().unwrap(), &token).await;
    assert!(response.starts_with("HTTP/1.1 429"));
    assert!(response.contains("fictor_budget_exceeded"));
    proxy.shutdown().await.unwrap();
    let calls = events(&store, &session).await;
    assert_eq!(calls.len(), 3);
    let rejected = calls
        .iter()
        .find(|event| event.payload["outcome"] == "rejected")
        .unwrap();
    assert_eq!(rejected.payload["error"], "fictor_budget_exceeded");
    assert_eq!(rejected.payload["req_blob"], serde_json::Value::Null);
}

async fn streaming_call(
    address: SocketAddr,
    token: &ProxyToken,
) -> (
    hyper::Response<hyper::body::Incoming>,
    hyper::client::conn::http1::SendRequest<http_body_util::Full<bytes::Bytes>>,
    tokio::task::JoinHandle<()>,
) {
    let stream = TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = hyper::Request::builder()
        .method("POST")
        .uri("http://models.fictor.internal/p/fake/v1/messages")
        .header("Host", "models.fictor.internal")
        .header("Proxy-Authorization", token.basic_header())
        .header("Connection", "close")
        .body(http_body_util::Full::new(bytes::Bytes::from_static(
            b"opaque!",
        )))
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), sender.send_request(request))
        .await
        .unwrap()
        .unwrap();
    (response, sender, driver)
}

fn admitted_count(home: &std::path::Path) -> i64 {
    rusqlite::Connection::open_with_flags(
        home.join("fictor.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap()
    .query_row(
        "SELECT COALESCE(SUM(count),0) FROM budget_usage WHERE scope='day'",
        [],
        |row| row.get(0),
    )
    .unwrap()
}
async fn assert_no_provider_connection(listener: &TcpListener) {
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "unadmitted request reached provider"
    );
}
async fn request_path(address: SocketAddr, token: &ProxyToken, provider: &str) -> String {
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(format!("POST http://models.fictor.internal/p/{provider}/v1/messages HTTP/1.1\r\nHost: ignored\r\nProxy-Authorization: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",token.basic_header()).as_bytes()).await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}
fn assert_rejected_without_capture(event: &fictor::store::Event, error: &str, status: u16) {
    assert_eq!(event.payload["outcome"], "rejected");
    assert_eq!(event.payload["error"], error);
    assert_eq!(event.payload["status"], status);
    assert_eq!(event.payload["req_blob"], serde_json::Value::Null);
    assert_eq!(event.payload["resp_blob"], serde_json::Value::Null);
    assert_eq!(event.payload["resp_complete"], false);
    assert!(event.blob_refs.is_empty());
}

#[tokio::test]
async fn forbidden_and_unknown_providers_are_audited_without_admission_or_upstream_io() {
    let (root, store, session) = fixture().await;
    let home = root.path().join("core");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (proxy, token) = setup_options(
        store.clone(),
        &session,
        &home,
        format!("http://{}", listener.local_addr().unwrap()),
        20,
        ModelOptions {
            secret_required: true,
            secret_available: false,
            permissions: vec![],
        },
    )
    .await;
    let forbidden = call(proxy.tcp_addr().unwrap(), &token).await;
    assert!(forbidden.starts_with("HTTP/1.1 403"));
    assert!(forbidden.contains("fictor_provider_not_allowed"));
    let allowed = proxy
        .register_with_models(
            ProxyIdentity {
                instance_id: "unknown-provider".into(),
                ..identity(&session)
            },
            &[],
            &["fake".into()],
        )
        .unwrap();
    let unknown = request_path(proxy.tcp_addr().unwrap(), &allowed, "unknown").await;
    assert!(unknown.starts_with("HTTP/1.1 403"));
    proxy.shutdown().await.unwrap();
    assert_eq!(admitted_count(&home), 0);
    assert_no_provider_connection(&listener).await;
    let calls = events(&store, &session).await;
    assert_eq!(calls.len(), 2);
    for event in &calls {
        assert_rejected_without_capture(event, "fictor_provider_not_allowed", 403);
    }
}

#[tokio::test]
async fn missing_secret_in_empty_file_is_503_audited_before_budget_and_capture() {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let (root, store, session) = fixture().await;
    let home = root.path().join("core");
    let mut secrets = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(home.join("secrets.toml"))
        .unwrap();
    secrets.write_all(b"schema = 1\n[secrets]\n").unwrap();
    drop(secrets);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (proxy, token) = setup_options(
        store.clone(),
        &session,
        &home,
        format!("http://{}", listener.local_addr().unwrap()),
        20,
        ModelOptions {
            secret_required: true,
            secret_available: false,
            permissions: vec!["fake".into()],
        },
    )
    .await;
    let response = call(proxy.tcp_addr().unwrap(), &token).await;
    assert!(response.starts_with("HTTP/1.1 503"));
    assert!(response.contains("fictor_secret_unavailable"));
    proxy.shutdown().await.unwrap();
    assert_eq!(admitted_count(&home), 0);
    assert_no_provider_connection(&listener).await;
    let calls = events(&store, &session).await;
    assert_eq!(calls.len(), 1);
    assert_rejected_without_capture(&calls[0], "fictor_secret_unavailable", 503);
}

#[tokio::test]
async fn request_over_64_mib_is_413_without_budget_capture_or_provider_connection() {
    let (root, store, session) = fixture().await;
    let home = root.path().join("core");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (proxy, token) = setup(
        store.clone(),
        &session,
        &home,
        format!("http://{}", listener.local_addr().unwrap()),
        20,
        false,
    )
    .await;
    let mut client = TcpStream::connect(proxy.tcp_addr().unwrap()).await.unwrap();
    let length = 64 * 1024 * 1024 + 1;
    let response=tokio::time::timeout(Duration::from_secs(30),async {
        client.write_all(format!("POST http://models.fictor.internal/p/fake/v1/messages HTTP/1.1\r\nHost: ignored\r\nProxy-Authorization: {}\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n",token.basic_header()).as_bytes()).await.unwrap();
        let chunk=vec![b'x';1024*1024];
        for _ in 0..64 {client.write_all(&chunk).await.unwrap();}
        client.write_all(b"x").await.unwrap();
        let mut response=String::new();
        client.read_to_string(&mut response).await.unwrap();
        response
    }).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 413"));
    assert!(response.contains("fictor_request_too_large"));
    proxy.shutdown().await.unwrap();
    assert_eq!(admitted_count(&home), 0);
    assert_no_provider_connection(&listener).await;
    let calls = events(&store, &session).await;
    assert_eq!(calls.len(), 1);
    assert_rejected_without_capture(&calls[0], "fictor_request_too_large", 413);
    assert_eq!(calls[0].payload["req_bytes"], 64 * 1024 * 1024 + 1);
}

/// Restores fixture data even if a fault-injection assertion panics.
struct BlockBlobRoot {
    path: std::path::PathBuf,
    backup: std::path::PathBuf,
    active: bool,
}
impl BlockBlobRoot {
    fn install(home: &std::path::Path) -> Self {
        let path = home.join("blobs");
        let backup = home.join("blobs.fault-backup");
        std::fs::rename(&path, &backup).unwrap();
        let guard = Self {
            path,
            backup,
            active: true,
        };
        std::fs::write(&guard.path, b"injected file where blob directory belongs").unwrap();
        guard
    }
    fn restore(mut self) {
        std::fs::remove_file(&self.path).unwrap();
        std::fs::rename(&self.backup, &self.path).unwrap();
        self.active = false;
    }
}
impl Drop for BlockBlobRoot {
    fn drop(&mut self) {
        if self.active {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::rename(&self.backup, &self.path);
        }
    }
}
#[tokio::test]
async fn request_blob_write_failure_is_audited_and_consumes_admission_without_upstream_io() {
    let (root, store, session) = fixture().await;
    let home = root.path().join("core");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (proxy, token) = setup(
        store.clone(),
        &session,
        &home,
        format!("http://{}", listener.local_addr().unwrap()),
        20,
        false,
    )
    .await;
    let fault = BlockBlobRoot::install(&home);
    let response = call(proxy.tcp_addr().unwrap(), &token).await;
    fault.restore();
    assert!(response.starts_with("HTTP/1.1 503"));
    assert!(response.contains("fictor_capture_failed"));
    proxy.shutdown().await.unwrap();
    assert_eq!(
        admitted_count(&home),
        1,
        "an admitted capture failure must not refund budget"
    );
    assert_no_provider_connection(&listener).await;
    let calls = events(&store, &session).await;
    assert_eq!(calls.len(), 1);
    assert_rejected_without_capture(&calls[0], "fictor_capture_failed", 503);
    assert_eq!(calls[0].payload["req_bytes"], 7);
}

#[tokio::test]
async fn missing_capture_temporary_is_audited_as_capture_failed_with_request_preserved() {
    let (root, store, session) = fixture().await;
    let home = root.path().join("core");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let blobs = home.join("blobs");
    let upstream = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        headers(&mut client).await;
        let mut request = [0; 7];
        client.read_exact(&mut request).await.unwrap();
        let captures: Vec<_> = std::fs::read_dir(blobs)
            .unwrap()
            .map(Result::unwrap)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".model-capture-")
            })
            .collect();
        assert_eq!(captures.len(), 1);
        std::fs::remove_file(captures[0].path()).unwrap();
        client
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npartial")
            .await
            .unwrap();
    });
    let (proxy, token) = setup(
        store.clone(),
        &session,
        &home,
        format!("http://{address}"),
        20,
        false,
    )
    .await;
    use http_body_util::BodyExt;
    let (mut response, sender, driver) = streaming_call(proxy.tcp_addr().unwrap(), &token).await;
    assert_eq!(response.status(), hyper::StatusCode::OK);
    let failed = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(frame) = response.body_mut().frame().await {
            if frame.is_err() {
                return true;
            }
        }
        false
    })
    .await
    .unwrap();
    assert!(
        failed,
        "capture finalization failure was exposed as a clean response EOF"
    );
    drop(response);
    drop(sender);
    driver.await.unwrap();
    upstream.await.unwrap();
    proxy.shutdown().await.unwrap();
    let calls = events(&store, &session).await;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].payload["outcome"], "capture_failed");
    assert_eq!(calls[0].payload["error"], "fictor_capture_failed");
    assert_eq!(calls[0].payload["resp_complete"], false);
    assert_eq!(calls[0].payload["resp_blob"], serde_json::Value::Null);
    assert_eq!(calls[0].payload["resp_bytes"], 7);
    assert_eq!(
        store
            .get_blob(calls[0].payload["req_blob"].as_str().unwrap().into())
            .await
            .unwrap(),
        b"opaque!"
    );
    assert_eq!(admitted_count(&home), 1);
}

#[tokio::test]
async fn response_over_256_mib_closes_stream_and_persists_only_the_captured_prefix() {
    use std::io::{Read, Seek, SeekFrom};
    const MIB: usize = 1024 * 1024;
    const LIMIT: usize = 256 * MIB;
    let (root, store, session) = fixture().await;
    let home = root.path().join("core");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        headers(&mut client).await;
        let mut request = [0; 7];
        client.read_exact(&mut request).await.unwrap();
        client
            .write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", LIMIT + MIB).as_bytes(),
            )
            .await
            .unwrap();
        let chunk = vec![b'x'; MIB];
        for _ in 0..257 {
            if client.write_all(&chunk).await.is_err() {
                return;
            }
        }
        let mut byte = [0];
        let closed = tokio::time::timeout(Duration::from_secs(60), client.read(&mut byte))
            .await
            .unwrap();
        assert!(
            matches!(closed, Ok(0) | Err(_)),
            "provider connection remained open after capture limit"
        );
    });
    let (proxy, token) = setup(
        store.clone(),
        &session,
        &home,
        format!("http://{address}"),
        20,
        false,
    )
    .await;
    use http_body_util::BodyExt;
    let (mut response, sender, driver) = streaming_call(proxy.tcp_addr().unwrap(), &token).await;
    assert_eq!(response.status(), hyper::StatusCode::OK);
    let (delivered, failed) = tokio::time::timeout(Duration::from_secs(60), async {
        let mut delivered = 0usize;
        while let Some(frame) = response.body_mut().frame().await {
            match frame {
                Ok(frame) => {
                    if let Ok(bytes) = frame.into_data() {
                        assert!(bytes.iter().all(|byte| *byte == b'x'));
                        delivered += bytes.len();
                    }
                }
                Err(_) => return (delivered, true),
            }
        }
        (delivered, false)
    })
    .await
    .unwrap();
    assert!(
        failed,
        "capture limit must terminate the response with an error"
    );
    drop(response);
    drop(sender);
    driver.await.unwrap();
    upstream.await.unwrap();
    proxy.shutdown().await.unwrap();
    let calls = events(&store, &session).await;
    assert_eq!(calls.len(), 1);
    let payload = &calls[0].payload;
    assert_eq!(payload["outcome"], "capture_limit");
    assert_eq!(payload["resp_complete"], false);
    let captured = payload["resp_bytes"].as_u64().unwrap() as usize;
    assert!(captured <= LIMIT && captured > LIMIT - MIB);
    assert!(delivered <= captured && delivered > LIMIT - 2 * MIB);
    let hash = payload["resp_blob"]
        .as_str()
        .unwrap()
        .strip_prefix("sha256:")
        .unwrap();
    let path = home.join("blobs").join(&hash[..2]).join(&hash[2..]);
    let mut file = std::fs::File::open(path).unwrap();
    assert_eq!(file.metadata().unwrap().len(), captured as u64);
    let mut byte = [0];
    file.read_exact(&mut byte).unwrap();
    assert_eq!(byte[0], b'x');
    file.seek(SeekFrom::End(-1)).unwrap();
    file.read_exact(&mut byte).unwrap();
    assert_eq!(byte[0], b'x');
    assert_eq!(admitted_count(&home), 1);
}

#[tokio::test]
async fn revoking_instance_closes_provider_and_audits_the_partial_stream() {
    let (root, store, session) = fixture().await;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        headers(&mut client).await;
        let mut request = [0; 7];
        client.read_exact(&mut request).await.unwrap();
        client
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\npartial\r\n")
            .await
            .unwrap();
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), client.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    });
    let (proxy, token) = setup(
        store.clone(),
        &session,
        &root.path().join("core"),
        format!("http://{address}"),
        20,
        false,
    )
    .await;
    let mut client = connect(proxy.tcp_addr().unwrap(), &token).await;
    assert!(headers(&mut client).await.starts_with("HTTP/1.1 200"));
    let mut prefix = [0; 10];
    client.read_exact(&mut prefix).await.unwrap();
    proxy.revoke(&token).unwrap();
    let mut remaining = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut remaining))
        .await
        .unwrap();
    upstream.await.unwrap();
    proxy.shutdown().await.unwrap();
    let calls = events(&store, &session).await;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].payload["outcome"], "client_cancelled");
    assert_eq!(calls[0].payload["resp_complete"], false);
    assert_eq!(
        store
            .get_blob(calls[0].payload["resp_blob"].as_str().unwrap().into())
            .await
            .unwrap(),
        b"partial"
    );
}

#[tokio::test]
async fn failed_model_audit_errors_the_stream_and_closes_proxy_without_further_admission() {
    use http_body_util::BodyExt;
    let (root, store, session) = fixture().await;
    let home = root.path().join("core");
    let listener = Arc::new(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
    let address = listener.local_addr().unwrap();
    let server = listener.clone();
    let upstream = tokio::spawn(async move {
        let (mut client, _) = server.accept().await.unwrap();
        headers(&mut client).await;
        let mut request = [0; 7];
        client.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"opaque!");
        client
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone")
            .await
            .unwrap();
    });
    let (proxy, token) = setup(
        store.clone(),
        &session,
        &home,
        format!("http://{address}"),
        20,
        false,
    )
    .await;
    store.write(|connection| {
        connection.execute_batch("CREATE TRIGGER fail_test_model_audit BEFORE INSERT ON events WHEN NEW.kind = 'model.call' BEGIN SELECT RAISE(ABORT, 'injected model audit failure'); END;")?;
        Ok(())
    }).await.unwrap();
    let (mut response, sender, driver) = streaming_call(proxy.tcp_addr().unwrap(), &token).await;
    assert_eq!(response.status(), hyper::StatusCode::OK);
    let failed = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(frame) = response.body_mut().frame().await {
            if frame.is_err() {
                return true;
            }
        }
        false
    })
    .await
    .unwrap();
    assert!(failed, "failed audit was exposed as a clean response EOF");
    drop(response);
    drop(sender);
    driver.await.unwrap();
    upstream.await.unwrap();
    assert_eq!(admitted_count(&home), 1);
    assert!(events(&store, &session).await.is_empty());
    store
        .write(|connection| {
            connection.execute_batch("DROP TRIGGER fail_test_model_audit;")?;
            Ok(())
        })
        .await
        .unwrap();
    let response = call(proxy.tcp_addr().unwrap(), &token).await;
    assert!(response.starts_with("HTTP/1.1 503"));
    assert!(response.contains("fictor_proxy_unavailable"));
    assert_eq!(
        admitted_count(&home),
        1,
        "closed proxy admitted a second request"
    );
    assert_no_provider_connection(&listener).await;
    proxy.shutdown().await.unwrap();
    assert!(events(&store, &session).await.is_empty());
}

#[tokio::test]
async fn cancelling_before_provider_headers_closes_transport_and_audits_empty_capture() {
    let (root, store, session) = fixture().await;
    let home = root.path().join("core");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (ready, received) = tokio::sync::oneshot::channel();
    let upstream = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        headers(&mut client).await;
        let mut request = [0; 7];
        client.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"opaque!");
        ready.send(()).unwrap();
        // Intentionally send no response headers: client cancellation must abort
        // the provider connection rather than waiting for the 600-second timeout.
        let mut byte = [0];
        let closed = tokio::time::timeout(Duration::from_secs(5), client.read(&mut byte))
            .await
            .unwrap();
        assert!(
            matches!(closed, Ok(0) | Err(_)),
            "provider survived client cancellation before headers"
        );
    });
    let (proxy, token) = setup(
        store.clone(),
        &session,
        &home,
        format!("http://{address}"),
        20,
        false,
    )
    .await;
    let client = connect(proxy.tcp_addr().unwrap(), &token).await;
    tokio::time::timeout(Duration::from_secs(5), received)
        .await
        .unwrap()
        .unwrap();
    drop(client);
    upstream.await.unwrap();
    proxy.shutdown().await.unwrap();
    let calls = events(&store, &session).await;
    assert_eq!(calls.len(), 1);
    let payload = &calls[0].payload;
    assert_eq!(payload["outcome"], "client_cancelled");
    assert_eq!(payload["resp_complete"], false);
    assert_eq!(payload["resp_bytes"], 0);
    assert_eq!(payload["status"], serde_json::Value::Null);
    assert_eq!(payload["ttfb_ms"], serde_json::Value::Null);
    assert_eq!(
        store
            .get_blob(payload["req_blob"].as_str().unwrap().into())
            .await
            .unwrap(),
        b"opaque!"
    );
    assert!(
        store
            .get_blob(payload["resp_blob"].as_str().unwrap().into())
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        admitted_count(&home),
        1,
        "cancelling an admitted request refunded budget"
    );
}

#[tokio::test]
async fn bodyless_http_responses_complete_and_commit_audit_before_client_headers() {
    for (method, status, length) in [
        ("HEAD", 200, Some(123)),
        ("POST", 204, None),
        ("POST", 304, Some(123)),
        ("POST", 200, Some(0)),
    ] {
        let (root, store, session) = fixture().await;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let upstream = tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.unwrap();
            let request = headers(&mut client).await;
            assert!(request.starts_with(&format!("{method} /v1/no-body HTTP/1.1\r\n")));
            let reason = match status {
                204 => "No Content",
                304 => "Not Modified",
                _ => "OK",
            };
            let length = length.map_or_else(String::new, |length| {
                format!("Content-Length: {length}\r\n")
            });
            client
                .write_all(
                    format!("HTTP/1.1 {status} {reason}\r\n{length}Connection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
        });
        let (proxy, token) = setup(
            store.clone(),
            &session,
            &root.path().join("core"),
            format!("http://{address}"),
            20,
            false,
        )
        .await;
        let mut client = TcpStream::connect(proxy.tcp_addr().unwrap()).await.unwrap();
        client.write_all(format!("{method} http://models.fictor.internal/p/fake/v1/no-body HTTP/1.1\r\nHost: ignored\r\nProxy-Authorization: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",token.basic_header()).as_bytes()).await.unwrap();
        assert!(
            headers(&mut client)
                .await
                .starts_with(&format!("HTTP/1.1 {status}"))
        );
        // A bodyless response has no later EOF barrier: audit must already be durable.
        let calls = events(&store, &session).await;
        assert_eq!(
            calls.len(),
            1,
            "missing bodyless audit for {method} {status}"
        );
        let payload = &calls[0].payload;
        assert_eq!(payload["outcome"], "complete", "{method} {status}");
        assert_eq!(payload["status"], status);
        assert_eq!(payload["resp_complete"], true);
        assert_eq!(payload["resp_bytes"], 0);
        assert_eq!(payload["ttfb_ms"], serde_json::Value::Null);
        assert!(
            store
                .get_blob(payload["resp_blob"].as_str().unwrap().into())
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store.session(session).await.unwrap().flags,
            fictor::store::Flags::default()
        );
        let mut body = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut body))
            .await
            .unwrap()
            .unwrap();
        assert!(body.is_empty(), "unexpected body for {method} {status}");
        upstream.await.unwrap();
        proxy.shutdown().await.unwrap();
    }
}
