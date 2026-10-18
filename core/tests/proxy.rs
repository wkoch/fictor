use fictor::{
    config::Mode,
    proxy::{EgressProxy, ProxyIdentity},
    store::{EventQuery, NewSession, Store, Trust},
};
use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixStream},
};

async fn fixture() -> (tempfile::TempDir, Arc<Store>, String) {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("data");
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    fictor::initialize(&home).await.unwrap();
    let store = Arc::new(Store::open(&home).await.unwrap());
    let session = store
        .create_session(NewSession {
            title: "proxy".into(),
            workspace,
            workspace_trust: Trust::Trusted,
            harness: "harness".into(),
            mode: Mode::Default,
            model: None,
        })
        .await
        .unwrap();
    (root, store, session.id)
}
fn identity(instance: &str, session: Option<&str>) -> ProxyIdentity {
    ProxyIdentity {
        instance_id: instance.into(),
        ext_id: "test-extension".into(),
        session_id: session.map(Into::into),
    }
}
async fn headers(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> String {
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !bytes.ends_with(b"\r\n\r\n") {
            assert!(bytes.len() < 16384, "headers too large");
            let mut byte = [0];
            stream.read_exact(&mut byte).await.unwrap();
            bytes.push(byte[0]);
        }
    })
    .await
    .unwrap();
    String::from_utf8(bytes).unwrap()
}
async fn request(address: SocketAddr, request: String) -> String {
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}
async fn upstream(
    taint: Option<(Arc<Store>, String)>,
) -> (SocketAddr, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        let request = headers(&mut client).await;
        if let Some((store, session)) = taint {
            assert!(
                store.session(session).await.unwrap().flags.untrusted,
                "external data could arrive before durable session taint"
            );
        }
        client.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close, X-Upstream-Hop\r\nX-Upstream-Hop: stripped\r\n\r\nhello").await.unwrap();
        request
    });
    (address, task)
}

#[tokio::test]
async fn requires_per_instance_random_basic_credentials_and_reserves_model_host() {
    let (_root, store, session) = fixture().await;
    let proxy = EgressProxy::bind_tcp(store, vec![]).await.unwrap();
    let address = proxy.tcp_addr().unwrap();
    let first = proxy
        .register(identity("one", Some(&session)), &[])
        .unwrap();
    let second = proxy
        .register(identity("two", Some(&session)), &[])
        .unwrap();
    assert_eq!(first.expose().len(), 64);
    assert_ne!(first.expose(), second.expose());
    for authorization in [
        String::new(),
        "Proxy-Authorization: Basic Zng6dW5rbm93bg==\r\n".into(),
    ] {
        let response=request(address,format!("GET http://blocked.invalid/ HTTP/1.1\r\nHost: ignored\r\n{authorization}Connection: close\r\n\r\n")).await;
        assert!(response.starts_with("HTTP/1.1 407"));
        assert!(
            response
                .to_ascii_lowercase()
                .contains("proxy-authenticate: basic")
        );
    }
    for host in [
        "models.fictor.internal",
        "MoDeLs.FiCtOr.InTeRnAl",
        "models.fictor.internal.",
    ] {
        for uri in [format!("http://{host}/p/provider/x"), format!("{host}:443")] {
            let method = if uri.starts_with("http") {
                "GET"
            } else {
                "CONNECT"
            };
            let reserved=request(address,format!("{method} {uri} HTTP/1.1\r\nHost: ignored\r\nProxy-Authorization: {}\r\nConnection: close\r\n\r\n",first.basic_header())).await;
            assert!(reserved.starts_with("HTTP/1.1 503"));
        }
    }
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn rejects_explicit_invalid_ports_and_non_http_absolute_targets() {
    let (_root, store, _session) = fixture().await;
    let proxy = EgressProxy::bind_tcp(store, vec![]).await.unwrap();
    let token = proxy
        .register(identity("invalid", None), &["127.0.0.1:80".into()])
        .unwrap();
    for (method, uri) in [
        ("GET", "http://127.0.0.1:65536/"),
        ("GET", "http://127.0.0.1:abc/"),
        ("GET", "http://127.0.0.1:0/"),
        ("GET", "http://127.0.0.1:/"),
        ("GET", "https://127.0.0.1/"),
        ("GET", "/relative"),
        ("CONNECT", "127.0.0.1"),
        ("CONNECT", "127.0.0.1:65536"),
    ] {
        let result=request(proxy.tcp_addr().unwrap(),format!("{method} {uri} HTTP/1.1\r\nHost: ignored\r\nProxy-Authorization: {}\r\nConnection: close\r\n\r\n",token.basic_header())).await;
        assert!(
            result.starts_with("HTTP/1.1 400"),
            "malformed destination accepted: {uri}"
        );
    }
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn forwards_http_without_proxy_credentials_or_hop_headers_and_taints_before_delivery() {
    let (_root, store, session) = fixture().await;
    let (upstream_address, server) = upstream(Some((store.clone(), session.clone()))).await;
    let proxy = EgressProxy::bind_tcp(store.clone(), vec![]).await.unwrap();
    let token = proxy
        .register(
            identity("http", Some(&session)),
            &[upstream_address.to_string()],
        )
        .unwrap();
    let result=request(proxy.tcp_addr().unwrap(),format!("GET http://{upstream_address}/path?q=1 HTTP/1.1\r\nHost: evil.invalid\r\nProxy-Authorization: {}\r\nProxy-Connection: keep-alive\r\nConnection: close, X-Private-Hop\r\nX-Private-Hop: must-strip\r\nX-End-To-End: preserved\r\n\r\n",token.basic_header())).await;
    assert!(result.starts_with("HTTP/1.1 200"));
    assert!(result.ends_with("hello"));
    assert!(!result.to_ascii_lowercase().contains("x-upstream-hop"));
    let forwarded = server.await.unwrap();
    let normalized = forwarded.to_ascii_lowercase();
    assert!(forwarded.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
    assert!(normalized.contains(&format!("host: {upstream_address}\r\n")));
    assert!(normalized.contains("x-end-to-end: preserved"));
    for forbidden in [
        "proxy-authorization",
        "proxy-connection",
        "x-private-hop",
        "evil.invalid",
    ] {
        assert!(
            !normalized.contains(forbidden),
            "forwarded forbidden header"
        );
    }
    assert!(
        !forwarded.contains(token.expose()),
        "proxy credential reached upstream"
    );
    assert!(
        store
            .session(session.clone())
            .await
            .unwrap()
            .flags
            .untrusted
    );
    let events = store
        .query_events(EventQuery {
            session_id: Some(session),
            kinds: vec!["session.tainted".into()],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].payload["reason"], "net:127.0.0.1");
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn explicit_trusted_host_does_not_taint_and_global_identity_has_no_session_effect() {
    let (_root, store, session) = fixture().await;
    let proxy = EgressProxy::bind_tcp(store.clone(), vec!["127.0.0.1".into()])
        .await
        .unwrap();
    for (instance, scope) in [("trusted", Some(session.as_str())), ("global", None)] {
        let (upstream_address, server) = upstream(None).await;
        let token = proxy
            .register(identity(instance, scope), &[upstream_address.to_string()])
            .unwrap();
        let response=request(proxy.tcp_addr().unwrap(),format!("GET http://{upstream_address}/ HTTP/1.1\r\nHost: ignored\r\nProxy-Authorization: {}\r\nConnection: close\r\n\r\n",token.basic_header())).await;
        assert!(response.starts_with("HTTP/1.1 200"));
        server.await.unwrap();
    }
    assert!(!store.session(session).await.unwrap().flags.untrusted);
    proxy.shutdown().await.unwrap();
}

async fn echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0u8; 32];
        loop {
            let count = stream.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            stream.write_all(&buffer[..count]).await.unwrap();
        }
    });
    (address, task)
}
async fn tunnel(address: SocketAddr, target: SocketAddr, basic: String) -> TcpStream {
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: {basic}\r\n\r\n").as_bytes()).await.unwrap();
    assert!(headers(&mut client).await.starts_with("HTTP/1.1 200"));
    client.write_all(b"ping").await.unwrap();
    let mut bytes = [0; 4];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"ping");
    client
}
#[tokio::test]
async fn connect_streams_and_revocation_closes_existing_tunnel() {
    let (_root, store, session) = fixture().await;
    let (target, server) = echo().await;
    let proxy = EgressProxy::bind_tcp(store.clone(), vec![]).await.unwrap();
    let token = proxy
        .register(identity("connect", Some(&session)), &[target.to_string()])
        .unwrap();
    let mut client = tunnel(proxy.tcp_addr().unwrap(), target, token.basic_header()).await;
    assert!(store.session(session).await.unwrap().flags.untrusted);
    proxy.revoke(&token).unwrap();
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), client.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    let denied=request(proxy.tcp_addr().unwrap(),format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: {}\r\nConnection: close\r\n\r\n",token.basic_header())).await;
    assert!(denied.starts_with("HTTP/1.1 407"));
    server.await.unwrap();
    proxy.shutdown().await.unwrap();
}
#[tokio::test]
async fn shutdown_closes_active_tunnels() {
    let (_root, store, _session) = fixture().await;
    let (target, server) = echo().await;
    let proxy = EgressProxy::bind_tcp(store, vec![]).await.unwrap();
    let token = proxy
        .register(identity("shutdown", None), &[target.to_string()])
        .unwrap();
    let mut client = tunnel(proxy.tcp_addr().unwrap(), target, token.basic_header()).await;
    proxy.shutdown().await.unwrap();
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), client.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    server.await.unwrap();
}
#[tokio::test]
async fn denial_buckets_aggregate_per_instance_and_host_and_flush_on_shutdown() {
    let (_root, store, session) = fixture().await;
    let proxy = EgressProxy::bind_tcp(store.clone(), vec![]).await.unwrap();
    let first = proxy
        .register(identity("one", Some(&session)), &["allowed.invalid".into()])
        .unwrap();
    let second = proxy.register(identity("two", None), &[]).unwrap();
    let start = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 60;
    for token in [&first, &first, &first, &second] {
        let response=request(proxy.tcp_addr().unwrap(),format!("GET http://blocked.invalid/ HTTP/1.1\r\nHost: ignored\r\nProxy-Authorization: {}\r\nConnection: close\r\n\r\n",token.basic_header())).await;
        assert!(response.starts_with("HTTP/1.1 403"));
    }
    proxy.shutdown().await.unwrap();
    let finish = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 60;
    let events = store
        .query_events(EventQuery {
            session_id: Some("sys".into()),
            kinds: vec!["net.denied".into()],
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(events.len() >= 2 && events.len() <= 2 + (finish - start) as usize);
    let mut counts = BTreeMap::new();
    for event in events {
        assert_eq!(event.actor, "core");
        assert_eq!(event.source, "core");
        assert_eq!(event.payload["ext_id"], "test-extension");
        assert_eq!(event.payload["host"], "blocked.invalid");
        *counts
            .entry(event.payload["count"].as_u64().unwrap())
            .or_insert(0) += 1;
    }
    assert_eq!(
        counts
            .iter()
            .map(|(count, occurrences)| count * occurrences)
            .sum::<u64>(),
        4
    );
    assert!(!store.session(session).await.unwrap().flags.untrusted);
}
#[tokio::test]
async fn unix_endpoint_is_private_authenticated_and_removed_at_shutdown() {
    use std::os::unix::fs::PermissionsExt;
    let (root, store, _session) = fixture().await;
    let path = root
        .path()
        .join("data/run")
        .canonicalize()
        .unwrap()
        .join("egress.sock");
    let proxy = EgressProxy::bind_unix(path.clone(), store, vec![])
        .await
        .unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(proxy.tcp_addr().is_none());
    assert_eq!(proxy.unix_path(), Some(path.as_path()));
    let token = proxy.register(identity("unix", None), &[]).unwrap();
    let mut client = UnixStream::connect(&path).await.unwrap();
    client.write_all(format!("GET http://blocked.invalid/ HTTP/1.1\r\nHost: ignored\r\nProxy-Authorization: {}\r\nConnection: close\r\n\r\n",token.basic_header()).as_bytes()).await.unwrap();
    assert!(headers(&mut client).await.starts_with("HTTP/1.1 403"));
    proxy.shutdown().await.unwrap();
    assert!(!path.exists());
}

#[tokio::test]
async fn failed_session_audit_closes_request_before_forwarding_upstream_headers() {
    let (_root, store, _session) = fixture().await;
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = upstream.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut bytes = [0; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), stream.read(&mut bytes))
                .await
                .unwrap()
                .unwrap(),
            0,
            "request escaped before its audit succeeded"
        );
    });
    let proxy = EgressProxy::bind_tcp(store, vec![]).await.unwrap();
    let token = proxy
        .register(
            identity("failed-audit", Some("nonexistent-session")),
            &[address.to_string()],
        )
        .unwrap();
    let mut client = TcpStream::connect(proxy.tcp_addr().unwrap()).await.unwrap();
    client.write_all(format!("GET http://{address}/ HTTP/1.1\r\nHost: ignored\r\nProxy-Authorization: {}\r\nConnection: close\r\n\r\n",token.basic_header()).as_bytes()).await.unwrap();
    let mut response = String::new();
    let read = tokio::time::timeout(Duration::from_secs(5), client.read_to_string(&mut response))
        .await
        .unwrap();
    assert!(read.is_err() || response.is_empty() || response.starts_with("HTTP/1.1 503"));
    server.await.unwrap();
    assert!(
        proxy
            .register(identity("after-failure", None), &[])
            .is_err()
    );
    proxy.shutdown().await.unwrap();
}
