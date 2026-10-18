use fictor::{
    config::{Budget, Mode, Provider},
    proxy::{EgressProxy, ProxyIdentity, model_proxy::ModelProxy},
    secrets::{BackendKind, SecretStore},
    store::{EventQuery, NewSession, Store, Trust},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{collections::BTreeMap, net::Ipv4Addr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

// Generated locally with openssl req -x509 -newkey rsa:2048 -nodes -days 36500,
// SAN DNS:localhost,IP:127.0.0.1 and serverAuth EKU. This private key is a public
// test fixture, never a real credential. The certificate is never installed/trusted.
const CERTIFICATE: &[u8] = include_bytes!("fixtures/model-untrusted-cert.der");
const PRIVATE_KEY: &[u8] = include_bytes!("fixtures/model-untrusted-key.der");

#[tokio::test]
async fn untrusted_provider_certificate_fails_before_credentials_or_body_leave_the_core() {
    let temporary = tempfile::tempdir().unwrap();
    let home = temporary.path().join("core");
    fictor::initialize(&home).await.unwrap();
    let workspace = temporary.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let store = Arc::new(Store::open(&home).await.unwrap());
    let session = store
        .create_session(NewSession {
            title: "untrusted TLS provider".into(),
            workspace,
            workspace_trust: Trust::Trusted,
            harness: "harness".into(),
            mode: Mode::Default,
            model: None,
        })
        .await
        .unwrap();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(CERTIFICATE.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(PRIVATE_KEY.to_vec())),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let provider_task = tokio::spawn(async move {
        let (stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        // A TLS ClientHello must arrive, rather than cleartext HTTP carrying a key.
        let mut record = [0; 1];
        let count = tokio::time::timeout(Duration::from_secs(5), stream.peek(&mut record))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(record[0], 0x16);
        // TlsAcceptor never exposes an application stream: no credential header or
        // opaque HTTP request body can be read by this provider after rejection.
        let handshake = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(stream))
            .await
            .unwrap();
        assert!(
            handshake.is_err(),
            "the self-signed provider must not be trusted"
        );
    });

    let secrets = Arc::new(
        SecretStore::open_with_lease(store.owner().clone(), BackendKind::File, Default::default())
            .unwrap(),
    );
    secrets
        .set("tls_test_key", "fake-tls-core-credential")
        .unwrap();
    let provider = Provider {
        base_url: format!("https://{address}"),
        auth_header: Some("x-api-key".into()),
        auth_prefix: None,
        secret: Some("tls_test_key".into()),
        extra_headers: BTreeMap::new(),
    };
    let model = ModelProxy::new(
        store.clone(),
        BTreeMap::from([("tls".into(), provider)]),
        secrets,
        Budget {
            max_model_requests_per_day: 10,
            max_model_requests_per_session: 10,
        },
    )
    .unwrap();
    let proxy = EgressProxy::bind_tcp(store.clone(), vec![]).await.unwrap();
    proxy.set_model_proxy(model).unwrap();
    let token = proxy
        .register_with_models(
            ProxyIdentity {
                instance_id: "tls-test-instance".into(),
                ext_id: "harness".into(),
                session_id: Some(session.id.clone()),
            },
            &[],
            &["tls".into()],
        )
        .unwrap();
    let body = "opaque-tls-request-body";
    let mut extension = TcpStream::connect(proxy.tcp_addr().unwrap()).await.unwrap();
    extension.write_all(format!(
        "POST http://models.fictor.internal/p/tls/v1/messages HTTP/1.1\r\nHost: models.fictor.internal\r\nProxy-Authorization: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        token.basic_header(), body.len(),
    ).as_bytes()).await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(
        Duration::from_secs(10),
        extension.read_to_string(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(response.starts_with("HTTP/1.1 502"), "{response}");
    assert!(response.contains("fictor_upstream_error"));
    assert!(!response.contains("fake-tls-core-credential"));
    provider_task.await.unwrap();
    proxy.shutdown().await.unwrap();

    let calls = store
        .query_events(EventQuery {
            session_id: Some(session.id),
            kinds: vec!["model.call".into()],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(calls.len(), 1);
    let payload = &calls[0].payload;
    assert_eq!(payload["outcome"], "upstream_error");
    assert_eq!(payload["resp_complete"], false);
    assert_eq!(payload["resp_bytes"], 0);
    assert_eq!(
        store
            .get_blob(payload["req_blob"].as_str().unwrap().into())
            .await
            .unwrap(),
        body.as_bytes()
    );
    assert!(!payload.to_string().contains("fake-tls-core-credential"));
}
