use fictor::{
    config::Mode,
    kernel::{
        KernelError, KernelIdentity, KernelServer, LogFuture, LogRecord, LogSink, MAX_MESSAGE_BYTES,
    },
    store::{AppendEvent, NewSession, Provenance, Sensitivity, Store, Trust},
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, os::unix::fs::PermissionsExt, sync::Arc, time::Duration};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

struct Fixture {
    _root: TempDir,
    home: std::path::PathBuf,
    store: Arc<Store>,
    session: String,
}
impl Fixture {
    async fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("fk-")
            .tempdir_in("/tmp")
            .unwrap();
        let home = root.path().join("h");
        let workspace = root.path().join("w");
        std::fs::create_dir(&workspace).unwrap();
        fictor::initialize(&home).await.unwrap();
        let store = Arc::new(Store::open(&home).await.unwrap());
        let session = store
            .create_session(NewSession {
                title: "test".into(),
                workspace,
                workspace_trust: Trust::Trusted,
                harness: "alpha".into(),
                mode: Mode::Default,
                model: None,
            })
            .await
            .unwrap()
            .id;
        Self {
            _root: root,
            home,
            store,
            session,
        }
    }
    fn identity(&self, session: Option<String>, scopes: &[&str]) -> KernelIdentity {
        KernelIdentity {
            ext_id: "alpha".into(),
            instance_id: ulid::Ulid::generate().to_string(),
            session_id: session,
            is_harness: false,
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
        }
    }
    async fn server(&self, session: Option<String>, scopes: &[&str]) -> KernelServer {
        KernelServer::bind(
            &self.home,
            self.identity(session, scopes),
            self.store.clone(),
            vec!["fake".into()],
        )
        .await
        .unwrap()
    }
    async fn append(&self, session: &str, text: &str) -> String {
        self.store
            .append(AppendEvent {
                session_id: session.into(),
                parent_id: None,
                kind: "x.alpha.note".into(),
                actor: "core".into(),
                payload: json!({"text":text}),
                blob_refs: vec![],
                provenance: Provenance {
                    trust: Trust::Trusted,
                    sensitivity: Sensitivity::Public,
                    source: "core".into(),
                },
            })
            .await
            .unwrap()
            .id
    }
}
struct Client(BufReader<UnixStream>);
impl Client {
    async fn raw(server: &KernelServer) -> Self {
        Self(BufReader::new(
            UnixStream::connect(server.socket_path()).await.unwrap(),
        ))
    }
    async fn new(server: &KernelServer) -> Self {
        let mut c = Self::raw(server).await;
        let hello = c
            .call("kernel.hello", json!({"protocol":1,"token":server.token()}))
            .await;
        assert_eq!(hello["result"]["protocol"], 1);
        c
    }
    async fn call(&mut self, method: &str, params: Value) -> Value {
        self.send(json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .await;
        self.read().await
    }
    async fn send(&mut self, value: Value) {
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        self.0.get_mut().write_all(&bytes).await.unwrap();
    }
    async fn read(&mut self) -> Value {
        serde_json::from_str(&self.read_raw().await).unwrap()
    }
    async fn read_raw(&mut self) -> String {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(5), self.0.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        assert!(n > 0);
        line
    }
    async fn send_raw(&mut self, text: &str) {
        self.0.get_mut().write_all(text.as_bytes()).await.unwrap();
        self.0.get_mut().write_all(b"\n").await.unwrap();
    }
    async fn closed(&mut self) {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(3), self.0.read_line(&mut line))
            .await
            .unwrap();
        assert!(matches!(n, Ok(0) | Err(_)));
        assert!(line.is_empty(), "closed transport emitted a partial frame");
    }
}
fn error(value: &Value, name: &str) {
    assert_eq!(value["error"]["message"], name);
}

struct Logs(tokio::sync::mpsc::UnboundedSender<LogRecord>);
impl LogSink for Logs {
    fn write(&self, record: LogRecord) -> LogFuture {
        Box::pin(std::future::ready(
            self.0.send(record).map_err(|_| KernelError::Log),
        ))
    }
}

#[tokio::test]
async fn log_notifications_require_hello_validate_fields_and_never_reply() {
    let fixture = Fixture::new().await;
    let (sender, mut logs) = tokio::sync::mpsc::unbounded_channel();
    let mut server = KernelServer::bind_with_log(
        &fixture.home,
        fixture.identity(Some(fixture.session.clone()), &["kv"]),
        fixture.store.clone(),
        vec![],
        Some(Arc::new(Logs(sender))),
    )
    .await
    .unwrap();
    let mut unauthenticated = Client::raw(&server).await;
    unauthenticated.send(json!({"jsonrpc":"2.0","method":"log","params":{"level":"info","message":"before hello"}})).await;
    error(&unauthenticated.read().await, "UNAUTHENTICATED");
    unauthenticated.closed().await;
    assert!(logs.try_recv().is_err());

    let mut client = Client::new(&server).await;
    for level in ["debug", "info", "warn", "error"] {
        client.send(json!({"jsonrpc":"2.0","method":"log","params":{"level":level,"message":"valid","fields":{"nested":{"number":3,"value":null},"ext_id":"untrusted field"}}})).await;
    }
    client
        .send(
            json!({"jsonrpc":"2.0","method":"log","params":{"level":"info","message":"no fields"}}),
        )
        .await;
    for invalid in [
        json!({"level":"trace","message":"invalid"}),
        json!({"level":"info","message":1}),
        json!({"level":"warn","message":"invalid","fields":[]}),
        json!({"level":"warn","message":"invalid","fields":null}),
        json!({"level":"error","message":"forged","ext_id":"another-extension"}),
    ] {
        client
            .send(json!({"jsonrpc":"2.0","method":"log","params":invalid}))
            .await;
    }
    // A subsequent request is a delivery barrier and detects forbidden replies
    // to either valid or invalid notifications.
    let result = client
        .call("kv.get", json!({"key":"delivery-barrier"}))
        .await;
    assert!(result.get("result").is_some());
    for level in ["debug", "info", "warn", "error"] {
        let log = logs.try_recv().unwrap();
        assert_eq!(log.level.as_str(), level);
        assert_eq!(log.message, "valid");
        assert_eq!(log.fields.unwrap()["nested"]["number"], 3);
    }
    let log = logs.try_recv().unwrap();
    assert_eq!(log.message, "no fields");
    assert!(log.fields.is_none());
    assert!(logs.try_recv().is_err());
    error(
        &client
            .call(
                "log",
                json!({"level":"info","message":"not a notification"}),
            )
            .await,
        "METHOD_NOT_FOUND",
    );
    assert!(logs.try_recv().is_err());
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn unavailable_log_sink_closes_the_channel_without_echoing_the_record() {
    let fixture = Fixture::new().await;
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    drop(receiver);
    let mut server = KernelServer::bind_with_log(
        &fixture.home,
        fixture.identity(Some(fixture.session.clone()), &["kv"]),
        fixture.store.clone(),
        vec![],
        Some(Arc::new(Logs(sender))),
    )
    .await
    .unwrap();
    let mut client = Client::new(&server).await;
    client.send(json!({"jsonrpc":"2.0","method":"log","params":{"level":"error","message":"fake credential never echoed"}})).await;
    client.closed().await;
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn hello_authentication_protocol_identity_and_socket_permissions() {
    let f = Fixture::new().await;
    let mut server = f.server(Some(f.session.clone()), &["kv"]).await;
    assert!(server.url().starts_with("unix:///"));
    assert_eq!(server.token().len(), 64);
    assert_eq!(
        std::fs::metadata(server.socket_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(server.socket_path().parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let mut c = Client::raw(&server).await;
    error(
        &c.call("kv.get", json!({"key":"x"})).await,
        "UNAUTHENTICATED",
    );
    c.closed().await;
    let mut c = Client::raw(&server).await;
    error(
        &c.call("kernel.hello", json!({"protocol":1,"token":"bad"}))
            .await,
        "UNAUTHENTICATED",
    );
    c.closed().await;
    let mut c = Client::raw(&server).await;
    let mismatch = c
        .call("kernel.hello", json!({"protocol":2,"token":server.token()}))
        .await;
    error(&mismatch, "INVALID_PARAMS");
    assert_eq!(mismatch["error"]["data"]["supported"], json!([1]));
    c.closed().await;
    let mut c = Client::new(&server).await;
    error(
        &c.call("kernel.hello", json!({"protocol":1,"token":server.token()}))
            .await,
        "INVALID_PARAMS",
    );
    server.shutdown().await.unwrap();
    assert!(!server.socket_path().exists());
}

#[tokio::test]
async fn bind_rejects_invalid_identity_scopes_global_privilege_and_long_path() {
    let f = Fixture::new().await;
    for scopes in [BTreeSet::new(), BTreeSet::from(["unknown".to_string()])] {
        let mut id = f.identity(Some(f.session.clone()), &["kv"]);
        id.scopes = scopes;
        assert!(
            KernelServer::bind(&f.home, id, f.store.clone(), vec![])
                .await
                .is_err()
        );
    }
    for scope in ["sessions", "tools", "hooks"] {
        assert!(
            KernelServer::bind(&f.home, f.identity(None, &[scope]), f.store.clone(), vec![])
                .await
                .is_err()
        );
    }
    let mut identity = f.identity(None, &["kv"]);
    identity.is_harness = true;
    assert!(
        KernelServer::bind(&f.home, identity, f.store.clone(), vec![])
            .await
            .is_err()
    );
    let mut identity = f.identity(Some(f.session.clone()), &["kv"]);
    identity.instance_id = "../../escape".into();
    assert!(
        KernelServer::bind(&f.home, identity, f.store.clone(), vec![])
            .await
            .is_err()
    );
    let long = f.home.join("x".repeat(90));
    std::fs::create_dir(&long).unwrap();
    assert!(
        KernelServer::bind(
            &long,
            f.identity(Some(f.session.clone()), &["kv"]),
            f.store.clone(),
            vec![]
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn scopes_precede_unavailable_routes_and_forged_fields_are_rejected() {
    let f = Fixture::new().await;
    let mut server = f
        .server(Some(f.session.clone()), &["events.write", "tools"])
        .await;
    let mut c = Client::new(&server).await;
    error(&c.call("kv.get", json!({"key":"x"})).await, "SCOPE_DENIED");
    error(&c.call("tools.call", json!({})).await, "METHOD_NOT_FOUND");
    error(&c.call("hooks.invoke", json!({})).await, "SCOPE_DENIED");
    for field in [
        "actor",
        "trust",
        "sensitivity",
        "source",
        "flags",
        "blob_refs",
    ] {
        let mut params = json!({"session_id":f.session,"kind":"x.alpha.note","payload":{}});
        params[field] = json!("forged");
        error(&c.call("events.append", params).await, "INVALID_PARAMS");
    }
    for kind in [
        "x.beta.note",
        "session.tainted",
        "assistant.message",
        "x.alpha.",
        "x.alpha..bad",
    ] {
        error(
            &c.call(
                "events.append",
                json!({"session_id":f.session,"kind":kind,"payload":{}}),
            )
            .await,
            "INVALID_KIND",
        );
    }
    let response = c
        .call(
            "events.append",
            json!({"session_id":f.session,"kind":"x.alpha.note","payload":{"test":true}}),
        )
        .await;
    let event = f
        .store
        .event(response["result"]["id"].as_str().unwrap().into())
        .await
        .unwrap();
    assert_eq!(event.actor, "ext:alpha");
    assert_eq!(event.source, "ext:alpha");
    assert_eq!(event.trust, Trust::Trusted);
    assert_eq!(event.sensitivity, Sensitivity::Public);
    assert!(!event.flags.untrusted && !event.flags.private);
    error(&c.call("events.append",json!({"session_id":f.session,"kind":"x.alpha.note","payload":{},"parent_id":ulid::Ulid::generate().to_string()})).await,"HEAD_MOVED");
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn ancestor_reads_stop_at_fork_and_queries_never_cross_sessions() {
    let f = Fixture::new().await;
    let before = f.append(&f.session, "before").await;
    let child = f.store.fork_session(before.clone(), None).await.unwrap();
    let future = f.append(&f.session, "future").await;
    let sibling = f.store.fork_session(before.clone(), None).await.unwrap();
    let foreign = f.append(&sibling.id, "foreign").await;
    let mut server = f
        .server(
            Some(child.id.clone()),
            &["events.read", "events.write", "sessions"],
        )
        .await;
    let mut c = Client::new(&server).await;
    assert_eq!(
        c.call("events.get", json!({"id":before})).await["result"]["id"],
        before
    );
    for id in [&future, &foreign] {
        error(
            &c.call("events.get", json!({"id":id})).await,
            "SCOPE_DENIED",
        );
    }
    let path = c.call("events.path", json!({"session_id":f.session})).await;
    assert_eq!(
        path["result"]["events"].as_array().unwrap().last().unwrap()["id"],
        before
    );
    let events = c.call("events.query", json!({})).await;
    let ids = events["result"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(!ids.contains(&future.as_str()));
    assert!(!ids.contains(&foreign.as_str()));
    let events = c
        .call("events.query", json!({"session_id":f.session}))
        .await;
    assert_eq!(events["result"]["events"][0]["id"], before);
    error(
        &c.call("events.path", json!({"session_id":sibling.id}))
            .await,
        "SCOPE_DENIED",
    );
    error(
        &c.call(
            "events.path",
            json!({"session_id":child.id,"after_id":future}),
        )
        .await,
        "INVALID_PARAMS",
    );
    error(
        &c.call("sessions.get", json!({"session_id":f.session}))
            .await,
        "SCOPE_DENIED",
    );
    assert_eq!(
        c.call("sessions.get", json!({"session_id":child.id})).await["result"]["id"],
        child.id
    );
    error(
        &c.call(
            "events.append",
            json!({"session_id":f.session,"kind":"x.alpha.note","payload":{}}),
        )
        .await,
        "SCOPE_DENIED",
    );
    error(
        &c.call("sessions.fork", json!({"from_event_id":future}))
            .await,
        "SCOPE_DENIED",
    );
    assert_eq!(
        c.call("sessions.fork", json!({"from_event_id":before}))
            .await["result"]["fork_event_id"],
        before
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn kv_namespaces_blobs_config_reload_and_global_write_boundary() {
    let f = Fixture::new().await;
    let origin = f
        .store
        .session(f.session.clone())
        .await
        .unwrap()
        .head_id
        .unwrap();
    let other = f.store.fork_session(origin, None).await.unwrap();
    let scopes = ["kv", "blobs", "config", "events.read", "events.write"];
    let mut first = f.server(Some(f.session.clone()), &scopes).await;
    let mut second = f.server(Some(other.id), &scopes).await;
    let mut global = f.server(None, &scopes).await;
    let mut a = Client::new(&first).await;
    let mut b = Client::new(&second).await;
    let mut g = Client::new(&global).await;
    assert!(
        a.call("kv.set", json!({"key":"same","value":{"a":1}}))
            .await
            .get("result")
            .is_some()
    );
    assert_eq!(
        b.call("kv.get", json!({"key":"same"})).await["result"]["value"],
        Value::Null
    );
    assert_eq!(
        g.call("kv.get", json!({"key":"same"})).await["result"]["value"],
        Value::Null
    );
    error(
        &a.call("kv.get", json!({"key":"same","namespace":"alpha"}))
            .await,
        "INVALID_PARAMS",
    );
    assert_eq!(
        a.call("kv.list", json!({"prefix":"sa","limit":1})).await["result"]["items"][0]["key"],
        "same"
    );
    a.call("kv.delete", json!({"key":"same"})).await;
    assert_eq!(
        a.call("kv.get", json!({"key":"same"})).await["result"]["value"],
        Value::Null
    );
    let put = a.call("blobs.put", json!({"text":"hello"})).await;
    let hash = put["result"]["hash"].clone();
    assert_eq!(
        b.call("blobs.get", json!({"hash":hash})).await["result"]["base64"],
        "aGVsbG8="
    );
    error(
        &a.call("blobs.put", json!({"text":"x","base64":"eA=="}))
            .await,
        "INVALID_PARAMS",
    );
    error(
        &a.call("blobs.put", json!({"base64":"??"})).await,
        "INVALID_PARAMS",
    );
    let large = f.store.put_blob(vec![0; 13 * 1024 * 1024]).await.unwrap();
    error(
        &a.call("blobs.get", json!({"hash":large})).await,
        "TOO_LARGE",
    );
    let config = std::fs::read_to_string(f.home.join("config.toml")).unwrap();
    std::fs::write(
        f.home.join("config.toml"),
        format!("{config}\n[ext.alpha]\nvalue = 1\n[ext.beta]\nprivate = 'hidden'\n"),
    )
    .unwrap();
    assert_eq!(
        a.call("config.get", json!({"section":"ext"})).await["result"]["ext"],
        json!({"value":1})
    );
    std::fs::write(
        f.home.join("config.toml"),
        format!("{config}\n[ext.alpha]\nvalue = 2\n"),
    )
    .unwrap();
    assert_eq!(
        a.call("config.get", json!({"section":"ext"})).await["result"]["ext"]["value"],
        2
    );
    assert_eq!(
        a.call("config.get", json!({"section":"providers"})).await["result"],
        json!({"providers":[{"id":"fake","url":"http://models.fictor.internal/p/fake"}]})
    );
    std::fs::write(f.home.join("AGENTS.md"), "user instructions").unwrap();
    assert_eq!(
        a.call("config.get", json!({"section":"instructions"}))
            .await["result"]["instructions"],
        "user instructions"
    );
    error(
        &g.call(
            "events.append",
            json!({"session_id":f.session,"kind":"x.alpha.note","payload":{}}),
        )
        .await,
        "SCOPE_DENIED",
    );
    assert!(
        g.call(
            "events.append",
            json!({"session_id":"sys","kind":"x.alpha.note","payload":{}})
        )
        .await
        .get("result")
        .is_some()
    );
    first.shutdown().await.unwrap();
    second.shutdown().await.unwrap();
    global.shutdown().await.unwrap();
}

#[tokio::test]
async fn graceful_shutdown_notifies_clients_and_retains_socket_until_cleanup() {
    let f = Fixture::new().await;
    let mut server = f.server(Some(f.session.clone()), &["kv"]).await;
    let mut client = Client::new(&server).await;
    let socket = server.socket_path().to_path_buf();
    server.notify_shutdown();
    assert_eq!(client.read().await["method"], "shutdown");
    client.closed().await;
    assert!(socket.exists(), "namespace cleanup still needs the socket");
    assert!(UnixStream::connect(&socket).await.is_err());
    server.revoke();
    server.shutdown().await.unwrap();
    assert!(!socket.exists());
}

#[tokio::test]
async fn oversized_input_and_output_are_bounded_and_shutdown_revokes_idle_connections() {
    let f = Fixture::new().await;
    let mut server = f.server(Some(f.session.clone()), &["kv", "config"]).await;
    let mut c = Client::new(&server).await;
    std::fs::write(f.home.join("AGENTS.md"), "x".repeat(MAX_MESSAGE_BYTES)).unwrap();
    error(
        &c.call("config.get", json!({"section":"instructions"}))
            .await,
        "TOO_LARGE",
    );
    let mut bad = Client::new(&server).await;
    let writer = tokio::spawn(async move {
        let _ = bad
            .0
            .get_mut()
            .write_all(&vec![b'x'; MAX_MESSAGE_BYTES + 1])
            .await;
        bad
    });
    let mut bad = writer.await.unwrap();
    bad.closed().await;
    let mut idle = Client::new(&server).await;
    server.shutdown().await.unwrap();
    assert_eq!(c.read().await["method"], "shutdown");
    c.closed().await;
    assert_eq!(idle.read().await["method"], "shutdown");
    idle.closed().await;
    assert!(UnixStream::connect(server.socket_path()).await.is_err());
}

#[tokio::test]
async fn connection_limit_counts_unauthenticated_streams_and_reclaims_finished_slots() {
    let f = Fixture::new().await;
    let mut server = f.server(Some(f.session.clone()), &["kv"]).await;
    let mut clients = Vec::new();
    let mut unauthenticated = Client::raw(&server).await;
    unauthenticated.0.get_mut().write_all(b"{").await.unwrap();
    clients.push(unauthenticated);
    for _ in 0..3 {
        clients.push(Client::new(&server).await);
    }
    let mut fifth = Client::raw(&server).await;
    fifth.closed().await;
    drop(clients.remove(0));
    // Closing a peer schedules its task. Retry until that completed task has
    // been reaped rather than relying on a platform-specific scheduling delay.
    let mut replacement=tokio::time::timeout(Duration::from_secs(3),async {
        loop {
            let mut candidate=Client::raw(&server).await;
            let request=json!({"jsonrpc":"2.0","id":1,"method":"kernel.hello","params":{"protocol":1,"token":server.token()}});
            let mut frame=serde_json::to_vec(&request).unwrap();frame.push(b'\n');
            if candidate.0.get_mut().write_all(&frame).await.is_ok() {
                let mut line=String::new();
                if candidate.0.read_line(&mut line).await.is_ok_and(|n|n>0) {
                    let result:Value=serde_json::from_str(&line).unwrap();
                    if result["result"]["protocol"]==1 {break candidate;}
                }
            }
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
    assert_eq!(
        replacement.call("kv.get", json!({"key":"slot"})).await["result"]["value"],
        Value::Null
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn request_ids_preserve_decoded_unicode_null_and_original_number_tokens() {
    #[derive(serde::Deserialize)]
    struct Correlation<'a> {
        #[serde(borrow)]
        id: &'a serde_json::value::RawValue,
    }
    let f = Fixture::new().await;
    let mut server = f.server(Some(f.session.clone()), &["kv"]).await;
    let mut c = Client::raw(&server).await;
    let hello_id = "9".repeat(256);
    c.send_raw(&format!("{{\"jsonrpc\":\"2.0\",\"id\":{hello_id},\"method\":\"kernel.hello\",\"params\":{{\"protocol\":1,\"token\":\"{}\"}}}}", server.token())).await;
    let hello = c.read_raw().await;
    assert_eq!(
        serde_json::from_str::<Correlation<'_>>(&hello)
            .unwrap()
            .id
            .get(),
        hello_id
    );
    assert_eq!(
        serde_json::from_str::<Value>(&hello).unwrap()["result"]["protocol"],
        1
    );
    for id in [
        String::new(),
        "é".repeat(128),
        "😀".repeat(64),
        "\0".repeat(256),
        "\n\r\t\"\\".repeat(50),
        "é".into(),
        "e\u{301}".into(),
    ] {
        c.send(json!({"jsonrpc":"2.0","id":id,"method":"kv.get","params":{"key":"missing"}}))
            .await;
        assert_eq!(c.read().await["id"], id);
    }
    let escaped = format!("\"{}\"", "\\uD83D\\uDE00".repeat(64));
    c.send_raw(&format!("{{\"jsonrpc\":\"2.0\",\"id\":{escaped},\"method\":\"kv.get\",\"params\":{{\"key\":\"missing\"}}}}" )).await;
    assert_eq!(c.read().await["id"], "😀".repeat(64));
    let numbers = [
        "9".repeat(256),
        format!("-{}", "9".repeat(255)),
        format!("0.{}", "1".repeat(254)),
        format!("1e+{}", "9".repeat(253)),
        "90071992547409931234567890123456789".into(),
        "-0".into(),
        "-123.456e-012".into(),
        "1.000e+003".into(),
    ];
    for number in numbers {
        c.send_raw(&format!("{{\"jsonrpc\":\"2.0\",\"id\": \t{number} \t,\"method\":\"kv.get\",\"params\":{{\"key\":\"missing\"}}}}" )).await;
        let line = c.read_raw().await;
        let response: Correlation<'_> = serde_json::from_str(&line).unwrap();
        assert_eq!(
            response.id.get(),
            number,
            "numeric correlation must not round or normalize"
        );
    }
    c.send(
        json!({"jsonrpc":"2.0","id":null,"method":"kv.set","params":{"key":"null-id","value":1}}),
    )
    .await;
    let response = c.read().await;
    assert_eq!(response["id"], Value::Null);
    assert!(response.get("result").is_some());
    // A notification produces neither a reply nor a request-only KV effect.
    c.send(json!({"jsonrpc":"2.0","method":"kv.set","params":{"key":"notification","value":1}}))
        .await;
    c.send(json!({"jsonrpc":"2.0","method":"missing","params":{}}))
        .await;
    c.send(
        json!({"jsonrpc":"2.0","id":"barrier","method":"kv.get","params":{"key":"notification"}}),
    )
    .await;
    let response = c.read().await;
    assert_eq!(response["id"], "barrier");
    assert_eq!(response["result"]["value"], Value::Null);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn invalid_envelopes_preserve_only_a_unique_admitted_id_and_batches_have_no_effects() {
    let f = Fixture::new().await;
    let mut server = f.server(Some(f.session.clone()), &["kv"]).await;
    let mut c = Client::new(&server).await;
    for (body, message) in [
        (r#""jsonrpc":"2.0","method":"missing""#, "METHOD_NOT_FOUND"),
        (
            r#""jsonrpc":"2.0","method":"kv.get","params":{"extra":1}"#,
            "INVALID_PARAMS",
        ),
        (r#""jsonrpc":"wrong","method":"kv.get""#, "INVALID_REQUEST"),
        (
            r#""jsonrpc":"2.0","method":"kv.get","params":[]"#,
            "INVALID_REQUEST",
        ),
        (
            r#""jsonrpc":"2.0","method":"kv.set","method":"kv.get""#,
            "INVALID_REQUEST",
        ),
        (
            r#""jsonrpc":"2.0","method":"kv.get","params":{"key":"one","key":"two"}"#,
            "INVALID_REQUEST",
        ),
        (
            r#""jsonrpc":"2.0","method":"kv.get","extra":"private-canary""#,
            "INVALID_REQUEST",
        ),
        (
            r#""jsonrpc":"2.0","method":"kv.set","params":{"key":"refused","value":1e9999}"#,
            "INVALID_REQUEST",
        ),
    ] {
        c.send_raw(&format!("{{{body},\"id\":\"known\"}}")).await;
        let response = c.read().await;
        assert_eq!(response["id"], "known", "{body}");
        error(&response, message);
        assert!(!response.to_string().contains("private-canary"));
    }
    for id in ["true", "{}", "[]", r#"1,"i\u0064":1"#] {
        c.send_raw(&format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"kv.set\",\"params\":{{\"key\":\"refused\",\"value\":1}}}}" )).await;
        let response = c.read().await;
        assert_eq!(response["id"], Value::Null);
        error(&response, "INVALID_REQUEST");
    }
    for surrogate in [r#""\uD83D""#, r#""\uDE00""#, r#""\uD83Dx""#] {
        c.send_raw(&format!("{{\"jsonrpc\":\"2.0\",\"id\":{surrogate},\"method\":\"kv.set\",\"params\":{{\"key\":\"refused\",\"value\":1}}}}" )).await;
        let response = c.read().await;
        assert_eq!(response["id"], Value::Null);
        assert!(matches!(
            response["error"]["code"].as_i64(),
            Some(-32600 | -32700)
        ));
    }
    c.send_raw(r#"{"jsonrpc":"2.0","id":"known","method":"kv.set","params": "#)
        .await;
    let response = c.read().await;
    assert_eq!(response["id"], Value::Null);
    error(&response, "PARSE_ERROR");
    let member =
        json!({"jsonrpc":"2.0","id":1,"method":"kv.set","params":{"key":"refused","value":1}});
    for batch in [
        json!([]),
        json!([member]),
        json!([member, {"jsonrpc":"2.0","id":"x".repeat(257),"method":"kv.set","params":{"key":"refused","value":2}}]),
    ] {
        c.send(batch).await;
        let response = c.read().await;
        assert_eq!(response["id"], Value::Null);
        error(&response, "INVALID_REQUEST");
    }
    assert_eq!(
        c.call("kv.get", json!({"key":"refused"})).await["result"]["value"],
        Value::Null
    );
    let mut before_hello = Client::raw(&server).await;
    before_hello.send(json!([{"jsonrpc":"2.0","id":1,"method":"kernel.hello","params":{"protocol":1,"token":server.token()}}])).await;
    error(&before_hello.read().await, "INVALID_REQUEST");
    before_hello.closed().await;
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn excessive_ids_close_before_hello_or_dispatch_without_a_fictitious_null_reply() {
    let f = Fixture::new().await;
    let mut server = f.server(Some(f.session.clone()), &["kv"]).await;
    let ids = [
        serde_json::to_string(&"x".repeat(257)).unwrap(),
        serde_json::to_string(&format!("{}x", "é".repeat(128))).unwrap(),
        format!("\"{}x\"", "\\uD83D\\uDE00".repeat(64)),
        format!("\"{}\"", "\\u0000".repeat(257)),
        "9".repeat(257),
        format!("-{}", "9".repeat(256)),
        format!("0.{}", "1".repeat(255)),
        format!("1e-{}", "9".repeat(254)),
    ];
    for authenticated in [false, true] {
        for id in &ids {
            let mut c = if authenticated {
                Client::new(&server).await
            } else {
                Client::raw(&server).await
            };
            let (method, params) = if authenticated {
                ("kv.set", json!({"key":"refused","value":1}))
            } else {
                ("kernel.hello", json!({"protocol":1,"token":server.token()}))
            };
            c.send_raw(&format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"{method}\",\"params\":{params}}}"
            ))
            .await;
            c.closed().await;
        }
    }
    // Original ARQ-027 reproducer: ID consumes nearly an entire valid frame.
    // Repeating it still cannot dispatch the write or generate an id:null error.
    for _ in 0..2 {
        let mut c = Client::new(&server).await;
        c.send(json!({"jsonrpc":"2.0","id":"x".repeat(MAX_MESSAGE_BYTES - 256),"method":"kv.set","params":{"key":"refused","value":1}})).await;
        c.closed().await;
    }
    let mut c = Client::new(&server).await;
    assert_eq!(
        c.call("kv.get", json!({"key":"refused"})).await["result"]["value"],
        Value::Null
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn exact_input_frame_is_admitted_and_one_extra_json_byte_closes_before_write() {
    let f = Fixture::new().await;
    let mut server = f.server(Some(f.session.clone()), &["kv"]).await;
    for (extra, key) in [(0, "boundary"), (1, "refused")] {
        let mut c = Client::new(&server).await;
        let mut frame = json!({"jsonrpc":"2.0","id":"boundary","method":"kv.set","params":{"key":key,"value":1}}).to_string();
        frame.push_str(&" ".repeat(MAX_MESSAGE_BYTES + extra - frame.len()));
        if extra == 0 {
            c.send_raw(&frame).await;
            let response = c.read().await;
            assert_eq!(response["id"], "boundary");
            assert!(response.get("result").is_some());
        } else {
            // A refused frame may close while the sender is still writing LF.
            let _ =
                c.0.get_mut()
                    .write_all(format!("{frame}\n").as_bytes())
                    .await;
            c.closed().await;
        }
    }
    let mut c = Client::new(&server).await;
    assert_eq!(
        c.call("kv.get", json!({"key":"boundary"})).await["result"]["value"],
        1
    );
    assert_eq!(
        c.call("kv.get", json!({"key":"refused"})).await["result"]["value"],
        Value::Null
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn oversized_response_and_disconnected_delivery_preserve_each_committed_fork() {
    #[derive(serde::Deserialize)]
    struct Correlation<'a> {
        #[serde(borrow)]
        id: &'a serde_json::value::RawValue,
    }
    let f = Fixture::new().await;
    let mut server = f.server(Some(f.session.clone()), &["sessions", "kv"]).await;
    let mut c = Client::new(&server).await;
    let mut lost = Client::new(&server).await;
    let origin = f.append(&f.session, "fork origin").await;
    let session = f.session.clone();
    f.store
        .write(move |db| {
            db.execute(
                "UPDATE sessions SET title=?1 WHERE id=?2",
                rusqlite::params!["x".repeat(MAX_MESSAGE_BYTES), session],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let id = "90071992547409931234567890123456789.000e+004";
    c.send_raw(&format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"sessions.fork\",\"params\":{{\"from_event_id\":\"{origin}\"}}}}" )).await;
    let frame = c.read_raw().await;
    assert!(
        frame.len() <= 1608,
        "only the minimal correlated error may be delivered"
    );
    let response: Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(
        serde_json::from_str::<Correlation<'_>>(&frame)
            .unwrap()
            .id
            .get(),
        id
    );
    error(&response, "TOO_LARGE");
    // Ordered connection barrier: no second response, rollback or replay.
    c.send(json!({"jsonrpc":"2.0","id":"after-fork","method":"kv.get","params":{"key":"barrier"}}))
        .await;
    assert_eq!(c.read().await["id"], "after-fork");
    let parent = f.session.clone();
    let (sessions, audits) = f
        .store
        .write(move |db| {
            let sessions: i64 = db.query_row(
                "SELECT count(*) FROM sessions WHERE parent_session_id=?1",
                [parent],
                |r| r.get(0),
            )?;
            let audits: i64 = db.query_row(
                "SELECT count(*) FROM events WHERE kind='session.forked'",
                [],
                |r| r.get(0),
            )?;
            Ok((sessions, audits))
        })
        .await
        .unwrap();
    assert_eq!((sessions, audits), (1, 1));

    let session = f.session.clone();
    f.store
        .write(move |db| {
            db.execute(
                "UPDATE sessions SET title=?1 WHERE id=?2",
                rusqlite::params!["x".repeat(MAX_MESSAGE_BYTES - 4096), session],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    // The second reply fits but cannot be consumed: confirm its transaction
    // before dropping a client that never reads any part of that large result.
    lost.send(json!({"jsonrpc":"2.0","id":"undelivered","method":"sessions.fork","params":{"from_event_id":origin}})).await;
    let child = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let parent = f.session.clone();
            let ids = f
                .store
                .write(move |db| {
                    let mut query = db.prepare(
                        "SELECT id FROM sessions WHERE parent_session_id=?1 ORDER BY id",
                    )?;
                    Ok(query
                        .query_map([parent], |r| r.get::<_, String>(0))?
                        .collect::<Result<Vec<_>, _>>()?)
                })
                .await
                .unwrap();
            if ids.len() == 2 {
                break ids[1].clone();
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let committed = f.store.session(child).await.unwrap();
    assert!(
        json!({"jsonrpc":"2.0","id":"undelivered","result":committed})
            .to_string()
            .len()
            <= MAX_MESSAGE_BYTES
    );
    drop(lost);
    server.shutdown().await.unwrap();
    let (sessions, audits) = f
        .store
        .write(move |db| {
            let sessions: i64 = db.query_row(
                "SELECT count(*) FROM sessions WHERE parent_session_id=?1",
                [f.session.clone()],
                |r| r.get(0),
            )?;
            let audits: i64 = db.query_row(
                "SELECT count(*) FROM events WHERE kind='session.forked'",
                [],
                |r| r.get(0),
            )?;
            Ok((sessions, audits))
        })
        .await
        .unwrap();
    assert_eq!(
        (sessions, audits),
        (2, 2),
        "neither delivery failure may roll back or replay an admitted fork"
    );
}
