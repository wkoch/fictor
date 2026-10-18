use fictor::{
    config::Mode,
    kernel::{KernelIdentity, KernelServer, MAX_MESSAGE_BYTES},
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
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(5), self.0.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        assert!(n > 0);
        serde_json::from_str(&line).unwrap()
    }
    async fn closed(&mut self) {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(3), self.0.read_line(&mut line))
            .await
            .unwrap();
        assert!(matches!(n, Ok(0) | Err(_)));
    }
}
fn error(value: &Value, name: &str) {
    assert_eq!(value["error"]["message"], name);
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
    error(&bad.read().await, "TOO_LARGE");
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
