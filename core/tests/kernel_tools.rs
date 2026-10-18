use fictor::{
    config::Mode,
    gateway::PinnedCatalog,
    kernel::{KernelIdentity, KernelServer},
    store::{NewSession, Store, Trust},
};
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

async fn session(store: &Store, workspace: &Path) -> String {
    store
        .create_session(NewSession {
            title: "registry".into(),
            workspace: workspace.into(),
            workspace_trust: Trust::Trusted,
            harness: "client".into(),
            mode: Mode::Default,
            model: None,
        })
        .await
        .unwrap()
        .id
}

fn lock(home: &Path) {
    let key = "1.0.0-aaaaaaaaaaaa";
    let relative = format!("store/example/{key}");
    let bundle = home.join("extensions").join(&relative);
    fs::create_dir_all(&bundle).unwrap();
    let manifest=b"schema: 1\nid: example\nversion: 1.0.0\ndescription: Registry fixture\nscope: session\nruntime:\n  kind: binary\n  entry: does-not-exist\ntools:\n  echo:\n    effect: read\n    sensitivity: public\n";
    let manifest_path = bundle.join("fictor.yaml");
    fs::write(&manifest_path, manifest).unwrap();
    fs::set_permissions(manifest_path, fs::Permissions::from_mode(0o444)).unwrap();
    let tools =
        vec![json!({"name":"echo","description":"Pinned echo","inputSchema":{"type":"object"}})];
    let catalog = PinnedCatalog::new(tools.clone()).unwrap();
    let value = json!({"schema":1,"runtimes":{},"extensions":{"example":{
        "enabled":true,"active":key,"versions":{key:{
            "version":"1.0.0","hash":format!("sha256:{}","a".repeat(64)),"path":relative,
            "source":{"kind":"local"},"approved":{"by":"user","at":"2026-10-18T12:00:00Z","approval_id":null},
            "overrides":{"permissions":{},"tools":{}},"privileges":[],"tools":tools,
            "tools_hash":catalog.hash(),"packages":[],"audit":null
        }}
    }}});
    let path = home.join("extensions/lock.json");
    fs::write(&path, value.to_string()).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

async fn call(client: &mut BufReader<UnixStream>, method: &str, params: Value) -> Value {
    let mut frame =
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .unwrap();
    frame.push(b'\n');
    client.get_mut().write_all(&frame).await.unwrap();
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    serde_json::from_str(&line).unwrap()
}

async fn client(
    home: &Path,
    store: Arc<Store>,
    id: &str,
    scopes: &[&str],
) -> (KernelServer, BufReader<UnixStream>) {
    let server = KernelServer::bind(
        home,
        KernelIdentity {
            ext_id: "client".into(),
            instance_id: ulid::Ulid::generate().to_string(),
            session_id: Some(id.into()),
            is_harness: true,
            scopes: scopes.iter().map(|scope| (*scope).into()).collect(),
        },
        store,
        vec![],
    )
    .await
    .unwrap();
    let mut socket = BufReader::new(UnixStream::connect(server.socket_path()).await.unwrap());
    let hello = call(
        &mut socket,
        "kernel.hello",
        json!({"protocol":1,"token":server.token()}),
    )
    .await;
    assert_eq!(hello["result"]["protocol"], 1);
    (server, socket)
}

#[tokio::test]
async fn tools_list_reads_the_pin_without_running_code_and_enforces_session_and_scope() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("h");
    let workspace = root.path().join("w");
    fs::create_dir(&workspace).unwrap();
    fictor::initialize(&home).await.unwrap();
    let store = Arc::new(Store::open(&home).await.unwrap());
    let id = session(&store, &workspace).await;
    let other = session(&store, &workspace).await;
    lock(&home);
    // The manifest entry does not exist: successful listing cannot spawn it.
    let (mut server, mut socket) = client(&home, store.clone(), &id, &["tools"]).await;
    let response = call(&mut socket, "tools.list", json!({"session_id":id})).await;
    assert_eq!(
        response["result"],
        json!({"tools":[{
            "name":"example__echo","description":"Pinned echo","input_schema":{"type":"object"},
            "effect":"read","sensitivity":"public"
        }]})
    );
    assert_eq!(
        call(&mut socket, "tools.list", json!({"session_id":other})).await["error"]["code"],
        -32002
    );
    assert_eq!(
        call(
            &mut socket,
            "tools.list",
            json!({"session_id":id,"extra":true})
        )
        .await["error"]["code"],
        -32602
    );
    assert_eq!(
        call(&mut socket, "tools.list", json!({"session_id":"invalid"})).await["error"]["code"],
        -32602
    );
    assert_eq!(
        call(&mut socket, "tools.call", json!({"session_id":id})).await["error"]["code"],
        -32601
    );
    let (mut no_scope, mut denied) = client(&home, store, &id, &["kv"]).await;
    assert_eq!(
        call(&mut denied, "tools.list", json!({"session_id":id})).await["error"]["code"],
        -32002
    );
    no_scope.shutdown().await.unwrap();
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn missing_lock_is_empty_but_broken_active_state_is_an_error() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("h");
    let workspace = root.path().join("w");
    fs::create_dir(&workspace).unwrap();
    fictor::initialize(&home).await.unwrap();
    fs::remove_file(home.join("extensions/lock.json")).unwrap();
    let store = Arc::new(Store::open(&home).await.unwrap());
    let id = session(&store, &workspace).await;
    let (mut server, mut socket) = client(&home, store, &id, &["tools"]).await;
    assert_eq!(
        call(&mut socket, "tools.list", json!({"session_id":id})).await["result"],
        json!({"tools":[]})
    );
    lock(&home);
    fs::write(home.join("extensions/lock.json"), b"broken").unwrap();
    let error = call(&mut socket, "tools.list", json!({"session_id":id})).await;
    assert_eq!(error["error"]["code"], -32603);
    assert!(error.get("result").is_none());
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn discovery_waits_for_the_installers_snapshot_section() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    fictor::initialize(&home).await.unwrap();
    let store = Arc::new(Store::open(&home).await.unwrap());
    let id = session(&store, &workspace).await;
    let (mut server, mut socket) = client(&home, store.clone(), &id, &["tools", "catalog"]).await;
    for method in ["tools.list", "catalog.list"] {
        let section = store.owner().installer_gate().lock_owned().await;
        socket
            .get_mut()
            .write_all(
                format!(
                    "{}\n",
                    json!({"jsonrpc":"2.0","id":1,"method":method,"params":{"session_id":id}})
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut line = String::new();
        assert!(
            tokio::time::timeout(Duration::from_millis(75), socket.read_line(&mut line))
                .await
                .is_err()
        );
        // Publish while the reader is excluded. It must see the complete new
        // committed snapshot, rather than the previously empty registry.
        if method == "tools.list" {
            lock(&home);
        } else {
            fs::write(
                home.join("extensions/lock.json"),
                serde_json::to_vec(&fictor::installer::lock::Lock::default()).unwrap(),
            )
            .unwrap();
        }
        drop(section);
        tokio::time::timeout(Duration::from_secs(5), socket.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        let response: Value = serde_json::from_str(&line).unwrap();
        assert!(response.get("result").is_some(), "{response}");
        if method == "tools.list" {
            assert_eq!(response["result"]["tools"][0]["name"], "example__echo");
        }
    }
    server.shutdown().await.unwrap();
}
