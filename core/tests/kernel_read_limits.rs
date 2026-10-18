use fictor::{
    config::Mode,
    kernel::{KernelIdentity, KernelServer, MAX_MESSAGE_BYTES},
    store::{AppendEvent, NewSession, Provenance, Sensitivity, Store, StoreError, Trust},
};
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

struct Fixture {
    _root: tempfile::TempDir,
    home: PathBuf,
    store: Arc<Store>,
    session: String,
}
impl Fixture {
    async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("h");
        let workspace = root.path().join("w");
        std::fs::create_dir(&workspace).unwrap();
        fictor::initialize(&home).await.unwrap();
        let store = Arc::new(Store::open(&home).await.unwrap());
        let session = store
            .create_session(NewSession {
                title: "read limits".into(),
                workspace,
                workspace_trust: Trust::Trusted,
                harness: "client".into(),
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
    async fn client(&self, scopes: &[&str]) -> (KernelServer, BufReader<UnixStream>) {
        let server = KernelServer::bind(
            &self.home,
            KernelIdentity {
                ext_id: "client".into(),
                instance_id: ulid::Ulid::generate().to_string(),
                session_id: Some(self.session.clone()),
                is_harness: false,
                scopes: scopes.iter().map(|scope| (*scope).into()).collect(),
            },
            self.store.clone(),
            vec![],
        )
        .await
        .unwrap();
        let mut client = BufReader::new(UnixStream::connect(server.socket_path()).await.unwrap());
        assert_eq!(
            call(
                &mut client,
                "kernel.hello",
                json!({"protocol":1,"token":server.token()})
            )
            .await["result"]["protocol"],
            1
        );
        (server, client)
    }
}
async fn call(client: &mut BufReader<UnixStream>, method: &str, params: Value) -> Value {
    let mut frame =
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .unwrap();
    frame.push(b'\n');
    client.get_mut().write_all(&frame).await.unwrap();
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(20), client.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    serde_json::from_str(&line).unwrap()
}
fn too_large(response: Value) {
    assert_eq!(response["error"]["message"], "TOO_LARGE");
    assert!(response.get("result").is_none());
    assert!(response.to_string().len() < 200);
}

#[tokio::test]
async fn kv_list_counts_escaped_keys_and_stops_before_decoding_later_rows() {
    let fixture = Fixture::new().await;
    let namespace = format!("client@{}", fixture.session);
    for prefix in ["a", "b"] {
        // Raw keys total <3 MiB, but their JSON-escaped form exceeds16MiB.
        fixture
            .store
            .kv_set(
                namespace.clone(),
                format!("{prefix}{}", "\u{1}".repeat(1_400_000)),
                json!(null),
            )
            .await
            .unwrap();
    }
    fixture
        .store
        .kv_set(namespace.clone(), "small".into(), json!({"ok":true}))
        .await
        .unwrap();
    let bad_namespace = namespace.clone();
    fixture
        .store
        .write(move |db| {
            db.execute(
                "INSERT INTO kv(ns,key,value,updated_at) VALUES (?1,'z-later','not JSON',0)",
                [bad_namespace],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    // This verifies the malformed later row really is observable to an unlimited
    // read. Kernel overflow must stop before reaching it, yielding TooLarge.
    assert!(matches!(
        fixture.store.kv_list(namespace, String::new(), 10).await,
        Err(StoreError::Json(_))
    ));
    let (mut server, mut client) = fixture.client(&["kv"]).await;
    too_large(call(&mut client, "kv.list", json!({"limit":10})).await);
    assert_eq!(
        call(&mut client, "kv.list", json!({"prefix":"small"})).await["result"],
        json!({"items":[{"key":"small","value":{"ok":true}}]})
    );
    assert_eq!(
        call(&mut client, "kv.list", json!({"limit":10001})).await["error"]["message"],
        "INVALID_PARAMS"
    );
    let (mut denied_server, mut denied) = fixture.client(&["events.read"]).await;
    assert_eq!(
        call(&mut denied, "kv.list", json!({})).await["error"]["message"],
        "SCOPE_DENIED"
    );
    denied_server.shutdown().await.unwrap();
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn event_path_and_query_bound_inline_payloads_without_losing_authorization_or_order() {
    let fixture = Fixture::new().await;
    let mut ids = Vec::new();
    for index in 0..285 {
        let event = fixture
            .store
            .append(AppendEvent {
                session_id: fixture.session.clone(),
                parent_id: None,
                kind: "x.client.note".into(),
                actor: "core".into(),
                payload: json!({"index":index,"text":"\u{1}".repeat(10_000)}),
                blob_refs: vec![],
                provenance: Provenance {
                    trust: Trust::Trusted,
                    sensitivity: Sensitivity::Public,
                    source: "core".into(),
                },
            })
            .await
            .unwrap();
        assert!(event.payload.get("$blob").is_none());
        ids.push(event.id);
    }
    let (mut server, mut client) = fixture.client(&["events.read"]).await;
    too_large(
        call(
            &mut client,
            "events.path",
            json!({"session_id":fixture.session,"limit":10000}),
        )
        .await,
    );
    too_large(
        call(
            &mut client,
            "events.query",
            json!({"limit":500,"kinds":["x.client.note"]}),
        )
        .await,
    );
    let path = call(
        &mut client,
        "events.path",
        json!({"session_id":fixture.session,"limit":2}),
    )
    .await;
    assert_eq!(path["result"]["truncated"], true);
    assert_eq!(path["result"]["events"][0]["id"], ids[283]);
    assert_eq!(path["result"]["events"][1]["id"], ids[284]);
    let query = call(
        &mut client,
        "events.query",
        json!({"limit":2,"kinds":["x.client.note"]}),
    )
    .await;
    assert_eq!(query["result"]["events"][0]["id"], ids[284]);
    assert_eq!(query["result"]["events"][1]["id"], ids[283]);
    for method in ["events.path", "events.query"] {
        assert_eq!(
            call(
                &mut client,
                method,
                json!({"session_id":ulid::Ulid::generate().to_string()})
            )
            .await["error"]["message"],
            "SCOPE_DENIED"
        );
    }
    let (mut denied_server, mut denied) = fixture.client(&["kv"]).await;
    assert_eq!(
        call(
            &mut denied,
            "events.path",
            json!({"session_id":fixture.session})
        )
        .await["error"]["message"],
        "SCOPE_DENIED"
    );
    denied_server.shutdown().await.unwrap();
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn blobs_get_caps_bytes_before_base64_and_preserves_small_reads_and_scope() {
    let fixture = Fixture::new().await;
    let large = fixture
        .store
        .put_blob(vec![b'x'; MAX_MESSAGE_BYTES / 4 * 3 + 1])
        .await
        .unwrap();
    let small = fixture
        .store
        .put_blob(b"small\0bytes".to_vec())
        .await
        .unwrap();
    let (mut server, mut client) = fixture.client(&["blobs"]).await;
    too_large(call(&mut client, "blobs.get", json!({"hash":large})).await);
    assert_eq!(
        call(&mut client, "blobs.get", json!({"hash":small})).await["result"],
        json!({"base64":"c21hbGwAYnl0ZXM=","size":11})
    );
    let (mut denied_server, mut denied) = fixture.client(&["kv"]).await;
    assert_eq!(
        call(&mut denied, "blobs.get", json!({"hash":small})).await["error"]["message"],
        "SCOPE_DENIED"
    );
    denied_server.shutdown().await.unwrap();
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn instructions_bound_local_file_before_decoding_and_preserve_optional_text() {
    let fixture = Fixture::new().await;
    let (mut server, mut client) = fixture.client(&["config"]).await;
    assert_eq!(
        call(&mut client, "config.get", json!({"section":"instructions"})).await["result"],
        json!({"instructions":null})
    );
    let path = fixture.home.join("AGENTS.md");
    std::fs::write(&path, "Instruções: ação, \"texto\".\n").unwrap();
    assert_eq!(
        call(&mut client, "config.get", json!({"section":"instructions"})).await["result"],
        json!({"instructions":"Instruções: ação, \"texto\".\n"})
    );
    std::fs::write(&path, [0xff]).unwrap();
    let oversized = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    oversized.set_len(MAX_MESSAGE_BYTES as u64 + 1).unwrap();
    // The oversized file is refused before UTF-8 decoding, rather than loaded
    // in full and returned as an unrelated INTERNAL_ERROR.
    too_large(call(&mut client, "config.get", json!({"section":"instructions"})).await);
    oversized.set_len(1).unwrap();
    assert_eq!(
        call(&mut client, "config.get", json!({"section":"instructions"})).await["error"]["message"],
        "INTERNAL_ERROR"
    );
    std::fs::remove_file(&path).unwrap();
    assert_eq!(
        call(&mut client, "config.get", json!({"section":"instructions"})).await["result"],
        json!({"instructions":null})
    );
    server.shutdown().await.unwrap();
}

#[test]
fn config_sources_refuse_special_files_without_stalling_kernel_shutdown() {
    const CHILD: &str = "FICTOR_CONFIG_SPECIAL_FILE_CHILD";
    if std::env::var_os(CHILD).is_some() {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            let fixture = Fixture::new().await;
            let (mut server, mut client) = fixture.client(&["config"]).await;
            for (section, filename) in [("instructions", "AGENTS.md"), ("ext", "config.toml")] {
                for indirect in [false, true] {
                    let path = fixture.home.join(filename);
                    if std::fs::symlink_metadata(&path).is_ok() { std::fs::remove_file(&path).unwrap(); }
                    let target = if indirect { fixture._root.path().join(format!("{filename}.fifo")) } else { path.clone() };
                    let name = std::ffi::CString::new(target.as_os_str().as_encoded_bytes()).unwrap();
                    // SAFETY: this isolated fixture owns the NUL-terminated path.
                    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                    if indirect { std::os::unix::fs::symlink(&target, &path).unwrap(); }
                    let response = tokio::time::timeout(Duration::from_secs(1), call(&mut client, "config.get", json!({"section":section}))).await.expect("special-file read held a Kernel worker");
                    assert_eq!(response["error"]["message"], "INTERNAL_ERROR");
                    assert!(response.get("result").is_none());
                    if indirect { std::fs::remove_file(&path).unwrap(); }
                    std::fs::remove_file(&target).unwrap();
                    assert_eq!(call(&mut client, "config.get", json!({"section":"providers"})).await["result"], json!({"providers":[]}));
                }
                for target in [std::path::Path::new("/dev/null"), std::path::Path::new("/dev/zero"), fixture._root.path()] {
                    let path = fixture.home.join(filename);
                    std::os::unix::fs::symlink(target, &path).unwrap();
                    let response = tokio::time::timeout(Duration::from_secs(1), call(&mut client, "config.get", json!({"section":section}))).await.unwrap();
                    assert_eq!(response["error"]["message"], "INTERNAL_ERROR");
                    assert!(response.get("result").is_none());
                    std::fs::remove_file(path).unwrap();
                }
            }
            tokio::time::timeout(Duration::from_secs(1), server.shutdown()).await.unwrap().unwrap();
        });
        return;
    }
    // A pre-fix blocking File::open also prevents Tokio runtime shutdown after
    // the request times out. Isolate it so a regression cannot hang cargo test.
    let root = tempfile::Builder::new()
        .prefix("cfg-")
        .tempdir_in("/tmp")
        .unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "config_sources_refuse_special_files_without_stalling_kernel_shutdown",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env("TMPDIR", root.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "Kernel config read stalled its isolated process: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn config_regular_file_symlinks_reload_only_the_authenticated_table() {
    let fixture = Fixture::new().await;
    let instructions = fixture._root.path().join("user-instructions.md");
    let config = fixture._root.path().join("user-config.toml");
    std::fs::write(&instructions, "Instruções do usuário: ação.\n").unwrap();
    std::fs::write(
        &config,
        "[ext.client]\nvalue = 'first'\n[ext.other]\nsecret = 'private-marker'\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(&instructions, fixture.home.join("AGENTS.md")).unwrap();
    std::fs::remove_file(fixture.home.join("config.toml")).unwrap();
    std::os::unix::fs::symlink(&config, fixture.home.join("config.toml")).unwrap();
    let (mut server, mut client) = fixture.client(&["config"]).await;
    assert_eq!(
        call(&mut client, "config.get", json!({"section":"instructions"})).await["result"],
        json!({"instructions":"Instruções do usuário: ação.\n"})
    );
    assert_eq!(
        call(&mut client, "config.get", json!({"section":"ext"})).await["result"],
        json!({"ext":{"value":"first"}})
    );
    std::fs::write(
        &config,
        "[ext.client]\nvalue = 'second'\n[ext.other]\nsecret = 'private-marker'\n",
    )
    .unwrap();
    let response = call(&mut client, "config.get", json!({"section":"ext"})).await;
    assert_eq!(response["result"], json!({"ext":{"value":"second"}}));
    assert!(!response.to_string().contains("private-marker"));
    assert_eq!(
        call(
            &mut client,
            "config.get",
            json!({"section":"ext","ext_id":"other"})
        )
        .await["error"]["message"],
        "INVALID_PARAMS"
    );
    std::fs::remove_file(&instructions).unwrap();
    assert_eq!(
        call(&mut client, "config.get", json!({"section":"instructions"})).await["result"],
        json!({"instructions":null})
    );
    server.shutdown().await.unwrap();
}
