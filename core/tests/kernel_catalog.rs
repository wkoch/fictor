use fictor::{
    config::Mode,
    gateway::PinnedCatalog,
    kernel::{KernelIdentity, KernelServer},
    store::{NewSession, Store, Trust},
};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

struct Fixture {
    _root: tempfile::TempDir,
    home: PathBuf,
    bundle: PathBuf,
    store: Arc<Store>,
    session: String,
}
impl Fixture {
    async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("h");
        let workspace = root.path().join("w");
        fs::create_dir(&workspace).unwrap();
        fictor::initialize(&home).await.unwrap();
        let store = Arc::new(Store::open(&home).await.unwrap());
        let session = store
            .create_session(NewSession {
                title: "catalog".into(),
                workspace,
                workspace_trust: Trust::Trusted,
                harness: "client".into(),
                mode: Mode::Default,
                model: None,
            })
            .await
            .unwrap()
            .id;
        let key = "1.0.0-aaaaaaaaaaaa";
        let relative = format!("store/example/{key}");
        let bundle = home.join("extensions").join(&relative);
        fs::create_dir_all(bundle.join("skills/advice")).unwrap();
        fs::create_dir_all(bundle.join("prompts")).unwrap();
        fs::write(bundle.join("skills/advice/SKILL.md"), b"---\nname: advice\ndescription: Gives useful advice\nmetadata:\n  author: Fictor\nallowed-tools: Bash(*)\n---\n\xff\x00This body must not be parsed or returned.").unwrap();
        fs::write(bundle.join("skills/README.md"), b"Collection documentation").unwrap();
        fs::write(
            bundle.join("prompts/hello.md"),
            b"Unparsed command body: $ARGUMENTS \xff",
        )
        .unwrap();
        let manifest = json!({"schema":1,"id":"example","version":"1.0.0","description":"Catalog fixture",
            "scope":"session","runtime":{"kind":"binary","entry":"never-executed"},
            "commands":[{"name":"hello","description":"Say hello","prompt":"prompts/hello.md"}]
        });
        fs::write(bundle.join("fictor.yaml"), manifest.to_string()).unwrap();
        freeze(&bundle);
        let value = json!({"schema":1,"runtimes":{},"extensions":{"example":{
            "enabled":true,"active":key,"versions":{key:{
                "version":"1.0.0","hash":format!("sha256:{}","a".repeat(64)),"path":relative,
                "source":{"kind":"local"},"approved":{"by":"user","at":"2026-10-18T12:00:00Z","approval_id":null},
                "overrides":{"permissions":{},"tools":{}},"privileges":[],"tools":[],
                "tools_hash":PinnedCatalog::new(vec![]).unwrap().hash(),"packages":[],"audit":null
            }}
        }}});
        fs::write(home.join("extensions/lock.json"), value.to_string()).unwrap();
        fs::set_permissions(
            home.join("extensions/lock.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        Self {
            _root: root,
            home,
            bundle,
            store,
            session,
        }
    }
    fn manifest(&self) -> Value {
        serde_json::from_slice(&fs::read(self.bundle.join("fictor.yaml")).unwrap()).unwrap()
    }
    fn set_manifest(&self, value: &Value) {
        self.set_file("fictor.yaml", value.to_string().as_bytes());
    }
    fn set_file(&self, path: &str, bytes: &[u8]) {
        let path = self.bundle.join(path);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
    }
    fn edit_lock(&self, edit: impl FnOnce(&mut Value)) {
        let path = self.home.join("extensions/lock.json");
        let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        edit(&mut value);
        fs::write(path, value.to_string()).unwrap();
    }
    async fn client(&self, scopes: &[&str]) -> (KernelServer, BufReader<UnixStream>) {
        let server = KernelServer::bind(
            &self.home,
            KernelIdentity {
                ext_id: "client".into(),
                instance_id: ulid::Ulid::generate().to_string(),
                session_id: Some(self.session.clone()),
                is_harness: true,
                scopes: scopes.iter().map(|scope| (*scope).into()).collect(),
            },
            self.store.clone(),
            vec![],
        )
        .await
        .unwrap();
        let mut socket = BufReader::new(UnixStream::connect(server.socket_path()).await.unwrap());
        assert_eq!(
            call(
                &mut socket,
                "kernel.hello",
                json!({"protocol":1,"token":server.token()})
            )
            .await["result"]["protocol"],
            1
        );
        (server, socket)
    }
}
fn freeze(path: &Path) {
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            freeze(&entry.path());
        } else {
            fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o444)).unwrap();
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o555)).unwrap();
}
async fn call(client: &mut BufReader<UnixStream>, method: &str, params: Value) -> Value {
    let mut frame =
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .unwrap();
    frame.push(b'\n');
    client.get_mut().write_all(&frame).await.unwrap();
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(10), client.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    serde_json::from_str(&line).unwrap()
}

#[tokio::test]
async fn catalog_uses_active_metadata_and_absolute_store_paths_without_running_code() {
    let fixture = Fixture::new().await;
    let inactive_key = "0.9.0-bbbbbbbbbbbb";
    let inactive = fixture
        .home
        .join("extensions/store/example")
        .join(inactive_key);
    fs::create_dir(&inactive).unwrap();
    fs::write(
        inactive.join("fictor.yaml"),
        b"Inactive manifest is never read",
    )
    .unwrap();
    freeze(&inactive);
    fixture.edit_lock(|value| {
        let versions = &mut value["extensions"]["example"]["versions"];
        let mut old = versions["1.0.0-aaaaaaaaaaaa"].clone();
        old["version"] = "0.9.0".into();
        old["hash"] = format!("sha256:{}", "b".repeat(64)).into();
        old["path"] = format!("store/example/{inactive_key}").into();
        versions[inactive_key] = old;
    });
    let (mut server, mut socket) = fixture.client(&["catalog"]).await;
    let expected = json!({
        "skills":[{"ext_id":"example","name":"advice","description":"Gives useful advice","path":fixture.bundle.join("skills/advice/SKILL.md")}],
        "commands":[{"ext_id":"example","name":"hello","description":"Say hello","prompt_path":fixture.bundle.join("prompts/hello.md")}],
        "surfaces":[],"hooks":{}
    });
    let response = call(
        &mut socket,
        "catalog.list",
        json!({"session_id":fixture.session}),
    )
    .await;
    assert_eq!(response["result"], expected);
    // Entry never existed, and invalid UTF-8 bodies never reach the response.
    assert!(!fixture.bundle.join("never-executed").exists());
    let mut manifest = fixture.manifest();
    manifest["runtime"] = json!({"kind":"none"});
    manifest["scope"] = "global".into();
    manifest["skills"] = "library".into();
    fs::set_permissions(&fixture.bundle, fs::Permissions::from_mode(0o755)).unwrap();
    fs::rename(
        fixture.bundle.join("skills"),
        fixture.bundle.join("library"),
    )
    .unwrap();
    fs::set_permissions(&fixture.bundle, fs::Permissions::from_mode(0o555)).unwrap();
    fixture.set_manifest(&manifest);
    let response = call(
        &mut socket,
        "catalog.list",
        json!({"session_id":fixture.session}),
    )
    .await;
    assert_eq!(
        response["result"]["skills"][0]["path"],
        fixture
            .bundle
            .join("library/advice/SKILL.md")
            .to_str()
            .unwrap()
    );
    fixture.edit_lock(|value| value["extensions"]["example"]["enabled"] = false.into());
    fixture.set_file(
        "fictor.yaml",
        b"invalid active manifest is not read for disabled extensions",
    );
    assert_eq!(
        call(
            &mut socket,
            "catalog.list",
            json!({"session_id":fixture.session})
        )
        .await["result"],
        json!({"skills":[],"commands":[],"surfaces":[],"hooks":{}})
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn catalog_enforces_scope_session_and_exact_params_before_discovery() {
    let fixture = Fixture::new().await;
    let (mut server, mut socket) = fixture.client(&["catalog"]).await;
    for params in [
        json!({}),
        json!({"session_id":fixture.session,"extra":true}),
        json!({"session_id":"invalid"}),
        json!({"session_id":null}),
    ] {
        assert_eq!(
            call(&mut socket, "catalog.list", params).await["error"]["code"],
            -32602
        );
    }
    assert_eq!(
        call(
            &mut socket,
            "catalog.list",
            json!({"session_id":ulid::Ulid::generate().to_string()})
        )
        .await["error"]["code"],
        -32002
    );
    let (mut denied_server, mut denied) = fixture.client(&["kv"]).await;
    assert_eq!(
        call(
            &mut denied,
            "catalog.list",
            json!({"session_id":fixture.session})
        )
        .await["error"]["code"],
        -32002
    );
    denied_server.shutdown().await.unwrap();
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn malformed_skill_metadata_fails_without_partial_catalog_or_private_error_details() {
    let fixture = Fixture::new().await;
    let (mut server, mut socket) = fixture.client(&["catalog"]).await;
    for content in [
        "No frontmatter",
        "---\nname: advice\ndescription: private-marker\nname: advice\n---\n",
        "---\nname: !!str advice\ndescription: private-marker\n---\n",
        "---\nname: different\ndescription: private-marker\n---\n",
        "---\nname: advice\ndescription: private-marker\nunknown: value\n---\n",
        "---\nname: advice\ndescription: ' '\n---\n",
        "---\nname: advice\ndescription: private-marker\n",
    ] {
        fixture.set_file("skills/advice/SKILL.md", content.as_bytes());
        let response = call(
            &mut socket,
            "catalog.list",
            json!({"session_id":fixture.session}),
        )
        .await;
        assert_eq!(response["error"]["code"], -32603);
        assert!(response.get("result").is_none());
        assert!(!response.to_string().contains("private-marker"));
        assert!(
            !response
                .to_string()
                .contains(fixture.home.to_str().unwrap())
        );
    }
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn symlinked_and_mutable_catalog_content_is_rejected_without_following_it() {
    for relative in [
        "skills",
        "skills/advice",
        "skills/advice/SKILL.md",
        "prompts",
        "prompts/hello.md",
    ] {
        let fixture = Fixture::new().await;
        let (mut server, mut socket) = fixture.client(&["catalog"]).await;
        let target = fixture.bundle.join(relative);
        let parent = target.parent().unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755)).unwrap();
        let saved = target.with_extension("saved");
        fs::rename(&target, &saved).unwrap();
        std::os::unix::fs::symlink(&saved, &target).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o555)).unwrap();
        let response = call(
            &mut socket,
            "catalog.list",
            json!({"session_id":fixture.session}),
        )
        .await;
        assert_eq!(response["error"]["code"], -32603, "{relative}");
        assert!(saved.exists());
        server.shutdown().await.unwrap();
    }
    let fixture = Fixture::new().await;
    let (mut server, mut socket) = fixture.client(&["catalog"]).await;
    for path in [
        fixture.bundle.join("skills/advice/SKILL.md"),
        fixture.bundle.join("prompts/hello.md"),
        fixture.bundle.clone(),
    ] {
        let old = fs::metadata(&path).unwrap().permissions();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            call(
                &mut socket,
                "catalog.list",
                json!({"session_id":fixture.session})
            )
            .await["error"]["code"],
            -32603
        );
        fs::set_permissions(path, old).unwrap();
    }
    let prompt = fixture.bundle.join("prompts/hello.md");
    let parent = prompt.parent().unwrap();
    fs::set_permissions(parent, fs::Permissions::from_mode(0o755)).unwrap();
    fs::remove_file(&prompt).unwrap();
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let prompt_name = CString::new(prompt.as_os_str().as_bytes()).unwrap();
    // SAFETY: the temporary fixture owns the NUL-terminated path, with no links.
    assert_eq!(unsafe { libc::mkfifo(prompt_name.as_ptr(), 0o444) }, 0);
    fs::set_permissions(parent, fs::Permissions::from_mode(0o555)).unwrap();
    assert_eq!(
        call(
            &mut socket,
            "catalog.list",
            json!({"session_id":fixture.session})
        )
        .await["error"]["code"],
        -32603
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn invalid_identity_phase_one_declarations_and_invalid_overrides_fail_closed() {
    let fixture = Fixture::new().await;
    let (mut server, mut socket) = fixture.client(&["catalog"]).await;
    let original = fixture.manifest();
    for (key, value) in [
        ("id", json!("different")),
        ("version", json!("2.0.0")),
        ("scope", json!("global")),
        (
            "surfaces",
            json!([{"id":"panel","slot":"right","resource":"ui://example/panel","title":"Panel"}]),
        ),
        ("hooks", json!([{"point":"tool.after"}])),
        ("skills", json!("missing")),
        (
            "commands",
            json!([{"name":"bad","description":"Bad","prompt":"../private"}]),
        ),
    ] {
        let mut manifest = original.clone();
        manifest[key] = value;
        if key == "hooks" {
            manifest["hooks_api"] = 1.into();
        }
        fixture.set_manifest(&manifest);
        assert_eq!(
            call(
                &mut socket,
                "catalog.list",
                json!({"session_id":fixture.session})
            )
            .await["error"]["code"],
            -32603,
            "{key}"
        );
    }
    fixture.set_manifest(&original);
    fixture.edit_lock(|value| value["extensions"]["example"]["versions"]["1.0.0-aaaaaaaaaaaa"]["overrides"]["permissions"] = json!({"fs":{"read":[]}}));
    let valid = call(
        &mut socket,
        "catalog.list",
        json!({"session_id":fixture.session}),
    )
    .await;
    assert!(valid.get("result").is_some(), "{valid}");
    fixture.edit_lock(|value| value["extensions"]["example"]["versions"]["1.0.0-aaaaaaaaaaaa"]["overrides"]["permissions"] = json!({"fs":{"read":["${workspace}"]}}));
    assert_eq!(
        call(
            &mut socket,
            "catalog.list",
            json!({"session_id":fixture.session})
        )
        .await["error"]["code"],
        -32603
    );
    fs::write(fixture.home.join("extensions/lock.json"), b"broken").unwrap();
    assert_eq!(
        call(
            &mut socket,
            "catalog.list",
            json!({"session_id":fixture.session})
        )
        .await["error"]["code"],
        -32603
    );
    fs::remove_file(fixture.home.join("extensions/lock.json")).unwrap();
    assert_eq!(
        call(
            &mut socket,
            "catalog.list",
            json!({"session_id":fixture.session})
        )
        .await["result"],
        json!({"skills":[],"commands":[],"surfaces":[],"hooks":{}})
    );
    server.shutdown().await.unwrap();
}
