use fictor::{
    config::{Config, Mode},
    home,
    installer::manifest::{Manifest, ManifestError},
    proxy::EgressProxy,
    secrets::{BackendKind, Redactor, SecretStore},
    store::{EventQuery, NewSession, Store, Trust},
    supervisor::{Supervisor, SupervisorError},
};
use serde_json::json;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

struct Fixture {
    _root: tempfile::TempDir,
    home: PathBuf,
    workspace: PathBuf,
    real_home: PathBuf,
    store: Arc<Store>,
    secrets: Arc<SecretStore>,
    proxy: Arc<EgressProxy>,
    supervisor: Supervisor,
}
impl Fixture {
    async fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("fx-t-")
            .tempdir_in("/tmp")
            .unwrap();
        let base = root.path().canonicalize().unwrap();
        let home = base.join("core");
        home::prepare(&home).unwrap();
        let workspace = base.join("work");
        fs::create_dir(&workspace).unwrap();
        let real_home = base.join("user");
        fs::create_dir(&real_home).unwrap();
        let mut config = Config::create_if_missing(&home).unwrap();
        config.providers.clear();
        config.sandbox.home_ro_files.clear();
        let secrets =
            Arc::new(SecretStore::open(&home, BackendKind::File, Redactor::default()).unwrap());
        let store = Arc::new(Store::open(&home).await.unwrap());
        let proxy = EgressProxy::bind_unix(home.join("run/proxy.sock"), store.clone(), vec![])
            .await
            .unwrap();
        let proxy = Arc::new(proxy);
        let supervisor = Supervisor::new(
            &home,
            &real_home,
            Arc::new(config),
            secrets.clone(),
            store.clone(),
            proxy.clone(),
        )
        .unwrap()
        .with_fictor_exe(PathBuf::from(env!("CARGO_BIN_EXE_fictor")))
        .unwrap();
        Self {
            _root: root,
            home,
            workspace,
            real_home,
            store,
            secrets,
            proxy,
            supervisor,
        }
    }
    async fn session(&self) -> String {
        self.store
            .create_session(NewSession {
                title: "Supervisor test".into(),
                workspace: self.workspace.clone(),
                workspace_trust: Trust::Trusted,
                harness: "test-extension".into(),
                mode: Mode::Plan,
                model: None,
            })
            .await
            .unwrap()
            .id
    }
    fn bundle(&self, quarantine: bool, script: &str) -> PathBuf {
        let path = self.home.join(if quarantine {
            "extensions/quarantine/proposal"
        } else {
            "extensions/store/test-extension/1.0.0-000000000000"
        });
        fs::create_dir_all(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(path.join("server"), format!("#!/bin/sh\n{script}\n")).unwrap();
        fs::set_permissions(path.join("server"), fs::Permissions::from_mode(0o755)).unwrap();
        path
    }
}
fn manifest(permissions: serde_json::Value, session: bool, mcp: bool) -> Manifest {
    let mut value = json!({"schema":1,"id":"test-extension","version":"1.0.0","description":"Test only","runtime":{"kind":"binary","entry":"server"},"scope":if session {"session"}else{"global"},"mcp":mcp,"permissions":permissions});
    if !mcp {
        value["kernel"] = json!(["config"]);
    }
    Manifest::parse(&value.to_string()).unwrap()
}
async fn wait_file(path: &Path) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn bundled_native_process_has_clean_environment_redacted_logs_and_crash_audit() {
    let fixture = Fixture::new().await;
    fixture
        .secrets
        .set("fake_api", "fake-supervisor-credential\nmultiline")
        .unwrap();
    let session = fixture.session().await;
    let bundle = fixture.bundle(false,r#"printf '%s\n' "$FICTOR_EXT_ID" "$FICTOR_SESSION_ID" "$HOME" "${NODE_OPTIONS-unset}" > "$FICTOR_WORKSPACE/result"
printf '%s' "$API_TOKEN" >&2
printf '\n%s\n' "$HTTP_PROXY" >&2
exit 7"#);
    let manifest = manifest(
        json!({"fs":{"write":["${workspace}"]},"net":{"allow":["example.test"]},"spawn":true,"secrets":[{"name":"fake_api","env":"API_TOKEN"}]}),
        true,
        false,
    );
    let mut instance = fixture
        .supervisor
        .spawn(
            &manifest,
            &bundle,
            "1.0.0-000000000000",
            Some(&session),
            Some(&fixture.workspace),
        )
        .await
        .unwrap();
    let id = instance.instance_id.clone();
    let exit = tokio::time::timeout(Duration::from_secs(10), instance.wait())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(exit.code, Some(7));
    assert!(exit.crashed);
    let environment = fs::read_to_string(fixture.workspace.join("result")).unwrap();
    assert!(environment.contains("test-extension"));
    assert!(environment.contains(&session));
    assert!(environment.contains("unset"));
    assert!(!environment.contains(fixture.real_home.to_str().unwrap()));
    let log = fs::read_to_string(fixture.home.join("logs/ext/test-extension.log")).unwrap();
    assert!(!log.contains("fake-supervisor-credential"));
    assert!(!log.contains("multiline"));
    assert!(log.contains("***"));
    let events = fixture
        .store
        .query_events(EventQuery {
            session_id: Some("sys".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let started = events
        .iter()
        .find(|e| e.kind == "ext.started" && e.payload["instance_id"] == id)
        .unwrap();
    let crashed = events
        .iter()
        .find(|e| e.kind == "ext.crashed" && e.payload["instance_id"] == id)
        .unwrap();
    assert!(started.id < crashed.id);
    assert_eq!(crashed.blob_refs.len(), 1);
    let stderr = fixture
        .store
        .get_blob(crashed.blob_refs[0].clone())
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&stderr).contains("fake-supervisor-credential"));
    assert!(!fixture.home.join("run").join(format!("{id}.pid")).exists());
}

#[tokio::test]
async fn shutdown_kills_children_and_removes_pid_only_after_reap() {
    let fixture = Fixture::new().await;
    let session = fixture.session().await;
    let bundle = fixture.bundle(
        false,
        r#"trap '' TERM
(while :; do printf 'alive\n' >> "$FICTOR_WORKSPACE/child.activity"; /bin/sleep 0.05; done) &
wait"#,
    );
    let manifest = manifest(
        json!({"fs":{"write":["${workspace}"]},"spawn":true}),
        true,
        false,
    );
    let mut instance = fixture
        .supervisor
        .spawn(
            &manifest,
            &bundle,
            "1.0.0-000000000000",
            Some(&session),
            Some(&fixture.workspace),
        )
        .await
        .unwrap();
    let activity = fixture.workspace.join("child.activity");
    wait_file(&activity).await;
    let id = instance.instance_id.clone();
    let exit = tokio::time::timeout(Duration::from_secs(10), instance.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert!(!exit.crashed);
    // Child PIDs inside the sandbox cannot be queried in the host PID namespace.
    // Completion must stop observable descendant work before freeing its paths.
    let stopped_activity = fs::read(&activity).unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(fs::read(&activity).unwrap(), stopped_activity);
    assert!(!fixture.home.join("run").join(format!("{id}.pid")).exists());
}

#[tokio::test]
async fn smoke_uses_fake_credentials_disposable_kernel_state_and_no_real_data() {
    let fixture = Fixture::new().await;
    fixture
        .secrets
        .set("fake_api", "never-pass-this-real-fixture-value")
        .unwrap();
    let bundle = fixture.bundle(
        true,
        r#"case "$API_TOKEN" in fictor_honey_*) ;; *) exit 91 ;; esac
[ -z "${FICTOR_MODELS_URL-}" ] || exit 92
[ ! -e "$HOME/../../config.toml" ] || exit 93
printf '%s\n' "$API_TOKEN" >&2
exit 0"#,
    );
    let manifest = manifest(
        json!({"net":{"allow":["example.test"]},"models":["provider"],"spawn":true,"secrets":[{"name":"fake_api","env":"API_TOKEN"}]}),
        true,
        false,
    );
    let report = fixture
        .supervisor
        .smoke(&manifest, &bundle, "1.0.0-000000000000")
        .await
        .unwrap();
    assert!(report.catalog.tools().is_empty());
    assert!(report.resources.is_empty());
    assert!(!fixture.home.join("extensions/data/test-extension").exists());
    assert!(!fixture.home.join("logs/ext/test-extension.log").exists());
}

#[tokio::test]
async fn supervisor_second_barrier_refuses_globals_path_escape_and_fake_none_servers() {
    let fixture = Fixture::new().await;
    let bundle = fixture.bundle(true, "exit 0");
    let global = manifest(json!({"spawn":true}), false, false);
    assert!(matches!(
        fixture
            .supervisor
            .spawn(&global, &bundle, "key", None, None)
            .await,
        Err(SupervisorError::Unsupported)
    ));
    assert!(matches!(
        fixture.supervisor.smoke(&global, &bundle, "key").await,
        Err(SupervisorError::Unsupported)
    ));
    let mut none=Manifest::parse(r#"{"schema":1,"id":"test-extension","version":"1.0.0","description":"Test","runtime":{"kind":"none"}}"#).unwrap();
    assert!(
        fixture
            .supervisor
            .smoke(&none, &bundle, "key")
            .await
            .is_ok()
    );
    none.mcp = Some(true);
    assert!(matches!(
        fixture.supervisor.smoke(&none, &bundle, "key").await,
        Err(SupervisorError::Invalid)
    ));
    let mut bad = global.clone();
    bad.permissions.env.insert("HOME".into(), "escape".into());
    assert!(matches!(bad.validate(), Err(ManifestError::Schema)));
    assert!(matches!(
        fixture.supervisor.smoke(&bad, &bundle, "key").await,
        Err(SupervisorError::Invalid)
    ));
    let mut escaped = global;
    escaped.scope = fictor::installer::manifest::Scope::Session;
    escaped
        .permissions
        .fs
        .read
        .push("/var/lib/fictor-denied".into());
    assert!(matches!(
        fixture.supervisor.smoke(&escaped, &bundle, "key").await,
        Err(SupervisorError::Path)
    ));
}

#[tokio::test]
async fn smoke_requires_actual_mcp_discovery_and_returns_pinned_tools_and_resources() {
    let fixture = Fixture::new().await;
    let bundle=fixture.bundle(true,r#"while IFS= read -r line; do
case "$line" in
*'"id":'*) id=$(printf '%s' "$line" | /usr/bin/sed -E 's/.*"id":([0-9]+).*/\1/') ;;
*) continue ;;
esac
case "$line" in
*'"method":"initialize"'*) result='{"protocolVersion":"2025-03-26","capabilities":{"tools":{},"resources":{}},"serverInfo":{"name":"fake-smoke","version":"1"}}' ;;
*'"method":"tools/list"'*) result='{"tools":[{"name":"echo","inputSchema":{"type":"object"}}]}' ;;
*'"method":"resources/list"'*) result='{"resources":[{"uri":"ui://test/app","name":"App"}]}' ;;
*) continue ;;
esac
printf '{"jsonrpc":"2.0","id":%s,"result":%s}\n' "$id" "$result"
done"#);
    let manifest = manifest(json!({"spawn":true}), true, true);
    let report = fixture
        .supervisor
        .smoke(&manifest, &bundle, "1.0.0-000000000000")
        .await
        .unwrap();
    assert_eq!(report.catalog.tools().len(), 1);
    assert_eq!(report.catalog.tools()[0]["name"], "echo");
    assert_eq!(report.resources.len(), 1);
    fs::write(bundle.join("server"), "#!/bin/sh\nexit 0\n").unwrap();
    assert!(matches!(
        fixture.supervisor.smoke(&manifest, &bundle, "key").await,
        Err(SupervisorError::Mcp)
    ));
}

#[tokio::test]
async fn permission_templates_cannot_follow_symlinks_outside_their_root() {
    let fixture = Fixture::new().await;
    let session = fixture.session().await;
    let bundle = fixture.bundle(false, "exit 0");
    let data = fixture
        .home
        .join("extensions/data/test-extension/sessions")
        .join(&session);
    fs::create_dir_all(&data).unwrap();
    std::os::unix::fs::symlink(&fixture.workspace, data.join("escape")).unwrap();
    let manifest = manifest(
        json!({"fs":{"read":["${ext_data}/escape"]},"spawn":true}),
        true,
        false,
    );
    assert!(matches!(
        fixture
            .supervisor
            .spawn(
                &manifest,
                &bundle,
                "1.0.0-000000000000",
                Some(&session),
                Some(&fixture.workspace)
            )
            .await,
        Err(SupervisorError::Path)
    ));
}

#[tokio::test]
async fn dropping_managed_instance_kills_group_and_finishes_cleanup() {
    let fixture = Fixture::new().await;
    let session = fixture.session().await;
    let bundle = fixture.bundle(
        false,
        r#"/bin/sleep 60 &
printf '%s\n' "$!" > "$FICTOR_WORKSPACE/child.pid"
wait"#,
    );
    let manifest = manifest(
        json!({"fs":{"write":["${workspace}"]},"spawn":true}),
        true,
        false,
    );
    let instance = fixture
        .supervisor
        .spawn(
            &manifest,
            &bundle,
            "1.0.0-000000000000",
            Some(&session),
            Some(&fixture.workspace),
        )
        .await
        .unwrap();
    wait_file(&fixture.workspace.join("child.pid")).await;
    let leader = instance.pid() as i32;
    let pid_path = fixture
        .home
        .join("run")
        .join(format!("{}.pid", instance.instance_id));
    drop(instance);
    tokio::time::timeout(Duration::from_secs(5), async {
        while pid_path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_ne!(unsafe { libc::kill(leader, 0) }, 0);
}

#[tokio::test]
async fn smoke_runtime_installation_cannot_mount_the_production_core() {
    let fixture = Fixture::new().await;
    fixture
        .secrets
        .set("canary", "fake-production-only-canary")
        .unwrap();
    let bin = fixture.home.join("bin");
    fs::create_dir(&bin).unwrap();
    let runtime = bin.join("deno");
    // If the runtime were launched, it would attempt to read this fake production
    // secret; the expected Sandbox error precedes process creation entirely.
    fs::write(
        &runtime,
        format!(
            "#!/bin/sh\n/bin/cat '{}' >&2\nexit 0\n",
            fixture.home.join("secrets.toml").display()
        ),
    )
    .unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o755)).unwrap();
    let mut config = Config::load(&fixture.home).unwrap();
    config.providers.clear();
    config
        .runtimes
        .insert("deno".into(), runtime.to_str().unwrap().into());
    let supervisor = Supervisor::new(
        &fixture.home,
        &fixture.real_home,
        Arc::new(config),
        fixture.secrets.clone(),
        fixture.store.clone(),
        fixture.proxy.clone(),
    )
    .unwrap()
    .with_fictor_exe(PathBuf::from(env!("CARGO_BIN_EXE_fictor")))
    .unwrap();
    let bundle = fixture.bundle(true, "exit 0");
    let mut manifest = manifest(json!({"spawn":true}), true, false);
    manifest.runtime.kind = fictor::installer::manifest::RuntimeKind::Deno;
    assert!(matches!(
        supervisor.smoke(&manifest, &bundle, "key").await,
        Err(SupervisorError::Sandbox)
    ));
}
