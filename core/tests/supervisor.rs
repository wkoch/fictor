use fictor::{
    config::{Config, Mode},
    gateway::PinnedCatalog,
    home,
    installer::manifest::{KernelScope, Manifest, ManifestError, Role},
    proxy::EgressProxy,
    secrets::{BackendKind, Redactor, SecretStore},
    store::{EventQuery, NewSession, Store, Trust},
    supervisor::{Supervisor, SupervisorError},
};
use serde_json::json;
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
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
        Self::new_in(Path::new("/tmp")).await
    }
    async fn new_in(parent: &Path) -> Self {
        let root = tempfile::Builder::new()
            .prefix("fx-t-")
            .tempdir_in(parent)
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
    fn daemon_bundle(&self) -> PathBuf {
        let bundle = self.bundle(false, "exit 0");
        // A native fixture makes the double fork and setsid explicit. cc is part
        // of the supported development/CI toolchain; no downloaded code is used.
        let mut compiler = Command::new("cc")
            .args(["-x", "c", "-O2", "-Wall", "-Werror", "-o"])
            .arg(bundle.join("server"))
            .arg("-")
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        compiler.stdin.take().unwrap().write_all(br#"
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
    const char *workspace = getenv("FICTOR_WORKSPACE");
    char activity[4096], marker[4096], namespace_path[4096];
    if (!workspace) return 90;
    snprintf(activity, sizeof(activity), "%s/daemon.activity", workspace);
    snprintf(marker, sizeof(marker), "%s/parent.exit", workspace);
    snprintf(namespace_path, sizeof(namespace_path), "%s/daemon.namespace", workspace);
    pid_t first = fork();
    if (first < 0) return 91;
    if (first == 0) {
        if (setsid() < 0) _exit(92);
        pid_t second = fork();
        if (second < 0) _exit(93);
        if (second > 0) _exit(0);
        signal(SIGTERM, SIG_IGN);
        char namespace[128];
        ssize_t length = readlink("/proc/self/ns/pid", namespace, sizeof(namespace));
        int descriptor = open(namespace_path, O_WRONLY | O_CREAT, 0600);
        if (descriptor < 0 || length < 0 || write(descriptor, namespace, (size_t)length) != length) _exit(94);
        close(descriptor);
        for (;;) {
            descriptor = open(activity, O_WRONLY | O_CREAT | O_APPEND, 0600);
            if (descriptor < 0 || write(descriptor, "alive\n", 6) != 6) _exit(95);
            close(descriptor);
            usleep(10000);
        }
    }
    int status;
    if (waitpid(first, &status, 0) != first || !WIFEXITED(status) || WEXITSTATUS(status)) return 96;
    while (access(marker, F_OK) != 0) usleep(10000);
    return 37;
}
"#).unwrap();
        assert!(compiler.wait().unwrap().success());
        bundle
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

fn launch_pid(home: &Path) -> (PathBuf, u32) {
    let records: Vec<_> = fs::read_dir(home.join("run"))
        .unwrap()
        .map(Result::unwrap)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "pid"))
        .collect();
    assert_eq!(records.len(), 1);
    let pid = fs::read_to_string(&records[0])
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    (records[0].clone(), pid)
}

async fn hold_store_writer(
    store: Arc<Store>,
) -> (std::sync::mpsc::Sender<()>, tokio::task::JoinHandle<()>) {
    let (entered, waiting) = tokio::sync::oneshot::channel();
    let (release, held) = std::sync::mpsc::channel();
    let task = tokio::spawn(async move {
        store
            .write(move |_| {
                let _ = entered.send(());
                // Dropping the sender on a test failure also releases the writer.
                let _ = held.recv();
                Ok(())
            })
            .await
            .unwrap();
    });
    waiting.await.unwrap();
    (release, task)
}

#[tokio::test]
async fn startup_audit_failure_reaps_the_sandbox_before_releasing_external_resources() {
    let fixture = Arc::new(Fixture::new().await);
    let session = fixture.session().await;
    let bundle = fixture.bundle(
        false,
        r#"printf 'ready\n' > "$FICTOR_WORKSPACE/launch.started"
/bin/sleep 60"#,
    );
    let manifest = manifest(
        json!({"fs":{"write":["${workspace}"]},"spawn":true}),
        true,
        false,
    );
    let database = rusqlite::Connection::open(fixture.home.join("fictor.db")).unwrap();
    database.execute_batch("CREATE TRIGGER reject_extension_start BEFORE INSERT ON events WHEN NEW.kind='ext.started' BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    let (release, writer) = hold_store_writer(fixture.store.clone()).await;
    let external = Arc::new(tempfile::tempdir().unwrap());
    let external_path = external.path().to_owned();
    let retained = Arc::downgrade(&external);
    let task_fixture = fixture.clone();
    let launch = tokio::spawn(async move {
        task_fixture
            .supervisor
            .spawn_with_owner(
                &manifest,
                &bundle,
                "1.0.0-000000000000",
                Some(&session),
                Some(&task_fixture.workspace),
                external,
            )
            .await
    });
    wait_file(&fixture.workspace.join("launch.started")).await;
    let (pid_path, pid) = launch_pid(&fixture.home);
    assert!(retained.upgrade().is_some());
    assert!(external_path.exists());
    release.send(()).unwrap();
    writer.await.unwrap();

    let result = tokio::time::timeout(Duration::from_secs(5), launch)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(SupervisorError::Audit)));
    assert!(!pid_path.exists());
    assert!(retained.upgrade().is_none());
    assert!(!external_path.exists());
    assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
}

#[tokio::test]
async fn cancelled_launch_retains_external_resources_until_the_sandbox_is_reaped() {
    let fixture = Arc::new(Fixture::new().await);
    let session = fixture.session().await;
    let bundle = fixture.bundle(
        false,
        r#"printf 'ready\n' > "$FICTOR_WORKSPACE/launch.started"
/bin/sleep 60"#,
    );
    let manifest = manifest(
        json!({"fs":{"write":["${workspace}"]},"spawn":true}),
        true,
        false,
    );
    let (release, writer) = hold_store_writer(fixture.store.clone()).await;
    let external = Arc::new(tempfile::tempdir().unwrap());
    let external_path = external.path().to_owned();
    let retained = Arc::downgrade(&external);
    let task_fixture = fixture.clone();
    let launch = tokio::spawn(async move {
        task_fixture
            .supervisor
            .spawn_with_owner(
                &manifest,
                &bundle,
                "1.0.0-000000000000",
                Some(&session),
                Some(&task_fixture.workspace),
                external,
            )
            .await
    });
    wait_file(&fixture.workspace.join("launch.started")).await;
    let (pid_path, pid) = launch_pid(&fixture.home);
    launch.abort();
    assert!(matches!(launch.await, Err(error) if error.is_cancelled()));
    assert!(retained.upgrade().is_some());
    assert!(pid_path.exists());
    assert!(external_path.exists());
    release.send(()).unwrap();
    writer.await.unwrap();

    tokio::time::timeout(Duration::from_secs(5), async {
        while pid_path.exists() || retained.upgrade().is_some() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(!external_path.exists());
    assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
}

#[tokio::test]
async fn session_admission_rejects_missing_and_archived_sessions_without_starting_a_process() {
    let fixture = Fixture::new().await;
    let bundle = fixture.bundle(
        false,
        r#"printf 'unexpected\n' > "$FICTOR_WORKSPACE/unexpected.process""#,
    );
    // A normal MCP process may have no kernel channel. Admission must not rely
    // on KernelServer::bind to check the persisted session.
    let manifest = manifest(
        json!({"fs":{"write":["${workspace}"]},"spawn":true}),
        true,
        true,
    );
    let missing = ulid::Ulid::generate().to_string();
    assert!(matches!(
        fixture
            .supervisor
            .spawn(
                &manifest,
                &bundle,
                "1.0.0-000000000000",
                Some(&missing),
                Some(&fixture.workspace),
            )
            .await,
        Err(SupervisorError::Invalid)
    ));
    let session = fixture.session().await;
    let archived = session.clone();
    fixture
        .store
        .write(move |database| {
            database.execute("UPDATE sessions SET archived=1 WHERE id=?1", [archived])?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(matches!(
        fixture
            .supervisor
            .spawn(
                &manifest,
                &bundle,
                "1.0.0-000000000000",
                Some(&session),
                Some(&fixture.workspace),
            )
            .await,
        Err(SupervisorError::Invalid)
    ));
    assert!(!fixture.workspace.join("unexpected.process").exists());
    assert!(!fixture.home.join("extensions/data/test-extension").exists());
    assert!(
        fs::read_dir(fixture.home.join("run"))
            .unwrap()
            .all(|entry| entry
                .unwrap()
                .path()
                .extension()
                .is_none_or(|extension| extension != "pid"))
    );
}

#[tokio::test]
async fn session_workspace_must_match_the_store_and_accepts_a_canonical_alias() {
    let fixture = Fixture::new().await;
    let session = fixture.session().await;
    let bundle = fixture.bundle(
        false,
        r#"printf '%s\n' "$FICTOR_WORKSPACE" > "$FICTOR_WORKSPACE/admitted.workspace""#,
    );
    let permissions = json!({"fs":{"write":["${workspace}"]},"spawn":true});
    for mcp in [false, true] {
        let manifest = manifest(permissions.clone(), true, mcp);
        assert!(matches!(
            fixture
                .supervisor
                .spawn(
                    &manifest,
                    &bundle,
                    "1.0.0-000000000000",
                    Some(&session),
                    Some(&fixture.real_home),
                )
                .await,
            Err(SupervisorError::Path | SupervisorError::Invalid)
        ));
        let other = fixture._root.path().join("other-workspace");
        fs::create_dir_all(&other).unwrap();
        assert!(matches!(
            fixture
                .supervisor
                .spawn(
                    &manifest,
                    &bundle,
                    "1.0.0-000000000000",
                    Some(&session),
                    Some(&other),
                )
                .await,
            Err(SupervisorError::Invalid)
        ));
        assert!(!other.join("admitted.workspace").exists());
    }
    let alias = fixture._root.path().join("workspace-alias");
    std::os::unix::fs::symlink(&fixture.workspace, &alias).unwrap();
    let manifest = manifest(permissions, true, false);
    let mut instance = fixture
        .supervisor
        .spawn(
            &manifest,
            &bundle,
            "1.0.0-000000000000",
            Some(&session),
            Some(&alias),
        )
        .await
        .unwrap();
    assert_eq!(instance.wait().await.unwrap().code, Some(0));
    assert_eq!(
        fs::read_to_string(fixture.workspace.join("admitted.workspace")).unwrap(),
        format!("{}\n", fixture.workspace.display())
    );
}

fn namespace_members(namespace: &str) -> Vec<u32> {
    fs::read_dir("/proc")
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let pid = entry.file_name().to_str()?.parse::<u32>().ok()?;
            let namespace_path = fs::read_link(entry.path().join("ns/pid")).ok()?;
            (namespace_path == Path::new(namespace)).then_some(pid)
        })
        .collect()
}

async fn assert_namespace_ended(workspace: &Path) {
    let namespace = fs::read_to_string(workspace.join("daemon.namespace")).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !namespace_members(&namespace).is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let activity = fs::read(workspace.join("daemon.activity")).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        fs::read(workspace.join("daemon.activity")).unwrap(),
        activity
    );
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
async fn shutdown_confirms_double_forked_setsid_descendants_have_exited() {
    let fixture = Fixture::new().await;
    let session = fixture.session().await;
    let bundle = fixture.daemon_bundle();
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
    wait_file(&fixture.workspace.join("daemon.activity")).await;
    let namespace = fs::read_to_string(fixture.workspace.join("daemon.namespace")).unwrap();
    assert!(!namespace_members(&namespace).is_empty());
    let pid_path = fixture
        .home
        .join("run")
        .join(format!("{}.pid", instance.instance_id));
    assert!(pid_path.exists());
    assert!(!instance.shutdown().await.unwrap().crashed);
    assert_namespace_ended(&fixture.workspace).await;
    assert!(!pid_path.exists());
}

#[tokio::test]
async fn unexpected_parent_exit_also_removes_double_forked_setsid_descendants() {
    let fixture = Fixture::new().await;
    let session = fixture.session().await;
    let bundle = fixture.daemon_bundle();
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
    wait_file(&fixture.workspace.join("daemon.activity")).await;
    fs::write(fixture.workspace.join("parent.exit"), "exit").unwrap();
    let exit = tokio::time::timeout(Duration::from_secs(5), instance.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(exit.crashed);
    assert_eq!(exit.code, Some(37));
    assert_namespace_ended(&fixture.workspace).await;
}

#[tokio::test]
async fn killing_core_owner_also_ends_the_entire_sandbox_namespace() {
    let parent = tempfile::Builder::new()
        .prefix("fx-owner-")
        .tempdir_in("/tmp")
        .unwrap();
    let ready = parent.path().join("ready");
    let mut owner = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "core_owner_subprocess", "--nocapture"])
        .env("FICTOR_TEST_OWNER_ROOT", parent.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_file(&ready).await;
    let workspace = PathBuf::from(fs::read_to_string(&ready).unwrap());
    let namespace = fs::read_to_string(workspace.join("daemon.namespace")).unwrap();
    assert!(!namespace_members(&namespace).is_empty());
    owner.kill().unwrap(); // SIGKILL: no Rust destructors or async shutdown run.
    assert!(!owner.wait().unwrap().success());
    assert_namespace_ended(&workspace).await;
}

#[tokio::test]
async fn core_owner_subprocess() {
    // The parent test opts into this subprocess workload; ordinary suite runs
    // return immediately instead of creating another owner recursively.
    let Some(parent) = std::env::var_os("FICTOR_TEST_OWNER_ROOT") else {
        return;
    };
    let parent = PathBuf::from(parent);
    let fixture = Fixture::new_in(&parent).await;
    let session = fixture.session().await;
    let bundle = fixture.daemon_bundle();
    let manifest = manifest(
        json!({"fs":{"write":["${workspace}"]},"spawn":true}),
        true,
        false,
    );
    let _instance = fixture
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
    wait_file(&fixture.workspace.join("daemon.activity")).await;
    fs::write(parent.join("ready"), fixture.workspace.to_str().unwrap()).unwrap();
    std::future::pending::<()>().await;
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
[ ! -e "$REAL_QUARANTINE" ] || exit 94
printf '%s\n' "$API_TOKEN" >&2
exit 0"#,
    );
    let manifest = manifest(
        json!({"net":{"allow":["example.test"]},"models":["provider"],"spawn":true,"secrets":[{"name":"fake_api","env":"API_TOKEN"}],"env":{"REAL_QUARANTINE":fixture.home.join("extensions/quarantine").to_str().unwrap()}}),
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
}

#[tokio::test]
async fn smoke_omits_real_host_grants_and_preserves_the_reviewed_manifest() {
    let fixture = Fixture::new().await;
    let private = fixture.workspace.join("production-private");
    fs::write(&private, "private fixture data").unwrap();
    fs::write(fixture.real_home.join("private"), "home fixture data").unwrap();
    let bundle = fixture.bundle(
        true,
        r#"[ ! -e "$PRIVATE_FILE" ] || exit 91
[ ! -e "$PRIVATE_HOME" ] || exit 92
printf 'disposable\n' > "$FICTOR_WORKSPACE/allowed"
exit 0"#,
    );
    let manifest = manifest(
        json!({
            "fs": {"read": [private.to_str().unwrap(), "~/private"],
                   "write": [fixture.workspace.to_str().unwrap(), "${workspace}"]},
            "env": {"PRIVATE_FILE": private.to_str().unwrap(),
                    "PRIVATE_HOME": fixture.real_home.join("private").to_str().unwrap()},
            "spawn": true
        }),
        true,
        false,
    );
    fixture
        .supervisor
        .smoke(&manifest, &bundle, "key")
        .await
        .unwrap();
    assert_eq!(
        manifest.permissions.fs.read,
        vec![private.to_str().unwrap(), "~/private"]
    );
    assert_eq!(manifest.permissions.fs.write.len(), 2);
    assert_eq!(
        fs::read_to_string(&private).unwrap(),
        "private fixture data"
    );
    assert!(!fixture.workspace.join("allowed").exists());
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

fn mutable_catalog_bundle(fixture: &Fixture) -> PathBuf {
    fixture.bundle(false, r#"description="$INITIAL_DESCRIPTION"
/usr/bin/readlink /proc/self/ns/pid > "$FICTOR_WORKSPACE/catalog.namespace"
printf '%s\n' "$HTTP_PROXY" > "$FICTOR_WORKSPACE/catalog.proxy"
listed=0
while IFS= read -r line; do
case "$line" in
*'"id":'*) id=$(printf '%s' "$line" | /usr/bin/sed -E 's/.*"id":([0-9]+).*/\1/') ;;
*) continue ;;
esac
notify=0
case "$line" in
*'"method":"initialize"'*) result='{"protocolVersion":"2025-03-26","capabilities":{"tools":{"listChanged":true},"resources":{}},"serverInfo":{"name":"mutable-catalog","version":"1"}}' ;;
*'"method":"tools/list"'*)
listed=$((listed + 1))
if [ "$listed" -gt 1 ]; then printf 'verified\n' > "$FICTOR_WORKSPACE/reverified"; fi
result=$(printf '{"tools":[{"name":"echo","description":"%s","inputSchema":{"type":"object"}}]}' "$description") ;;
*'"method":"resources/list"'*) description="$NEXT_DESCRIPTION"; result='{"resources":[]}'; notify=1 ;;
*'"method":"tools/call"'*) result='{"content":[]}' ;;
*) continue ;;
esac
printf '{"jsonrpc":"2.0","id":%s,"result":%s}\n' "$id" "$result"
if [ "$notify" -eq 1 ]; then printf '{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}\n'; fi
done
# A hostile server can ignore transport EOF and keep its namespace alive.
/bin/sleep 60"#)
}

fn mutable_catalog_manifest(initial: &str, next: &str) -> Manifest {
    let mut manifest = manifest(
        json!({"spawn":true,"fs":{"write":["${workspace}"]},
               "env":{"INITIAL_DESCRIPTION":initial,"NEXT_DESCRIPTION":next}}),
        true,
        true,
    );
    manifest.kernel = vec![KernelScope::Config];
    manifest
}

fn fixed_catalog() -> PinnedCatalog {
    PinnedCatalog::new(vec![json!({
        "name":"echo","description":"fixed","inputSchema":{"type":"object"}
    })])
    .unwrap()
}

async fn assert_catalog_instance_released(fixture: &Fixture, instance_id: &str) {
    let namespace = fs::read_to_string(fixture.workspace.join("catalog.namespace")).unwrap();
    assert!(namespace_members(namespace.trim()).is_empty());
    assert!(
        !fixture
            .home
            .join(format!("run/k/{instance_id}.sock"))
            .exists()
    );
    let proxy = fs::read_to_string(fixture.workspace.join("catalog.proxy")).unwrap();
    let token = proxy
        .trim()
        .strip_prefix("http://fx:")
        .unwrap()
        .split('@')
        .next()
        .unwrap();
    let authorization = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        format!("fx:{token}"),
    );
    let mut stream = tokio::net::UnixStream::connect(fixture.home.join("run/proxy.sock"))
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut stream, format!("GET http://example.invalid/ HTTP/1.1\r\nHost: example.invalid\r\nProxy-Authorization: Basic {authorization}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 407"));
}

#[tokio::test]
async fn initial_pin_mismatch_stops_and_reaps_the_managed_sandbox() {
    let fixture = Fixture::new().await;
    let session = fixture.session().await;
    let bundle = mutable_catalog_bundle(&fixture);
    let manifest = mutable_catalog_manifest("changed", "changed");
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
    let pid = instance.pid();
    assert!(matches!(
        instance.connect_mcp(Some(fixed_catalog())).await,
        Err(SupervisorError::Mcp)
    ));
    tokio::time::timeout(Duration::from_secs(7), instance.wait())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
    assert_catalog_instance_released(&fixture, &instance.instance_id).await;
    let events = fixture
        .store
        .query_events(EventQuery {
            kinds: vec!["ext.tools_changed".into()],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
}

#[tokio::test]
async fn changed_runtime_pin_stops_and_reaps_the_managed_sandbox() {
    let fixture = Fixture::new().await;
    let session = fixture.session().await;
    let bundle = mutable_catalog_bundle(&fixture);
    let manifest = mutable_catalog_manifest("fixed", "changed");
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
    let pid = instance.pid();
    instance
        .connect_mcp(Some(fixed_catalog()))
        .await
        .unwrap()
        .resources()
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(7), instance.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(instance.connection().unwrap().is_disabled());
    assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
    assert_catalog_instance_released(&fixture, &instance.instance_id).await;
    let events = fixture
        .store
        .query_events(EventQuery {
            kinds: vec!["ext.tools_changed".into()],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
}

#[tokio::test]
async fn changed_pin_reaps_before_blocked_audit_and_reports_audit_failure() {
    let fixture = Fixture::new().await;
    let session = fixture.session().await;
    let bundle = mutable_catalog_bundle(&fixture);
    let manifest = mutable_catalog_manifest("fixed", "changed");
    let external = Arc::new(tempfile::tempdir().unwrap());
    let retained = Arc::downgrade(&external);
    let mut instance = fixture
        .supervisor
        .spawn_with_owner(
            &manifest,
            &bundle,
            "1.0.0-000000000000",
            Some(&session),
            Some(&fixture.workspace),
            external,
        )
        .await
        .unwrap();
    instance.connect_mcp(Some(fixed_catalog())).await.unwrap();
    fixture.store.write(|database| {
        database.execute_batch("CREATE TRIGGER reject_catalog_audit BEFORE INSERT ON events WHEN NEW.kind='ext.tools_changed' BEGIN SELECT RAISE(ABORT,'fixture'); END;")?;
        Ok(())
    }).await.unwrap();
    let (release, writer) = hold_store_writer(fixture.store.clone()).await;
    instance.connection().unwrap().resources().await.unwrap();
    let pid = instance.pid();
    let socket = fixture
        .home
        .join(format!("run/k/{}.sock", instance.instance_id));
    tokio::time::timeout(Duration::from_secs(7), async {
        while unsafe { libc::kill(pid as i32, 0) } == 0 || socket.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_catalog_instance_released(&fixture, &instance.instance_id).await;
    assert!(retained.upgrade().is_some());
    let record = fixture
        .home
        .join(format!("run/{}.pid", instance.instance_id));
    assert!(record.exists());
    release.send(()).unwrap();
    writer.await.unwrap();
    assert!(matches!(instance.wait().await, Err(SupervisorError::Audit)));
    assert!(retained.upgrade().is_none());
    assert!(!record.exists());
    assert!(
        fixture
            .store
            .query_events(EventQuery {
                kinds: vec!["ext.tools_changed".into()],
                ..Default::default()
            })
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn identical_catalog_notification_preserves_the_managed_instance() {
    let fixture = Fixture::new().await;
    let session = fixture.session().await;
    let bundle = mutable_catalog_bundle(&fixture);
    let manifest = mutable_catalog_manifest("fixed", "fixed");
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
    instance.connect_mcp(Some(fixed_catalog())).await.unwrap();
    instance
        .connect_mcp(Some(fixed_catalog()))
        .await
        .unwrap()
        .resources()
        .await
        .unwrap();
    wait_file(&fixture.workspace.join("reverified")).await;
    let connection = instance.connection().unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while connection.is_disabled() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (_cancel, cancelled) = tokio::sync::watch::channel(false);
    connection
        .call("echo", json!({}), Duration::from_secs(2), cancelled)
        .await
        .unwrap();
    assert_eq!(unsafe { libc::kill(instance.pid() as i32, 0) }, 0);
    assert!(
        fixture
            .store
            .query_events(EventQuery {
                kinds: vec!["ext.tools_changed".into()],
                ..Default::default()
            })
            .await
            .unwrap()
            .is_empty()
    );
    instance.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_managed_connection_cannot_switch_its_explicit_pin() {
    let fixture = Fixture::new().await;
    let session = fixture.session().await;
    let bundle = mutable_catalog_bundle(&fixture);
    let manifest = mutable_catalog_manifest("fixed", "fixed");
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
    instance.connect_mcp(Some(fixed_catalog())).await.unwrap();
    let changed = PinnedCatalog::new(vec![
        json!({"name":"echo","description":"other","inputSchema":{"type":"object"}}),
    ])
    .unwrap();
    assert!(matches!(
        instance.connect_mcp(Some(changed)).await,
        Err(SupervisorError::Mcp)
    ));
    assert!(instance.connection().is_none());
    instance.wait().await.unwrap();
    assert_catalog_instance_released(&fixture, &instance.instance_id).await;
    assert_eq!(
        fixture
            .store
            .query_events(EventQuery {
                kinds: vec!["ext.tools_changed".into()],
                ..Default::default()
            })
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn a_discovery_connection_cannot_be_upgraded_to_an_explicit_pin() {
    let fixture = Fixture::new().await;
    let session = fixture.session().await;
    let bundle = mutable_catalog_bundle(&fixture);
    let manifest = mutable_catalog_manifest("fixed", "fixed");
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
    instance.connect_mcp(None).await.unwrap();
    assert!(matches!(
        instance.connect_mcp(Some(fixed_catalog())).await,
        Err(SupervisorError::Mcp)
    ));
    assert!(instance.connection().is_none());
    instance.wait().await.unwrap();
    assert_catalog_instance_released(&fixture, &instance.instance_id).await;
    assert_eq!(
        fixture
            .store
            .query_events(EventQuery {
                kinds: vec!["ext.tools_changed".into()],
                ..Default::default()
            })
            .await
            .unwrap()
            .len(),
        1
    );
}

async fn cancelled_mcp_handshake_reaps_the_instance(pinned: bool) {
    let fixture = Fixture::new().await;
    let session = fixture.session().await;
    let bundle = fixture.bundle(
        false,
        r#"/usr/bin/readlink /proc/self/ns/pid > "$FICTOR_WORKSPACE/catalog.namespace"
printf '%s\n' "$HTTP_PROXY" > "$FICTOR_WORKSPACE/catalog.proxy"
IFS= read -r line || exit 90
case "$line" in
*'"method":"initialize"'*) printf 'received\n' > "$FICTOR_WORKSPACE/initialize.received" ;;
*) exit 91 ;;
esac
# Hold initialize open regardless of transport EOF from a cancelled client.
/bin/sleep 60"#,
    );
    let manifest = mutable_catalog_manifest("fixed", "fixed");
    let external = Arc::new(tempfile::tempdir().unwrap());
    let retained = Arc::downgrade(&external);
    let mut instance = fixture
        .supervisor
        .spawn_with_owner(
            &manifest,
            &bundle,
            "1.0.0-000000000000",
            Some(&session),
            Some(&fixture.workspace),
            external,
        )
        .await
        .unwrap();
    let pid = instance.pid();
    let record = fixture
        .home
        .join(format!("run/{}.pid", instance.instance_id));
    let received = fixture.workspace.join("initialize.received");
    {
        let handshake = instance.connect_mcp(pinned.then(fixed_catalog));
        tokio::pin!(handshake);
        tokio::select! {
            _ = &mut handshake => panic!("fixture must keep initialize pending"),
            _ = wait_file(&received) => {}
        }
        // Drop only the connect future. The caller keeps ManagedInstance alive.
    }
    assert!(instance.connection().is_none());
    assert!(retained.upgrade().is_some());
    assert!(record.exists());
    let exit = tokio::time::timeout(Duration::from_secs(7), instance.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(!exit.crashed);
    assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
    assert_catalog_instance_released(&fixture, &instance.instance_id).await;
    assert!(retained.upgrade().is_none());
    assert!(!record.exists());
    assert!(matches!(
        instance.connect_mcp(pinned.then(fixed_catalog)).await,
        Err(SupervisorError::Mcp)
    ));
    let events = fixture
        .store
        .query_events(EventQuery {
            kinds: vec![
                "ext.stopped".into(),
                "ext.crashed".into(),
                "ext.tools_changed".into(),
            ],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, "ext.stopped");
}

#[tokio::test]
async fn cancelled_pinned_handshake_stops_the_instance_while_the_handle_remains_alive() {
    cancelled_mcp_handshake_reaps_the_instance(true).await;
}

#[tokio::test]
async fn cancelled_discovery_handshake_stops_the_instance_while_the_handle_remains_alive() {
    cancelled_mcp_handshake_reaps_the_instance(false).await;
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
async fn node_permission_model_denies_spawn_and_uses_only_the_sandbox_environment() {
    let fixture = Fixture::new().await;
    let session = fixture.session().await;
    let bundle = fixture.bundle(false, "exit 0");
    fs::write(bundle.join("main.mjs"), r#"import { writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
if (process.permission.has('child') || process.permission.has('worker')) process.exit(91);
try { spawnSync('/usr/bin/true'); process.exit(92); }
catch (error) { if (error.code !== 'ERR_ACCESS_DENIED') throw error; }
if (process.env.NODE_OPTIONS !== undefined || process.env.NODE_USE_ENV_PROXY !== '1') process.exit(93);
writeFileSync(`${process.env.FICTOR_WORKSPACE}/node-result`, 'denied');
"#).unwrap();
    let mut manifest = manifest(json!({"fs":{"write":["${workspace}"]}}), true, false);
    manifest.runtime.kind = fictor::installer::manifest::RuntimeKind::Node;
    manifest.runtime.entry = Some("main.mjs".into());
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
    assert_eq!(instance.wait().await.unwrap().code, Some(0));
    assert_eq!(
        fs::read_to_string(fixture.workspace.join("node-result")).unwrap(),
        "denied"
    );
}

#[tokio::test]
async fn kernel_logs_from_node_share_the_extension_log_and_redact_instance_credentials() {
    let fixture = Fixture::new().await;
    fixture
        .secrets
        .set("fake_log", "fake-log-credential\nsecond-line")
        .unwrap();
    let session = fixture.session().await;
    let bundle = fixture.bundle(false, "exit 0");
    fs::write(bundle.join("main.mjs"), r#"import net from 'node:net';
const socket = net.createConnection(3129, '127.0.0.1');
const send = (message) => socket.write(JSON.stringify({jsonrpc:'2.0', ...message}) + '\n');
let buffered = '';
socket.setEncoding('utf8');
socket.on('connect', () => send({id:1, method:'kernel.hello', params:{protocol:1, token:process.env.FICTOR_KERNEL_TOKEN}}));
socket.on('data', (chunk) => {
  buffered += chunk;
  for (;;) {
    const index = buffered.indexOf('\n');
    if (index < 0) break;
    const reply = JSON.parse(buffered.slice(0, index));
    buffered = buffered.slice(index + 1);
    if (reply.error) throw new Error(reply.error.message);
    if (reply.id === 1) {
      send({method:'log', params:{level:'info', message:`structured event ${process.env.API_TOKEN}`, fields:{nested:[process.env.API_TOKEN], kernel:process.env.FICTOR_KERNEL_TOKEN, proxy:process.env.HTTP_PROXY, ext_id:'forged-destination'}}});
      send({id:2, method:'config.get', params:{section:'ext'}});
    }
    if (reply.id === 2) {
      process.stderr.write(`stderr only ${process.env.API_TOKEN}\n`);
      process.exitCode = 7;
      socket.end();
    }
  }
});
"#).unwrap();
    let mut manifest = manifest(
        json!({"net":{"allow":["example.test"]},"secrets":[{"name":"fake_log","env":"API_TOKEN"}]}),
        true,
        false,
    );
    manifest.runtime.kind = fictor::installer::manifest::RuntimeKind::Node;
    manifest.runtime.entry = Some("main.mjs".into());
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
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), instance.wait())
            .await
            .unwrap()
            .unwrap()
            .code,
        Some(7)
    );
    let log = fs::read_to_string(fixture.home.join("logs/ext/test-extension.log")).unwrap();
    assert!(log.contains("structured event") && log.contains("stderr only"));
    assert!(!log.contains("fake-log-credential") && !log.contains("second-line"));
    assert!(log.matches("***").count() >= 4);
    assert!(
        !log.split(|c: char| !c.is_ascii_hexdigit())
            .any(|part| part.len() >= 64)
    );
    assert!(
        !fixture
            .home
            .join("logs/ext/forged-destination.log")
            .exists()
    );
    let events = fixture
        .store
        .query_events(EventQuery {
            session_id: Some("sys".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let crash = events
        .iter()
        .find(|event| event.kind == "ext.crashed")
        .unwrap();
    let tail = fixture
        .store
        .get_blob(crash.blob_refs[0].clone())
        .await
        .unwrap();
    let tail = String::from_utf8(tail).unwrap();
    assert!(tail.contains("stderr only"));
    assert!(!tail.contains("structured event") && !tail.contains("fake-log-credential"));
}

#[tokio::test]
async fn implicit_home_files_are_unreadable_to_harness_and_tools_clients() {
    let fixture = Fixture::new().await;
    let private = fixture.real_home.join(".gitconfig");
    fs::write(&private, "private user configuration").unwrap();
    let mut config = Config::load(&fixture.home).unwrap();
    config.providers.clear();
    config.sandbox.home_ro_files = vec!["~/.gitconfig".into()];
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
    let bundle = fixture.bundle(
        false,
        r#"case "$EXPECTED" in
denied) [ ! -r "$PRIVATE" ] ;;
allowed) [ -r "$PRIVATE" ] ;;
*) exit 99 ;;
esac"#,
    );
    for role in ["harness", "tools", "ordinary"] {
        let session = fixture.session().await;
        let mut manifest = manifest(
            json!({"env":{
                "PRIVATE":private.to_str().unwrap(),
                "EXPECTED":if role == "ordinary" { "allowed" } else { "denied" }
            }}),
            true,
            false,
        );
        if role == "harness" {
            manifest.role = Role::Harness;
        }
        if role == "tools" {
            manifest.kernel.push(KernelScope::Tools);
        }
        let mut instance = supervisor
            .spawn(
                &manifest,
                &bundle,
                "1.0.0-000000000000",
                Some(&session),
                Some(&fixture.workspace),
            )
            .await
            .unwrap();
        assert_eq!(instance.wait().await.unwrap().code, Some(0), "{role}");
    }
}
