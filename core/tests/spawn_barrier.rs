//! Real namespace barrier tests: no workload before a durable armed journal.
//! No fallback/skip when bubblewrap or user namespaces are unavailable.
use fictor::{
    instance_recovery::{InstanceJournal, InstanceState, NewInstance, ProcessHandle, StateRecord},
    sandbox::{
        ProxyEndpoint, SandboxContext, SandboxPlan, SandboxProfile, Tier,
        admission::AdmissionListener,
    },
    store::{NewSession, Store, Trust},
};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

struct Fixture {
    root: Option<tempfile::TempDir>,
    removable: Arc<AtomicBool>,
    home: PathBuf,
    workspace: PathBuf,
    marker: PathBuf,
    journal: InstanceJournal,
    _store: Arc<Store>,
    _proxy: tokio::net::UnixListener,
}
impl Fixture {
    async fn new() -> Self {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let home = root.path().join("core");
        fictor::initialize(&home).await.unwrap();
        let store = Arc::new(Store::open(&home).await.unwrap());
        let workspace = root.path().join("work");
        fs::create_dir(&workspace).unwrap();
        let session = store
            .create_session(NewSession {
                title: "barrier fixture".into(),
                workspace: workspace.clone(),
                workspace_trust: Trust::Trusted,
                harness: "barrier-probe".into(),
                mode: fictor::config::Mode::Plan,
                model: None,
            })
            .await
            .unwrap();
        let journal = InstanceJournal::prepare(
            store.owner().clone(),
            NewInstance {
                instance_id: ulid::Ulid::generate().to_string(),
                ext_id: "barrier-probe".into(),
                key: "1.0.0-000000000000".into(),
                session_id: Some(session.id),
            },
        )
        .unwrap();
        journal.create_temporary().unwrap();
        let proxy = tokio::net::UnixListener::bind(home.join("run/proxy.sock")).unwrap();
        let marker = workspace.join("workload.started");
        Self {
            root: Some(root),
            removable: Arc::new(AtomicBool::new(true)),
            home,
            workspace,
            marker,
            journal,
            _store: store,
            _proxy: proxy,
        }
    }
    fn plan(&self) -> SandboxPlan {
        let runtime = std::env::current_exe().unwrap().canonicalize().unwrap();
        let bundle = self
            .home
            .join("extensions/store/barrier-probe/1.0.0-000000000000");
        let data = self.home.join("extensions/data/barrier-probe");
        let real_home = self.root.as_ref().unwrap().path().join("user");
        for path in [&bundle, &data, &real_home] {
            fs::create_dir_all(path).unwrap();
        }
        SandboxPlan::new(
            SandboxProfile {
                read_paths: vec![],
                write_paths: vec![self.workspace.clone()],
                spawn: true,
                kernel_socket: None,
                proxy: ProxyEndpoint::Unix(self.home.join("run/proxy.sock")),
                env: BTreeMap::from([(
                    "FX_BARRIER_MARKER".into(),
                    self.marker.to_string_lossy().into_owned(),
                )]),
                cwd: self.workspace.clone(),
                tier: Tier::Os,
            },
            SandboxContext {
                fictor_home: self.home.clone(),
                real_home,
                bundle_root: bundle,
                ext_data: data,
                tmp_dir: self.journal.temporary_path(),
                runtime_root: runtime.parent().unwrap().into(),
                runtime,
                fictor_exe: PathBuf::from(env!("CARGO_BIN_EXE_fictor")),
                home_ro_files: vec![],
                allow_store_read: false,
            },
            [
                "--exact",
                "barrier_workload_probe",
                "--nocapture",
                "--test-threads=1",
            ]
            .map(Into::into)
            .into(),
        )
        .unwrap()
    }
    fn spawn(&self, mut command: Command) -> Running {
        self.removable.store(false, Ordering::SeqCst);
        Running {
            child: command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        }
    }
    fn persisted(&self) -> StateRecord {
        StateRecord::parse(
            &fs::read(
                self.home
                    .join("run/instances")
                    .join(&self.journal.record().instance_id)
                    .join("state.json"),
            )
            .unwrap(),
            &self.journal.record().instance_id,
        )
        .unwrap()
    }
    async fn confirm(
        &self,
        process: &mut Running,
        launcher: &ProcessHandle,
        init: &ProcessHandle,
    ) -> std::process::ExitStatus {
        let status = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(status) = process.child.try_wait().unwrap() {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        assert!(init.wait_exited(deadline).unwrap());
        assert!(launcher.wait_exited(deadline).unwrap());
        // Manual fixture teardown is safe after both pinned processes ended;
        // assertions below still exercise production's conservative journal.
        self.removable.store(true, Ordering::SeqCst);
        status
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if !self.removable.load(Ordering::SeqCst) {
            // A failed test cannot turn an unconfirmed process into cleanup.
            if let Some(root) = self.root.take() {
                let _ = root.keep();
            }
        }
    }
}
struct Running {
    child: Child,
}
impl Drop for Running {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[tokio::test]
async fn workload_waits_for_durable_armed_and_receives_no_barrier_descriptors() {
    let mut fixture = Fixture::new().await;
    let listener = AdmissionListener::bind(&fixture.journal.admission_socket_path()).unwrap();
    let plan = fixture.plan();
    let command = plan.command_with_admission(&listener).unwrap();
    fixture.journal.spawning().unwrap();
    let mut running = fixture.spawn(command);
    let launcher = ProcessHandle::capture(running.child.id(), false).unwrap();
    let pending = listener.accept(Duration::from_secs(5)).await.unwrap();
    let init = ProcessHandle::capture(pending.peer_pid(), true).unwrap();
    assert_ne!(pending.peer_pid(), running.child.id());
    assert_eq!(fixture.persisted().state, InstanceState::Spawning);
    assert!(!fixture.marker.exists());
    fixture.journal.arm(&launcher, &init).unwrap();
    let persisted = fixture.persisted();
    assert_eq!(persisted.state, InstanceState::Armed);
    assert_eq!(persisted.init.unwrap(), init.identity());
    assert!(
        !fixture.marker.exists(),
        "armed alone does not release the channel"
    );
    pending.release().await.unwrap();
    assert_eq!(
        fixture.confirm(&mut running, &launcher, &init).await.code(),
        Some(17)
    );
    assert_eq!(fs::read(&fixture.marker).unwrap(), b"started");
    fixture.journal.cleanup_confirmed(&launcher, &init).unwrap();
    assert!(!fixture.journal.temporary_path().exists());
    assert!(!fixture.journal.admission_socket_path().exists());
}

#[tokio::test]
async fn closed_channel_does_not_execute_or_promote_a_spawning_journal() {
    let mut fixture = Fixture::new().await;
    let listener = AdmissionListener::bind(&fixture.journal.admission_socket_path()).unwrap();
    let plan = fixture.plan();
    let command = plan.command_with_admission(&listener).unwrap();
    fixture.journal.spawning().unwrap();
    let mut running = fixture.spawn(command);
    let launcher = ProcessHandle::capture(running.child.id(), false).unwrap();
    let pending = listener.accept(Duration::from_secs(5)).await.unwrap();
    let init = ProcessHandle::capture(pending.peer_pid(), true).unwrap();
    drop(pending);
    assert!(
        !fixture
            .confirm(&mut running, &launcher, &init)
            .await
            .success()
    );
    assert!(!fixture.marker.exists());
    assert_eq!(fixture.persisted().state, InstanceState::Spawning);
    assert!(fixture.journal.cleanup_confirmed(&launcher, &init).is_err());
    assert!(fixture.journal.temporary_path().exists());
}

#[tokio::test]
async fn failed_journal_publication_keeps_workload_blocked_until_channel_aborts() {
    let mut fixture = Fixture::new().await;
    let listener = AdmissionListener::bind(&fixture.journal.admission_socket_path()).unwrap();
    let plan = fixture.plan();
    let command = plan.command_with_admission(&listener).unwrap();
    fixture.journal.spawning().unwrap();
    let mut running = fixture.spawn(command);
    let launcher = ProcessHandle::capture(running.child.id(), false).unwrap();
    let pending = listener.accept(Duration::from_secs(5)).await.unwrap();
    let init = ProcessHandle::capture(pending.peer_pid(), true).unwrap();
    let state = fixture
        .home
        .join("run/instances")
        .join(&fixture.journal.record().instance_id)
        .join("state.json");
    fs::write(&state, b"invalid fixture state").unwrap();
    assert!(fixture.journal.arm(&launcher, &init).is_err());
    assert!(!fixture.marker.exists());
    drop(pending); // Only successful arm may call release.
    assert!(
        !fixture
            .confirm(&mut running, &launcher, &init)
            .await
            .success()
    );
    assert!(!fixture.marker.exists());
    assert_eq!(fs::read(state).unwrap(), b"invalid fixture state");
}

#[test]
fn barrier_workload_probe() {
    let Some(marker) = std::env::var_os("FX_BARRIER_MARKER") else {
        return;
    };
    let descriptors: Vec<_> = fs::read_dir("/proc/self/fd")
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    for descriptor in descriptors {
        if descriptor
            .file_name()
            .unwrap()
            .to_string_lossy()
            .parse::<u32>()
            .unwrap()
            >= 3
            && let Ok(target) = fs::read_link(descriptor)
        {
            assert!(
                !target.to_string_lossy().starts_with("socket:"),
                "barrier channel leaked into workload"
            );
        }
    }
    fs::write(marker, b"started").unwrap();
    std::process::exit(17);
}
