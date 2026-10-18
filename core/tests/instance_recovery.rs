use fictor::{
    instance_recovery::{
        self, DiagnosticCode, InstanceError, InstanceJournal, InstanceState, NewInstance,
        ProcessHandle, StateRecord,
    },
    store::{EventQuery, Store},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::{
        fs::{PermissionsExt, symlink},
        net::UnixListener,
    },
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

struct Fixture {
    home: tempfile::TempDir,
    store: Arc<Store>,
}
impl Fixture {
    async fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fictor::initialize(home.path()).await.unwrap();
        let store = Arc::new(Store::open(home.path()).await.unwrap());
        Self { home, store }
    }
    fn journal(&self) -> InstanceJournal {
        InstanceJournal::prepare(
            self.store.owner().clone(),
            NewInstance {
                instance_id: ulid::Ulid::generate().to_string(),
                ext_id: "example".into(),
                key: "1.2.3-0123456789ab".into(),
                session_id: Some(ulid::Ulid::generate().to_string()),
            },
        )
        .unwrap()
    }
    fn state(&self, journal: &InstanceJournal) -> PathBuf {
        self.home
            .path()
            .join("run/instances")
            .join(&journal.record().instance_id)
            .join("state.json")
    }
    fn orphan(&self, journal: &InstanceJournal, edit: impl FnOnce(&mut Value)) -> StateRecord {
        let path = self.state(journal);
        let mut value = serde_json::to_value(journal.record()).unwrap();
        // Represent a dead predecessor without relying on PID allocation/timing.
        value["owner"]["start_ticks"] =
            json!((journal.record().owner.start_ticks.0 + 1).to_string());
        edit(&mut value);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        StateRecord::parse(&fs::read(path).unwrap(), &journal.record().instance_id).unwrap()
    }
    async fn failures(&self) -> Vec<fictor::store::Event> {
        self.store
            .query_events(EventQuery {
                session_id: Some("sys".into()),
                kinds: vec!["ext.cleanup_failed".into()],
                ..Default::default()
            })
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn durable_transitions_preserve_shape_and_never_clean_on_drop_or_error() {
    let fixture = Fixture::new().await;
    let mut journal = fixture.journal();
    let path = fixture.state(&journal);
    let first = fs::read(&path).unwrap();
    let record = StateRecord::parse(&first, &journal.record().instance_id).unwrap();
    assert_eq!(record.state, InstanceState::Prepared);
    assert!(record.launcher.is_none());
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    let tmp = journal.create_temporary().unwrap();
    fs::write(tmp.join("canary"), "retained").unwrap();
    journal.spawning().unwrap();
    let bytes = fs::read(&path).unwrap();
    assert_eq!(
        StateRecord::parse(&bytes, &record.instance_id)
            .unwrap()
            .state,
        InstanceState::Spawning
    );
    let process = ProcessHandle::capture(std::process::id(), false).unwrap();
    journal.record_launcher(&process).unwrap();
    let before = fs::read(&path).unwrap();
    assert!(journal.arm(&process, &process).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    drop(journal);
    assert_eq!(fs::read_to_string(tmp.join("canary")).unwrap(), "retained");
    assert!(path.exists());
}

#[tokio::test]
async fn strict_records_require_all_nullable_fields_and_canonical_identity_strings() {
    let fixture = Fixture::new().await;
    let journal = fixture.journal();
    let record = serde_json::to_value(journal.record()).unwrap();
    let id = &journal.record().instance_id;
    for field in ["session_id", "launcher", "init", "sandbox_pidns"] {
        let mut bad = record.clone();
        bad.as_object_mut().unwrap().remove(field);
        assert!(
            StateRecord::parse(&serde_json::to_vec(&bad).unwrap(), id).is_err(),
            "missing {field}"
        );
    }
    for (field, value) in [
        ("schema", json!(2)),
        ("state", json!("cleanup_failed")),
        ("extra", json!(true)),
        ("instance_id", json!(ulid::Ulid::generate().to_string())),
        ("key", json!("../../workspace")),
        ("boot_id", json!("not-a-uuid")),
    ] {
        let mut bad = record.clone();
        bad[field] = value;
        assert!(
            StateRecord::parse(&serde_json::to_vec(&bad).unwrap(), id).is_err(),
            "invalid {field}"
        );
    }
    for value in [
        json!(0),
        json!("00"),
        json!("+1"),
        json!("18446744073709551616"),
    ] {
        let mut bad = record.clone();
        bad["owner"]["start_ticks"] = value;
        assert!(StateRecord::parse(&serde_json::to_vec(&bad).unwrap(), id).is_err());
    }
    let duplicate = String::from_utf8(serde_json::to_vec(&record).unwrap())
        .unwrap()
        .replacen("\"schema\":1", "\"schema\":1,\"sch\\u0065ma\":1", 1);
    assert!(StateRecord::parse(duplicate.as_bytes(), id).is_err());
    let mut nested = record.clone();
    nested["owner"]["unknown"] = json!(0);
    assert!(StateRecord::parse(&serde_json::to_vec(&nested).unwrap(), id).is_err());
}

#[tokio::test]
async fn prepared_cleanup_needs_no_observer_match_but_existing_roots_must_be_readable() {
    let fixture = Fixture::new().await;
    let journal = fixture.journal();
    let state = fixture.state(&journal);
    fixture.orphan(&journal, |value| {
        value["observer_pidns"]["ino"] =
            json!((journal.record().observer_pidns.ino.0 + 1).to_string())
    });
    drop(journal);
    let kernel = fixture.home.path().join("run/k");
    fs::remove_dir(&kernel).unwrap();
    assert!(
        instance_recovery::recover(fixture.store.clone())
            .await
            .is_err()
    );
    assert!(state.exists());
    // Restoring a missing root is a deliberate test action, never recovery's job.
    fs::create_dir(&kernel).unwrap();
    fs::set_permissions(&kernel, fs::Permissions::from_mode(0o700)).unwrap();
    let report = instance_recovery::recover(fixture.store.clone())
        .await
        .unwrap();
    assert_eq!(report.removed.len(), 1);
    assert!(!state.exists());
    let mut journal = fixture.journal();
    let state = fixture.state(&journal);
    journal.create_temporary().unwrap();
    journal.cleanup_prepared().unwrap();
    assert!(!state.exists());
    journal = fixture.journal();
    let state = fixture.state(&journal);
    journal.spawning().unwrap();
    assert!(journal.cleanup_prepared().is_err());
    assert!(state.exists());
}

#[tokio::test]
async fn prepared_cleanup_is_confined_durable_and_idempotent() {
    let fixture = Fixture::new().await;
    let journal = fixture.journal();
    let tmp = journal.create_temporary().unwrap();
    let unrelated = tempfile::tempdir().unwrap();
    fs::write(unrelated.path().join("sentinel"), "outside").unwrap();
    for directory in [
        "workspace",
        "extensions/data/example",
        "extensions/store/example/other",
    ] {
        fs::create_dir_all(fixture.home.path().join(directory)).unwrap();
        fs::write(fixture.home.path().join(directory).join("sentinel"), "keep").unwrap();
    }
    fs::create_dir(tmp.join("nested")).unwrap();
    fs::write(tmp.join("nested/owned"), "discard").unwrap();
    symlink(unrelated.path(), tmp.join("external")).unwrap();
    let kernel = UnixListener::bind(journal.kernel_socket_path()).unwrap();
    fs::set_permissions(
        journal.kernel_socket_path(),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let admission = UnixListener::bind(journal.admission_socket_path()).unwrap();
    fs::set_permissions(
        journal.admission_socket_path(),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let record = fixture.orphan(&journal, |_| {});
    drop(journal);
    let report = instance_recovery::recover(fixture.store.clone())
        .await
        .unwrap();
    assert_eq!(report.removed, vec![record.instance_id.clone()]);
    assert!(report.diagnostics.is_empty());
    assert!(!tmp.exists());
    assert!(
        !fixture
            .home
            .path()
            .join("run/k")
            .join(format!("{}.sock", record.instance_id))
            .exists()
    );
    assert_eq!(
        fs::read_to_string(unrelated.path().join("sentinel")).unwrap(),
        "outside"
    );
    for directory in [
        "workspace",
        "extensions/data/example",
        "extensions/store/example/other",
    ] {
        assert_eq!(
            fs::read_to_string(fixture.home.path().join(directory).join("sentinel")).unwrap(),
            "keep"
        );
    }
    assert!(fixture.failures().await.is_empty());
    let repeated = instance_recovery::recover(fixture.store.clone())
        .await
        .unwrap();
    assert!(repeated.removed.is_empty());
    assert!(repeated.diagnostics.is_empty());
    drop((kernel, admission));
}

#[tokio::test]
async fn spawning_retains_same_boot_and_reboot_cleans_only_valid_owned_records() {
    let fixture = Fixture::new().await;
    let mut journal = fixture.journal();
    let tmp = journal.create_temporary().unwrap();
    fs::write(tmp.join("keep"), "partial").unwrap();
    journal.spawning().unwrap();
    let record = fixture.orphan(&journal, |_| {});
    drop(journal);
    let report = instance_recovery::recover(fixture.store.clone())
        .await
        .unwrap();
    assert!(report.removed.is_empty());
    assert_eq!(report.diagnostics[0].code, DiagnosticCode::Uncertain);
    assert!(tmp.exists());
    let events = fixture.failures().await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].payload["instance_id"], record.instance_id);
    assert_eq!(events[0].payload["key"], record.key);
    let path = fixture
        .home
        .path()
        .join("run/instances")
        .join(&record.instance_id)
        .join("state.json");
    let mut value = serde_json::to_value(record).unwrap();
    value["boot_id"] = json!("00000000-0000-0000-0000-000000000000");
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let report = instance_recovery::recover(fixture.store.clone())
        .await
        .unwrap();
    assert_eq!(report.removed.len(), 1);
    assert!(!path.exists());
}

#[tokio::test]
async fn malformed_missing_and_linked_records_remain_without_invented_events() {
    let fixture = Fixture::new().await;
    let good = fixture.journal();
    let base = fixture.home.path().join("run/instances");
    let outside = tempfile::tempdir().unwrap();
    let sentinel = outside.path().join("state.json");
    fs::write(&sentinel, "external").unwrap();
    for content in [
        None,
        Some(b"{".as_slice()),
        Some(b"{\"schema\":2}".as_slice()),
    ] {
        let id = ulid::Ulid::generate().to_string();
        let directory = base.join(id);
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        if let Some(content) = content {
            fs::write(directory.join("state.json"), content).unwrap();
            fs::set_permissions(
                directory.join("state.json"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
    }
    let linked = base.join(ulid::Ulid::generate().to_string());
    symlink(outside.path(), &linked).unwrap();
    let state_link = base.join(ulid::Ulid::generate().to_string());
    fs::create_dir(&state_link).unwrap();
    fs::set_permissions(&state_link, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&sentinel, state_link.join("state.json")).unwrap();
    // A valid current owner is an inconsistency, before any cleanup is allowed.
    assert!(matches!(
        instance_recovery::recover(fixture.store.clone()).await,
        Err(InstanceError::OwnerAlive)
    ));
    fs::remove_file(fixture.state(&good)).unwrap();
    drop(good);
    let report = instance_recovery::recover(fixture.store.clone())
        .await
        .unwrap();
    assert_eq!(report.diagnostics.len(), 6);
    assert!(report.removed.is_empty());
    assert!(fixture.failures().await.is_empty());
    assert_eq!(fs::read_to_string(sentinel).unwrap(), "external");
    assert!(linked.is_symlink());
    assert!(state_link.join("state.json").is_symlink());
}

#[tokio::test]
async fn invalid_tmp_root_and_unknown_entries_retain_authority_and_retry() {
    let fixture = Fixture::new().await;
    let journal = fixture.journal();
    let tmp = journal.temporary_path();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("sentinel"), "external").unwrap();
    symlink(outside.path(), &tmp).unwrap();
    let state = fixture.state(&journal);
    fixture.orphan(&journal, |_| {});
    drop(journal);
    let report = instance_recovery::recover(fixture.store.clone())
        .await
        .unwrap();
    assert_eq!(report.diagnostics[0].code, DiagnosticCode::CleanupFailed);
    assert!(state.exists());
    assert!(tmp.is_symlink());
    assert_eq!(
        fs::read_to_string(outside.path().join("sentinel")).unwrap(),
        "external"
    );
    fs::remove_file(&tmp).unwrap();
    fs::create_dir(&tmp).unwrap();
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o700)).unwrap();
    let unknown = state.parent().unwrap().join("unattributed");
    fs::write(&unknown, "do not infer ownership").unwrap();
    let report = instance_recovery::recover(fixture.store.clone())
        .await
        .unwrap();
    assert_eq!(report.diagnostics[0].code, DiagnosticCode::CleanupFailed);
    assert!(state.exists());
    assert!(unknown.exists());
    fs::remove_file(unknown).unwrap();
    let report = instance_recovery::recover(fixture.store.clone())
        .await
        .unwrap();
    assert_eq!(report.removed.len(), 1);
    assert!(!state.exists());
}

#[tokio::test]
async fn reused_numeric_pids_are_not_signalled_and_observer_mismatch_is_uncertain() {
    let fixture = Fixture::new().await;
    let journal = fixture.journal();
    let tmp = journal.create_temporary().unwrap();
    let current = ProcessHandle::capture(std::process::id(), false).unwrap();
    fixture.orphan(&journal,|value|{value["state"]=json!("armed");let reused=json!({"pid":std::process::id(),"start_ticks":(current.identity().start_ticks.0+1).to_string()});value["launcher"]=reused.clone();value["init"]=reused;value["sandbox_pidns"]=json!({"dev":current.namespace().dev.0.to_string(),"ino":(current.namespace().ino.0+1).to_string()});});
    drop(journal);
    let report = instance_recovery::recover(fixture.store.clone())
        .await
        .unwrap();
    assert_eq!(report.removed.len(), 1);
    assert!(!tmp.exists());
    assert!(!current.is_exited().unwrap());
    let mut journal = fixture.journal();
    journal.spawning().unwrap();
    let state = fixture.state(&journal);
    fixture.orphan(&journal, |value| {
        value["observer_pidns"]["ino"] = json!((current.namespace().ino.0 + 1).to_string())
    });
    drop(journal);
    let report = instance_recovery::recover(fixture.store.clone())
        .await
        .unwrap();
    assert_eq!(report.diagnostics[0].code, DiagnosticCode::Uncertain);
    assert!(state.exists());
}

#[test]
fn pidfd_pins_a_real_process_and_only_confirms_exit_after_it_finishes() {
    let mut child = Command::new("/usr/bin/sh")
        .args(["-c", "printf 'ready\\n'; read line"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!(line, "ready\n");
    let handle = ProcessHandle::capture(child.id(), false).unwrap();
    assert!(!handle.is_exited().unwrap());
    assert!(
        !handle
            .wait_exited(Instant::now() + Duration::from_millis(10))
            .unwrap()
    );
    assert!(ProcessHandle::capture(std::process::id(), true).is_err());
    child.stdin.take().unwrap().write_all(b"finish\n").unwrap();
    assert!(child.wait().unwrap().success());
    assert!(
        handle
            .wait_exited(Instant::now() + Duration::from_secs(1))
            .unwrap()
    );
}
