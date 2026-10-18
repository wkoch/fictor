use fictor::{
    installer::{
        lease::InstallerLease,
        recovery::{self, DiagnosticCode, RecoveryError, RecoveryReport},
    },
    store::{
        NewProposal, ProposalCheck, ProposalIdentity, ProposalState as State, ProposalUpdate, Store,
    },
};
use serde_json::json;
use std::{
    fs,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    sync::Arc,
};

async fn recover(home: &Path, store: Arc<Store>) -> Result<RecoveryReport, RecoveryError> {
    let lease = Arc::new(InstallerLease::acquire(home).unwrap());
    recovery::recover(home, store, lease).await
}

async fn fixture() -> (tempfile::TempDir, Arc<Store>) {
    let home = tempfile::Builder::new()
        .prefix("fx-recovery-")
        .tempdir_in("/tmp")
        .unwrap();
    fictor::home::prepare(home.path()).unwrap();
    let store = Arc::new(Store::open(home.path()).await.unwrap());
    (home, store)
}
async fn begin(store: &Store) -> String {
    store
        .begin_attempt(NewProposal {
            source: json!({"kind":"local","path":"/never-open-or-execute-during-recovery"}),
            tainted: true,
        })
        .await
        .unwrap()
        .id
}
async fn identify(store: &Store, id: &str) {
    let manifest = json!({"schema":1,"id":"recovery-sample","version":"1.0.0",
        "description":"Recovery fixture","runtime":{"kind":"none"}});
    let manifest = serde_json::to_value(
        fictor::installer::manifest::Manifest::parse(&manifest.to_string()).unwrap(),
    )
    .unwrap();
    store
        .transition_proposal(
            id.into(),
            State::Received,
            State::Checking,
            ProposalUpdate {
                identity: Some(ProposalIdentity {
                    ext_id: "recovery-sample".into(),
                    version: "1.0.0".into(),
                    manifest,
                    update_of: None,
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
}
async fn reopen(home: &Path, store: Arc<Store>) -> Arc<Store> {
    Arc::try_unwrap(store)
        .ok()
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    Arc::new(Store::open(home).await.unwrap())
}
fn quarantine(home: &Path) -> PathBuf {
    home.join("extensions/quarantine")
}
fn receipt(home: &Path, id: &str) -> PathBuf {
    quarantine(home).join(format!(".receipt-{id}"))
}
fn interrupted_check(check: &ProposalCheck) -> bool {
    check.name == "recovery"
        && !check.passed
        && check.blocking
        && check.detail.as_deref() == Some("recovery:interrupted")
}

#[tokio::test]
async fn restart_recovers_each_receipt_window_without_reading_or_running_the_origin() {
    let (home, store) = fixture().await;
    let mut ids = Vec::new();
    for phase in ["initial_commit", "copying", "renamed", "checking"] {
        let id = begin(&store).await;
        if phase == "copying" {
            fs::create_dir(receipt(home.path(), &id)).unwrap();
            fs::write(
                receipt(home.path(), &id).join("partial"),
                "incomplete bytes",
            )
            .unwrap();
        }
        if matches!(phase, "renamed" | "checking") {
            let final_path = quarantine(home.path()).join(&id);
            fs::create_dir(&final_path).unwrap();
            fs::write(
                final_path.join("server"),
                "never execute incomplete candidate",
            )
            .unwrap();
        }
        if phase == "checking" {
            identify(&store, &id).await;
        }
        ids.push((id, phase));
    }
    let store = reopen(home.path(), store).await;
    let report = recover(home.path(), store.clone()).await.unwrap();
    assert!(report.diagnostics.is_empty());
    for (id, phase) in &ids {
        let proposal = store.proposal(id.clone()).await.unwrap();
        assert_eq!(proposal.state, State::Failed);
        assert!(proposal.tainted);
        assert_eq!(
            proposal.source["path"],
            "/never-open-or-execute-during-recovery"
        );
        assert_eq!(
            proposal
                .checks
                .unwrap()
                .iter()
                .filter(|c| interrupted_check(c))
                .count(),
            1
        );
        assert_eq!(proposal.ext_id.is_some(), *phase == "checking");
        assert_eq!(proposal.version.is_some(), *phase == "checking");
        assert!(!receipt(home.path(), id).exists());
        assert_eq!(
            quarantine(home.path()).join(id).exists(),
            *phase == "checking"
        );
    }
    let events = store
        .event_path("sys".into(), None, None)
        .await
        .unwrap()
        .events;
    assert_eq!(
        events.iter().filter(|e| e.kind == "ext.failed").count(),
        ids.len()
    );
    for event in events.iter().filter(|e| e.kind == "ext.failed") {
        assert_eq!(event.payload["reason"], "recovery:interrupted");
    }
    let before = serde_json::to_value(&events).unwrap();
    let store = reopen(home.path(), store).await;
    assert!(
        recover(home.path(), store.clone())
            .await
            .unwrap()
            .diagnostics
            .is_empty()
    );
    assert_eq!(
        serde_json::to_value(
            store
                .event_path("sys".into(), None, None)
                .await
                .unwrap()
                .events
        )
        .unwrap(),
        before
    );
}

#[tokio::test]
async fn recovery_preserves_existing_checks_identity_and_every_terminal_state() {
    let (home, store) = fixture().await;
    let mut ids = Vec::new();
    for state in [
        "received", "checking", "checked", "approved", "rejected", "promoted", "failed",
    ] {
        let id = begin(&store).await;
        identify(&store, &id).await;
        fs::create_dir(quarantine(home.path()).join(&id)).unwrap();
        fs::create_dir(receipt(home.path(), &id)).unwrap();
        ids.push((id, state));
    }
    // Persisted intermediate/legacy fixtures are installed with no Store writer
    // running. Production mutations remain on the Store's single writer task.
    Arc::try_unwrap(store)
        .ok()
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    let db = rusqlite::Connection::open(home.path().join("fictor.db")).unwrap();
    let checks =
        json!([{"name":"existing","passed":true,"blocking":false,"detail":"kept"}]).to_string();
    for (id, state) in &ids {
        db.execute(
            "UPDATE proposals SET state=?1,checks=?2 WHERE id=?3",
            rusqlite::params![state, checks, id],
        )
        .unwrap();
    }
    drop(db);
    let store = Arc::new(Store::open(home.path()).await.unwrap());
    let mut terminal_before = Vec::new();
    for (id, state) in &ids {
        if !matches!(*state, "received" | "checking") {
            terminal_before.push((
                id,
                serde_json::to_value(store.proposal(id.clone()).await.unwrap()).unwrap(),
            ));
        }
    }
    let report = recover(home.path(), store.clone()).await.unwrap();
    assert!(report.diagnostics.is_empty());
    for (id, state) in &ids {
        let proposal = store.proposal(id.clone()).await.unwrap();
        assert_eq!(proposal.ext_id.as_deref(), Some("recovery-sample"));
        assert_eq!(proposal.version.as_deref(), Some("1.0.0"));
        assert!(quarantine(home.path()).join(id).exists());
        assert!(!receipt(home.path(), id).exists());
        if matches!(*state, "received" | "checking") {
            let checks = proposal.checks.unwrap();
            assert_eq!(checks[0].name, "existing");
            assert_eq!(checks[0].detail.as_deref(), Some("kept"));
            assert_eq!(checks.iter().filter(|c| interrupted_check(c)).count(), 1);
        }
    }
    for (id, before) in terminal_before {
        assert_eq!(
            serde_json::to_value(store.proposal(id.clone()).await.unwrap()).unwrap(),
            before
        );
    }
}

#[tokio::test]
async fn orphan_receipts_and_links_cannot_delete_origin_store_or_unknown_directories() {
    let (home, store) = fixture().await;
    let external = tempfile::tempdir().unwrap();
    fs::write(external.path().join("keep"), "external").unwrap();
    let store_path = home.path().join("extensions/store/keep");
    fs::write(&store_path, "approved bundle").unwrap();
    let orphan_link = ulid::Ulid::generate().to_string();
    symlink(external.path(), receipt(home.path(), &orphan_link)).unwrap();
    let orphan_tree = ulid::Ulid::generate().to_string();
    fs::create_dir(receipt(home.path(), &orphan_tree)).unwrap();
    symlink(
        &store_path,
        receipt(home.path(), &orphan_tree).join("linked-store"),
    )
    .unwrap();
    symlink(
        external.path(),
        receipt(home.path(), &orphan_tree).join("linked-directory"),
    )
    .unwrap();
    let unknown = quarantine(home.path()).join("unrecognized-directory");
    fs::create_dir(&unknown).unwrap();
    fs::write(unknown.join("keep"), "unknown").unwrap();
    let unknown_final = quarantine(home.path()).join(ulid::Ulid::generate().to_string());
    fs::create_dir(&unknown_final).unwrap();
    let malformed = quarantine(home.path()).join(".receipt-not-a-ULID");
    fs::create_dir(&malformed).unwrap();
    let report = recover(home.path(), store.clone()).await.unwrap();
    assert_eq!(report.diagnostics.len(), 2);
    assert!(
        report
            .diagnostics
            .iter()
            .all(|d| d.code == DiagnosticCode::OrphanReceipt)
    );
    assert!(
        receipt(home.path(), &orphan_link)
            .symlink_metadata()
            .is_err()
    );
    assert!(!receipt(home.path(), &orphan_tree).exists());
    assert_eq!(
        fs::read_to_string(external.path().join("keep")).unwrap(),
        "external"
    );
    assert_eq!(fs::read_to_string(&store_path).unwrap(), "approved bundle");
    assert!(unknown.join("keep").exists() && unknown_final.exists() && malformed.exists());
    for id in [orphan_link, orphan_tree] {
        assert!(matches!(
            store.proposal(id).await,
            Err(fictor::store::StoreError::NotFound)
        ));
    }
    assert!(
        store
            .event_path("sys".into(), None, None)
            .await
            .unwrap()
            .events
            .is_empty()
    );
}

#[tokio::test]
async fn cleanup_failure_is_diagnosed_and_retried_without_losing_the_durable_failure() {
    let (home, store) = fixture().await;
    let id = begin(&store).await;
    fs::create_dir(receipt(home.path(), &id)).unwrap();
    fs::create_dir(quarantine(home.path()).join(&id)).unwrap();
    let lease = Arc::new(InstallerLease::acquire(home.path()).unwrap());
    let real_quarantine = home.path().join("extensions/quarantine-saved");
    fs::rename(quarantine(home.path()), &real_quarantine).unwrap();
    let external = tempfile::tempdir().unwrap();
    fs::write(external.path().join("keep"), "outside").unwrap();
    symlink(external.path(), quarantine(home.path())).unwrap();
    let report = recovery::recover(home.path(), store.clone(), lease)
        .await
        .unwrap();
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::CleanupFailed)
    );
    assert_eq!(
        store.proposal(id.clone()).await.unwrap().state,
        State::Failed
    );
    assert!(real_quarantine.join(format!(".receipt-{id}")).exists());
    fs::remove_file(quarantine(home.path())).unwrap();
    fs::rename(real_quarantine, quarantine(home.path())).unwrap();
    let store = reopen(home.path(), store).await;
    assert!(
        recover(home.path(), store.clone())
            .await
            .unwrap()
            .diagnostics
            .is_empty()
    );
    assert!(!receipt(home.path(), &id).exists() && !quarantine(home.path()).join(&id).exists());
    assert_eq!(
        fs::read_to_string(external.path().join("keep")).unwrap(),
        "outside"
    );
    let events = store
        .event_path("sys".into(), None, None)
        .await
        .unwrap()
        .events;
    assert_eq!(events.iter().filter(|e| e.kind == "ext.failed").count(), 1);
}

#[tokio::test]
async fn failed_database_reconciliation_prevents_cleanup() {
    let (home, store) = fixture().await;
    let id = begin(&store).await;
    fs::create_dir(receipt(home.path(), &id)).unwrap();
    // A failing database transaction must leave both state and filesystem alone.
    let db = rusqlite::Connection::open(home.path().join("fictor.db")).unwrap();
    db.execute_batch("CREATE TRIGGER reject_recovery BEFORE UPDATE ON proposals BEGIN SELECT RAISE(ABORT, 'fixture'); END;").unwrap();
    assert!(recover(home.path(), store.clone()).await.is_err());
    assert_eq!(
        store.proposal(id.clone()).await.unwrap().state,
        State::Received
    );
    assert!(receipt(home.path(), &id).exists());
    assert_eq!(
        store
            .event_path("sys".into(), None, None)
            .await
            .unwrap()
            .events
            .len(),
        1
    );
}

#[tokio::test]
async fn cancelling_recovery_keeps_the_lease_until_its_detached_worker_finishes() {
    let (home, store) = fixture().await;
    let id = begin(&store).await;
    // A SQLite read-to-write upgrade can fail BUSY immediately; park the actual
    // writer instead so recovery is guaranteed to remain pending after abort.
    let (writer_started, writer_ready) = tokio::sync::oneshot::channel();
    let (release_writer, writer_release) = std::sync::mpsc::channel();
    let blocked_store = store.clone();
    let blocker = tokio::spawn(async move {
        blocked_store
            .write(move |_| {
                let _ = writer_started.send(());
                // Sender Drop also releases the writer if the test unwinds.
                let _ = writer_release.recv();
                Ok(())
            })
            .await
    });
    writer_ready.await.unwrap();
    let lease = Arc::new(InstallerLease::acquire(home.path()).unwrap());
    let path = home.path().to_path_buf();
    let worker_store = store.clone();
    let (started, ready) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _ = started.send(());
        recovery::recover(&path, worker_store, lease).await
    });
    // This current-thread runtime runs the task through its first await, which
    // schedules the owning blocking worker before polling this receiver again.
    ready.await.unwrap();
    task.abort();
    let cancellation = task.await;
    let acquired = InstallerLease::acquire(home.path());
    let retained =
        matches!(&acquired, Err(error) if error.kind() == std::io::ErrorKind::WouldBlock);
    let acquisition_error = acquired.as_ref().err().map(std::io::Error::kind);
    drop(acquired);
    // Release before asserting, so a failing regression cannot park the writer.
    let released = release_writer.send(());
    let unblocked = blocker.await;
    assert!(cancellation.unwrap_err().is_cancelled());
    assert!(
        retained,
        "lease released while recovery was pending: acquire error {acquisition_error:?}"
    );
    released.unwrap();
    unblocked.unwrap().unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if store.proposal(id.clone()).await.unwrap().state == State::Failed
                && InstallerLease::acquire(home.path()).is_ok()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[test]
fn cleanup_helper_refuses_unrecognized_ids() {
    let home = tempfile::tempdir().unwrap();
    fictor::home::prepare(home.path()).unwrap();
    for id in ["../store", "/outside", "", ".", "01J-not-valid"] {
        assert!(recovery::remove_receipt(home.path(), id, true).is_err());
    }
}
