//! Real process-crash recovery. SIGKILL leaves SQLite/WAL open in the worker;
//! this does not simulate power loss or replace the FULL durability checks.
use fictor::{
    config::Config,
    gateway::PinnedCatalog,
    installer::{
        activation::PromotionCoordinator,
        lease::InstallerLease,
        local::LocalChecker,
        lock::{Approval, Lock, LockedExtension, LockedVersion, Package, approval_at_ms},
        overrides::Overrides,
        promotion::materialize,
    },
    ownership::HomeLease,
    proxy::{EgressProxy, nat64::Nat64Prefixes},
    secrets::{BackendKind, Redactor, SecretStore},
    store::{NewPromotionIntent, PromotionState, Proposal, ProposalCheck, ProposalState, Store},
    supervisor::Supervisor,
};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        process::ExitStatusExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};

const ROOT: &str = "FICTOR_TEST_PROMOTION_CRASH_ROOT";
const CUTPOINT: &str = "FICTOR_TEST_PROMOTION_CRASH_CUTPOINT";
const READY: &str = "FICTOR_PROMOTION_CRASH_READY ";
const EXTENSION: &str = "crash-fixture";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Cutpoint {
    AfterJournal,
    BeforeLock,
    AfterLock,
    AfterCommit,
}
impl Cutpoint {
    fn name(self) -> &'static str {
        match self {
            Self::AfterJournal => "after_journal",
            Self::BeforeLock => "before_lock",
            Self::AfterLock => "after_lock",
            Self::AfterCommit => "after_commit",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    cutpoint: Cutpoint,
    proposal_id: String,
    operation_id: String,
    previous_key: String,
    candidate_key: String,
    checks: Vec<ProposalCheck>,
}

/// Only an explicitly selected helper runs the worker; the normal test is inert.
#[tokio::test]
async fn promotion_crash_worker() {
    let Some(root) = std::env::var_os(ROOT) else {
        return;
    };
    let cutpoint = match std::env::var(CUTPOINT).unwrap().as_str() {
        "after_journal" => Cutpoint::AfterJournal,
        "before_lock" => Cutpoint::BeforeLock,
        "after_lock" => Cutpoint::AfterLock,
        "after_commit" => Cutpoint::AfterCommit,
        _ => panic!("unknown fixture cutpoint"),
    };
    worker(Path::new(&root), cutpoint).await;
}

async fn approved(
    root: &Path,
    version: &str,
    store: Arc<Store>,
    supervisor: Arc<Supervisor>,
) -> (Proposal, PinnedCatalog, Arc<InstallerLease>) {
    let source = root.join(format!("source-{version}"));
    fs::create_dir(&source).unwrap();
    fs::write(
        source.join("fictor.yaml"),
        format!(
            "schema: 1\nid: {EXTENSION}\nversion: {version}\ndescription: Inert crash fixture\nruntime:\n  kind: none\nmcp: false\n"
        ),
    )
    .unwrap();
    fs::write(source.join("payload.txt"), version).unwrap();
    let checker = LocalChecker::new(
        store.owner().home().into(),
        Nat64Prefixes::default(),
        store.clone(),
        supervisor,
        Default::default(),
    );
    // Use the real receipt, dependency, bundle, declaration and inert-runtime
    // smoke path; no checks or manifest identity are fabricated by the fixture.
    let report = checker.check_local(&source).await.unwrap();
    assert_eq!(report.proposal.state, ProposalState::Checked);
    drop(checker);
    let lease = Arc::new(InstallerLease::acquire(store.owner().home()).unwrap());
    let nonce = store
        .proposal_nonce(report.proposal.id.clone())
        .await
        .unwrap();
    let proposal = PromotionCoordinator::new_offline(store, lease.clone())
        .approve(
            report.proposal.id,
            nonce,
            Overrides::from_value(json!({})).unwrap(),
        )
        .await
        .unwrap();
    (proposal, report.catalog, lease)
}

async fn worker(root: &Path, cutpoint: Cutpoint) {
    let home = root.join("home");
    let real_home = root.join("user");
    fs::create_dir(&real_home).unwrap();
    let owner = HomeLease::create_for_init(&home).unwrap();
    fictor::initialize_owned(owner.clone()).await.unwrap();
    let store = Arc::new(Store::open_with_lease(owner.clone()).await.unwrap());
    store
        .write(|db| {
            // Keep the prepared intent in the real WAL deterministically. FULL
            // is still enforced by the Store before every writer operation.
            db.pragma_update(None, "wal_autocheckpoint", 0)?;
            Ok(())
        })
        .await
        .unwrap();
    let secrets = Arc::new(
        SecretStore::open_with_lease(owner.clone(), BackendKind::File, Redactor::default())
            .unwrap(),
    );
    let proxy = Arc::new(
        EgressProxy::bind_unix_with_nat64(
            home.join("run/proxy.sock"),
            store.clone(),
            vec![],
            Nat64Prefixes::default(),
        )
        .await
        .unwrap(),
    );
    let supervisor = Arc::new(
        Supervisor::new(
            &home,
            &real_home,
            Arc::new(Config::load(&home).unwrap()),
            secrets,
            store.clone(),
            proxy,
        )
        .unwrap()
        .with_fictor_exe(PathBuf::from(env!("CARGO_BIN_EXE_fictor")))
        .unwrap(),
    );
    let (previous, _, previous_lease) =
        approved(root, "1.0.0", store.clone(), supervisor.clone()).await;
    let previous = PromotionCoordinator::new_offline(store.clone(), previous_lease)
        .promote(previous.id)
        .await
        .unwrap();
    let (proposal, catalog, lease) = approved(root, "2.0.0", store.clone(), supervisor).await;
    let _section = owner.installer_gate().lock_owned().await;
    let before_bytes = Lock::read_snapshot(&home).unwrap().unwrap();
    let mut after = Lock::parse_snapshot(&before_bytes).unwrap();
    let hash = proposal.hash.as_ref().unwrap();
    let key = format!("2.0.0-{}", &hash[7..19]);
    let candidate = LockedVersion {
        version: "2.0.0".into(),
        hash: hash.clone(),
        path: format!("store/{EXTENSION}/{key}"),
        source: proposal.source.clone(),
        approved: Approval {
            by: "user".into(),
            at: approval_at_ms(proposal.updated_at).unwrap(),
            approval_id: None,
        },
        overrides: proposal.overrides.clone(),
        privileges: vec![],
        tools: catalog.tools().to_vec(),
        tools_hash: catalog.hash().into(),
        packages: proposal
            .packages
            .as_ref()
            .unwrap()
            .iter()
            .map(|package| Package {
                ecosystem: package.ecosystem.clone(),
                name: package.name.clone(),
                version: package.version.clone(),
            })
            .collect(),
        audit: None,
    };
    let extension: &mut LockedExtension = after.extensions.get_mut(EXTENSION).unwrap();
    extension.active = key.clone();
    extension.versions.insert(key.clone(), candidate);
    let intent = store
        .prepare_promotion(NewPromotionIntent {
            proposal_id: proposal.id.clone(),
            before_lock: Some(String::from_utf8(before_bytes).unwrap()),
            after_lock: after.encode_snapshot().unwrap(),
        })
        .await
        .unwrap();
    if cutpoint != Cutpoint::AfterJournal {
        materialize(&home, store.clone(), lease.clone(), proposal.id.clone())
            .await
            .unwrap();
    }
    if matches!(cutpoint, Cutpoint::AfterLock | Cutpoint::AfterCommit) {
        publish_snapshot(&home, intent.after_lock.as_bytes());
    }
    if cutpoint == Cutpoint::AfterCommit {
        store
            .commit_promotion(intent.operation_id.clone())
            .await
            .unwrap();
    }
    let ready = Ready {
        cutpoint,
        proposal_id: proposal.id,
        operation_id: intent.operation_id,
        previous_key: previous.key,
        candidate_key: key,
        checks: proposal.checks.unwrap(),
    };
    {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{READY}{}", serde_json::to_string(&ready).unwrap()).unwrap();
        stdout.flush().unwrap();
    }
    // No Store::shutdown, normal return or Drop before the parent's SIGKILL.
    std::future::pending::<()>().await;
}

fn publish_snapshot(home: &Path, bytes: &[u8]) {
    // Fixture equivalent of the private Lock::write_snapshot: no production
    // hook/API is exposed solely to stop at the durable pre-commit boundary.
    let parent = home.join("extensions");
    let temporary = parent.join("lock.json.tmp");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    fs::rename(temporary, parent.join("lock.json")).unwrap();
    fs::File::open(parent).unwrap().sync_all().unwrap();
}

struct OwnedWorker(Child);
impl Drop for OwnedWorker {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

async fn crash_and_boot(cutpoint: Cutpoint, remove_receipt: bool) {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let mut child = OwnedWorker(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "promotion_crash_worker", "--nocapture"])
            .env_clear()
            .env(ROOT, root.path())
            .env(CUTPOINT, cutpoint.name())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let ready: Ready = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || {
            for line in BufReader::new(stdout).lines() {
                let line = line.unwrap();
                if let Some((_, json)) = line.split_once(READY) {
                    return serde_json::from_str(json).unwrap();
                }
            }
            panic!("worker exited before its durable cutpoint");
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(ready.cutpoint, cutpoint);
    for version in ["1.0.0", "2.0.0"] {
        fs::remove_dir_all(root.path().join(format!("source-{version}"))).unwrap();
    }
    child.0.kill().unwrap();
    assert_eq!(child.0.wait().unwrap().signal(), Some(libc::SIGKILL));
    let mut first_owner = Some(HomeLease::acquire(&home).unwrap());
    assert!(fs::metadata(home.join("fictor.db-wal")).unwrap().len() > 32);
    let candidate_path = home
        .join("extensions/store")
        .join(EXTENSION)
        .join(&ready.candidate_key);
    assert_eq!(candidate_path.exists(), cutpoint != Cutpoint::AfterJournal);
    // Read a detached main-file copy only after the child is dead. Opening the
    // application DB here could checkpoint away the very crash boundary tested.
    let main_copy = root.path().join("main-only.sqlite");
    fs::copy(home.join("fictor.db"), &main_copy).unwrap();
    let main = Connection::open_with_flags(main_copy, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let table_exists: bool = main
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='promotion_intents')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    // Even the initial schema may remain exclusively in WAL. Distinguish that
    // explicit case from any unexpected SQLite failure while reading a table.
    let rows: i64 = if table_exists {
        main.query_row(
            "SELECT count(*) FROM promotion_intents WHERE operation_id=?1",
            [&ready.operation_id],
            |row| row.get(0),
        )
        .unwrap()
    } else {
        0
    };
    assert_eq!(
        rows, 0,
        "the durable prepared intent must still be WAL-only"
    );
    drop(main);
    if remove_receipt {
        assert_eq!(cutpoint, Cutpoint::AfterLock);
        fs::remove_dir_all(home.join("extensions/quarantine").join(&ready.proposal_id)).unwrap();
    }
    let last_lock = fs::File::open(home.join("extensions/lock.json")).unwrap();
    let last_inode = last_lock.metadata().unwrap();
    let last_bytes = fs::read(home.join("extensions/lock.json")).unwrap();
    let mut first_events = None;
    for _ in 0..2 {
        // Acquire a fresh owner each time and enter the real boot recovery path.
        let owner = first_owner
            .take()
            .unwrap_or_else(|| HomeLease::acquire(&home).unwrap());
        fictor::initialize_owned(owner.clone()).await.unwrap();
        let store = Store::open_with_lease(owner).await.unwrap();
        let intent = store
            .promotion_intent(ready.operation_id.clone())
            .await
            .unwrap();
        let proposal = store.proposal(ready.proposal_id.clone()).await.unwrap();
        let (state, proposal_state, active, expected_lock) = match cutpoint {
            Cutpoint::AfterJournal | Cutpoint::BeforeLock => (
                PromotionState::Aborted,
                ProposalState::Approved,
                &ready.previous_key,
                intent.before_lock.as_deref().unwrap().as_bytes(),
            ),
            Cutpoint::AfterLock | Cutpoint::AfterCommit => (
                PromotionState::Committed,
                ProposalState::Promoted,
                &ready.candidate_key,
                intent.after_lock.as_bytes(),
            ),
        };
        assert_eq!(intent.state, state);
        assert_eq!(proposal.state, proposal_state);
        assert_eq!(proposal.checks.as_ref().unwrap(), &ready.checks);
        assert_eq!(last_bytes, expected_lock);
        assert_eq!(Lock::read_snapshot(&home).unwrap().unwrap(), last_bytes);
        let current_inode = fs::metadata(home.join("extensions/lock.json")).unwrap();
        assert_eq!(
            (current_inode.dev(), current_inode.ino()),
            (last_inode.dev(), last_inode.ino())
        );
        assert_eq!(
            Lock::load_required(&home).unwrap().extensions[EXTENSION].active,
            *active
        );
        assert_eq!(
            fs::read_to_string(
                home.join("extensions/store")
                    .join(EXTENSION)
                    .join(&ready.previous_key)
                    .join("payload.txt")
            )
            .unwrap(),
            "1.0.0"
        );
        if cutpoint == Cutpoint::AfterJournal {
            assert!(!candidate_path.exists());
        } else {
            assert_eq!(
                fs::read_to_string(candidate_path.join("payload.txt")).unwrap(),
                "2.0.0"
            );
        }
        assert!(store.pending_promotion().await.unwrap().is_none());
        let events = store
            .event_path("sys".into(), None, None)
            .await
            .unwrap()
            .events;
        let count = |kind: &str| events.iter().filter(|event| event.kind == kind).count();
        assert_eq!(count("ext.proposed"), 2);
        assert_eq!(count("ext.checking"), 2);
        assert_eq!(count("ext.checked"), 2);
        assert_eq!(count("ext.started"), 0);
        assert_eq!(
            count("ext.promoted"),
            if matches!(cutpoint, Cutpoint::AfterLock | Cutpoint::AfterCommit) {
                2
            } else {
                1
            }
        );
        assert_eq!(
            count("ext.promotion_aborted"),
            if matches!(cutpoint, Cutpoint::AfterJournal | Cutpoint::BeforeLock) {
                1
            } else {
                0
            }
        );
        let snapshot = serde_json::to_value(events).unwrap();
        if let Some(first) = &first_events {
            assert_eq!(
                first, &snapshot,
                "a repeated boot must not repeat any event"
            );
        } else {
            first_events = Some(snapshot);
        }
        store.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn sigkill_before_lock_aborts_once_and_preserves_the_previous_version() {
    crash_and_boot(Cutpoint::BeforeLock, false).await;
}

#[tokio::test]
async fn sigkill_after_lock_commits_once_from_the_uncheckpointed_wal() {
    crash_and_boot(Cutpoint::AfterLock, false).await;
}

#[tokio::test]
async fn sigkill_after_lock_recovers_without_origin_or_quarantine_receipt() {
    crash_and_boot(Cutpoint::AfterLock, true).await;
}

#[tokio::test]
async fn sigkill_after_journal_aborts_without_materializing_the_candidate() {
    crash_and_boot(Cutpoint::AfterJournal, false).await;
}

#[tokio::test]
async fn sigkill_after_writer_commit_recovers_without_repeating_the_promotion() {
    crash_and_boot(Cutpoint::AfterCommit, false).await;
}
