//! ADR-047: event evidence orders attempts; civil time and operation IDs do not.
//! Corrupt fixtures only INSERT audit rows (or suppress an INSERT in a new fake
//! database). The application's append-only UPDATE/DELETE guards stay installed.
use fictor::{
    admin::{Effect, MutationReason},
    config::Config,
    gateway::PinnedCatalog,
    installer::{
        BundleBudget, BundleProfile, inspect,
        lease::InstallerLease,
        local::LocalChecker,
        lock::{Approval, Lock, LockedExtension, LockedVersion, approval_at_ms},
        online::InstallService,
        overrides::Overrides,
    },
    proxy::{EgressProxy, nat64::Nat64Prefixes},
    secrets::{BackendKind, Redactor, SecretStore},
    store::{
        HumanDecision, NewPromotionIntent, NewProposal, PromotionAbortReason, PromotionIntent,
        PromotionState, Proposal, ProposalCheck, ProposalIdentity, ProposalState, ProposalUpdate,
        ReviewBase, Store, StoreClock, StoreError,
    },
    supervisor::Supervisor,
};
use rusqlite::params;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
};

struct Clock(AtomicI64);
impl Clock {
    fn set(&self, value: i64) {
        self.0.store(value, Ordering::SeqCst);
    }
}
impl StoreClock for Clock {
    fn now_ms(&self) -> Result<i64, StoreError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

struct Fixture {
    root: tempfile::TempDir,
    home: PathBuf,
    store: Arc<Store>,
    clock: Arc<Clock>,
}
impl Fixture {
    async fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("fx-order-")
            .tempdir_in("/tmp")
            .unwrap();
        let home = root.path().join("home");
        fictor::initialize(&home).await.unwrap();
        let clock = Arc::new(Clock(AtomicI64::new(1_000_000)));
        let store = Arc::new(Store::open_with_clock(&home, clock.clone()).await.unwrap());
        Self {
            root,
            home,
            store,
            clock,
        }
    }
    async fn reopen(self) -> Self {
        let Self {
            root,
            home,
            store,
            clock,
        } = self;
        Arc::try_unwrap(store)
            .ok()
            .unwrap()
            .shutdown()
            .await
            .unwrap();
        let store = Arc::new(Store::open_with_clock(&home, clock.clone()).await.unwrap());
        Self {
            root,
            home,
            store,
            clock,
        }
    }
    async fn service(&self) -> (InstallService, Arc<EgressProxy>) {
        let mut config = Config::load(&self.home).unwrap();
        config.providers.clear();
        config.sandbox.home_ro_files.clear();
        let secrets = Arc::new(
            SecretStore::open_with_lease(
                self.store.owner().clone(),
                BackendKind::File,
                Redactor::default(),
            )
            .unwrap(),
        );
        let proxy = Arc::new(
            EgressProxy::bind_unix_with_nat64(
                self.home.join("run/order-proxy.sock"),
                self.store.clone(),
                vec![],
                Nat64Prefixes::default(),
            )
            .await
            .unwrap(),
        );
        let supervisor = Arc::new(
            Supervisor::new(
                &self.home,
                self.root.path(),
                Arc::new(config),
                secrets,
                self.store.clone(),
                proxy.clone(),
            )
            .unwrap(),
        );
        let checker = LocalChecker::new(
            self.home.clone(),
            Nat64Prefixes::default(),
            self.store.clone(),
            supervisor,
            Default::default(),
        );
        (
            InstallService::new(self.store.clone(), checker)
                .await
                .unwrap(),
            proxy,
        )
    }
    async fn approved(&self) -> Proposal {
        let proposal = self
            .store
            .begin_attempt(NewProposal {
                source: json!({"kind":"local"}),
                tainted: false,
            })
            .await
            .unwrap();
        let manifest = json!({"schema":1,"id":"sample","version":"0.1.0","description":"Order fixture","runtime":{"kind":"none"},"scope":"global","mcp":false});
        let receipt = self.home.join("extensions/quarantine").join(&proposal.id);
        fs::create_dir(&receipt).unwrap();
        fs::write(receipt.join("fictor.yaml"), manifest.to_string()).unwrap();
        let bundle = inspect(
            &receipt,
            &BundleBudget::start(BundleProfile::PostDependencies),
        )
        .unwrap();
        self.store
            .transition_proposal(
                proposal.id.clone(),
                ProposalState::Received,
                ProposalState::Checking,
                ProposalUpdate {
                    identity: Some(ProposalIdentity {
                        ext_id: "sample".into(),
                        version: "0.1.0".into(),
                        manifest,
                        update_of: None,
                    }),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let catalog = PinnedCatalog::new(vec![]).unwrap();
        let checks = [
            "manifest",
            "dependencies",
            "bundle",
            "declarations",
            "smoke",
        ]
        .into_iter()
        .map(|name| ProposalCheck {
            name: name.into(),
            passed: true,
            blocking: true,
            detail: (name == "smoke")
                .then(|| json!({"tools":catalog.tools(),"tools_hash":catalog.hash()}).to_string()),
        })
        .collect();
        let base = || ReviewBase {
            update_of: None,
            hash: Lock::default().review_base_hash("sample").unwrap(),
        };
        self.store
            .transition_proposal(
                proposal.id.clone(),
                ProposalState::Checking,
                ProposalState::Checked,
                ProposalUpdate {
                    hash: Some(bundle.bundle_hash),
                    checks: Some(checks),
                    packages: Some(vec![]),
                    review_base: Some(base()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let nonce = self
            .store
            .proposal_nonce(proposal.id.clone())
            .await
            .unwrap();
        self.store
            .transition_proposal(
                proposal.id,
                ProposalState::Checked,
                ProposalState::Approved,
                ProposalUpdate {
                    decision: Some(HumanDecision::User(nonce)),
                    review_base: Some(base()),
                    overrides: Some(Overrides::default()),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
    }
    fn input(&self, proposal: &Proposal) -> NewPromotionIntent {
        let hash = proposal.hash.clone().unwrap();
        let key = format!("0.1.0-{}", &hash[7..19]);
        let catalog = PinnedCatalog::new(vec![]).unwrap();
        let version = LockedVersion {
            version: "0.1.0".into(),
            hash,
            path: format!("store/sample/{key}"),
            source: proposal.source.clone(),
            approved: Approval {
                by: "user".into(),
                at: approval_at_ms(proposal.updated_at).unwrap(),
                approval_id: None,
            },
            overrides: proposal.overrides.clone(),
            privileges: vec![],
            tools: vec![],
            tools_hash: catalog.hash().into(),
            packages: vec![],
            audit: None,
        };
        let mut after = Lock::default();
        after.extensions.insert(
            "sample".into(),
            LockedExtension {
                enabled: true,
                active: key.clone(),
                versions: [(key, version)].into(),
            },
        );
        NewPromotionIntent {
            proposal_id: proposal.id.clone(),
            before_lock: Some(Lock::default().encode_snapshot().unwrap()),
            after_lock: after.encode_snapshot().unwrap(),
        }
    }
    async fn events(&self) -> Vec<(String, String, Value, i64)> {
        self.store
            .write(|db| {
                let mut query = db.prepare(
                    "SELECT id,kind,payload,created_at FROM events ORDER BY id COLLATE BINARY",
                )?;
                let rows = query.query_map([], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get::<_, String>(2)?,
                        row.get(3)?,
                    ))
                })?;
                rows.map(|row| {
                    let (id, kind, payload, time) = row?;
                    Ok((id, kind, serde_json::from_str(&payload).unwrap(), time))
                })
                .collect::<Result<Vec<_>, StoreError>>()
            })
            .await
            .unwrap()
    }
    async fn snapshot(&self) -> Value {
        self.store
            .write(|db| {
                let mut values = Vec::new();
                for table in ["proposals", "promotion_intents", "events", "sessions"] {
                    let mut query = db.prepare(&format!("SELECT * FROM {table} ORDER BY 1"))?;
                    let count = query.column_count();
                    let rows = query.query_map([], move |row| {
                        (0..count)
                            .map(|column| Ok(format!("{:?}", row.get_ref(column)?)))
                            .collect::<Result<Vec<_>, rusqlite::Error>>()
                    })?;
                    values.push(json!([table, rows.collect::<Result<Vec<_>, _>>()?]));
                }
                Ok(json!(values))
            })
            .await
            .unwrap()
    }
    async fn next_event_ids(&self, count: usize) -> Vec<String> {
        let maximum = self.events().await.last().unwrap().0.clone();
        let floor = u128::from(ulid::Ulid::from_string(&maximum).unwrap());
        (1..=count)
            .map(|delta| ulid::Ulid::from(floor + delta as u128).to_string())
            .collect()
    }
    async fn reject_corruption(&self, proposal: &Proposal, operation: &PromotionIntent) {
        let staging = self
            .home
            .join("extensions/quarantine")
            .join(format!(".promotion-{}", operation.operation_id));
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("sentinel"), b"retain fake resources").unwrap();
        let lock_path = self.home.join("extensions/lock.json");
        let lock = fs::read(&lock_path).unwrap();
        let before = self.snapshot().await;
        let (service, proxy) = self.service().await;
        let status_error = match service.status(proposal.id.clone(), None).await {
            Err(error) => error,
            Ok(_) => panic!("corrupt journal was accepted by status"),
        };
        for error in [
            status_error,
            service.promote(proposal.id.clone()).await.unwrap_err(),
        ] {
            assert_eq!(error.reason, MutationReason::InvalidSnapshot);
            assert_eq!(error.effect, Effect::None);
        }
        assert_eq!(
            service
                .coordinator()
                .reconcile()
                .await
                .unwrap_err()
                .to_string(),
            "promotion:recovery_conflict"
        );
        assert_eq!(
            self.snapshot().await,
            before,
            "invalid history must never be repaired"
        );
        assert_eq!(fs::read(lock_path).unwrap(), lock);
        assert_eq!(
            fs::read(staging.join("sentinel")).unwrap(),
            b"retain fake resources"
        );
        assert!(
            self.store
                .write(|db| {
                    assert!(db.execute("UPDATE events SET actor='fixture'", []).is_err());
                    assert!(db.execute("DELETE FROM events", []).is_err());
                    Ok(())
                })
                .await
                .is_ok()
        );
        close_service(service, proxy).await;
    }
}

async fn close_service(service: InstallService, proxy: Arc<EgressProxy>) {
    drop(service);
    Arc::try_unwrap(proxy)
        .ok()
        .unwrap()
        .shutdown()
        .await
        .unwrap();
}

fn preparation(intent: &PromotionIntent) -> Value {
    json!({"operation_id":intent.operation_id,"proposal_id":intent.proposal_id,"ext_id":intent.ext_id,"key":intent.key,"before_hash":intent.before_hash,"after_hash":intent.after_hash})
}
async fn insert_audit(store: &Store, id: String, kind: &str, payload: Value, timestamp: i64) {
    let kind = kind.to_string();
    store.write(move |db| {
        db.execute("INSERT INTO events(id,session_id,kind,actor,payload,trust,sensitivity,source,flags,created_at) VALUES(?1,'sys',?2,'core',?3,'trusted','public','core',0,?4)", params![id,kind,payload.to_string(),timestamp])?;
        Ok(())
    }).await.unwrap();
}
async fn insert_intent(store: &Store, intent: PromotionIntent) {
    store.write(move |db| {
        let state = match intent.state { PromotionState::Prepared => "prepared", PromotionState::Aborted => "aborted", PromotionState::Committed => "committed" };
        db.execute("INSERT INTO promotion_intents(operation_id,proposal_id,before_lock,before_hash,after_lock,after_hash,state,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![intent.operation_id,intent.proposal_id,intent.before_lock,intent.before_hash,intent.after_lock,intent.after_hash,state,intent.created_at,intent.updated_at])?;
        Ok(())
    }).await.unwrap();
}

#[tokio::test]
async fn regressing_and_equal_civil_times_preserve_latest_status_and_deduplication_after_restart() {
    for restart in [false, true] {
        for next_time in [1_000_000, 100] {
            let mut fixture = Fixture::new().await;
            let proposal = fixture.approved().await;
            let first = fixture
                .store
                .prepare_promotion(fixture.input(&proposal))
                .await
                .unwrap();
            fixture
                .store
                .abort_promotion(
                    first.operation_id.clone(),
                    PromotionAbortReason::Interrupted,
                )
                .await
                .unwrap();
            fixture.clock.set(next_time);
            if restart {
                fixture = fixture.reopen().await;
            }
            let latest = fixture
                .store
                .prepare_promotion(fixture.input(&proposal))
                .await
                .unwrap();
            assert_eq!(latest.created_at, next_time);
            assert_eq!(
                fixture
                    .store
                    .promotion_intent(first.operation_id.clone())
                    .await
                    .unwrap()
                    .created_at,
                1_000_000
            );
            let (service, proxy) = fixture.service().await;
            let events = fixture.events().await;
            let evidence = |operation: &str| {
                events
                    .iter()
                    .find(|(_, kind, payload, _)| {
                        kind == "ext.promotion_prepared" && payload["operation_id"] == operation
                    })
                    .unwrap()
            };
            assert!(evidence(&latest.operation_id).0 > evidence(&first.operation_id).0);
            let gate = fixture.store.owner().installer_gate().lock_owned().await;
            for _ in 0..2 {
                let status = service.status(proposal.id.clone(), None).await.unwrap();
                assert_eq!(
                    status.promotion.as_ref().unwrap().operation_id,
                    latest.operation_id
                );
                assert_eq!(status.promotion.as_ref().unwrap().state, "prepared");
                assert_eq!(
                    service.promote(proposal.id.clone()).await.unwrap()["operation_id"],
                    latest.operation_id
                );
            }
            assert_eq!(
                fixture.events().await,
                events,
                "a prepared retry cannot start another worker"
            );
            drop(gate);
            fixture
                .store
                .commit_promotion(latest.operation_id.clone())
                .await
                .unwrap();
            let committed = fixture.events().await;
            for _ in 0..2 {
                let status = service.status(proposal.id.clone(), None).await.unwrap();
                assert_eq!(
                    status.promotion.as_ref().unwrap().operation_id,
                    latest.operation_id
                );
                assert_eq!(status.promotion.as_ref().unwrap().state, "committed");
                assert_eq!(
                    service.promote(proposal.id.clone()).await.unwrap()["operation_id"],
                    latest.operation_id
                );
            }
            assert_eq!(fixture.events().await, committed);
            close_service(service, proxy).await;
            fixture = fixture.reopen().await;
            let (service, proxy) = fixture.service().await;
            assert_eq!(
                service.promote(proposal.id.clone()).await.unwrap()["operation_id"],
                latest.operation_id
            );
            assert_eq!(
                service
                    .status(proposal.id.clone(), None)
                    .await
                    .unwrap()
                    .promotion
                    .unwrap()
                    .operation_id,
                latest.operation_id
            );
            assert_eq!(fixture.events().await, committed);
            close_service(service, proxy).await;
            let maximum = committed.last().unwrap().0.clone();
            fixture
                .store
                .begin_attempt(NewProposal {
                    source: json!({"kind":"local"}),
                    tainted: false,
                })
                .await
                .unwrap();
            let after_restart = fixture.events().await;
            assert!(after_restart.last().unwrap().0 > maximum);
            assert_eq!(&after_restart[..committed.len()], &committed);
        }
    }
}

#[tokio::test]
async fn a_previous_conclusion_must_precede_the_next_preparation_even_with_equal_times() {
    for same_proposal in [false, true] {
        let fixture = Fixture::new().await;
        let proposal = fixture.approved().await;
        let other = if same_proposal {
            fixture.store.proposal(proposal.id.clone()).await.unwrap()
        } else {
            fixture.approved().await
        };
        let first = fixture
            .store
            .prepare_promotion(fixture.input(&proposal))
            .await
            .unwrap();
        fixture.store.write(|db| { db.execute_batch("CREATE TRIGGER suppress_fixture_abort BEFORE INSERT ON events WHEN NEW.kind='ext.promotion_aborted' BEGIN SELECT RAISE(IGNORE); END;")?; Ok(()) }).await.unwrap();
        fixture
            .store
            .abort_promotion(
                first.operation_id.clone(),
                PromotionAbortReason::Interrupted,
            )
            .await
            .unwrap();
        fixture
            .store
            .write(|db| {
                db.execute_batch("DROP TRIGGER suppress_fixture_abort")?;
                Ok(())
            })
            .await
            .unwrap();
        let mut latest = first.clone();
        latest.operation_id = "00000000000000000000000001".into();
        latest.after_lock = fixture.input(&other).after_lock;
        latest.after_hash = format!(
            "sha256:{}",
            Sha256::digest(latest.after_lock.as_bytes())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        latest.proposal_id = other.id;
        let ids = fixture.next_event_ids(2).await;
        insert_intent(&fixture.store, latest.clone()).await;
        insert_audit(
            &fixture.store,
            ids[0].clone(),
            "ext.promotion_prepared",
            preparation(&latest),
            latest.created_at,
        )
        .await;
        insert_audit(
        &fixture.store,
        ids[1].clone(),
        "ext.promotion_aborted",
        json!({"operation_id":first.operation_id,"proposal_id":first.proposal_id,"ext_id":first.ext_id,"key":first.key,"reason":"promotion:interrupted"}),
        first.updated_at,
    )
    .await;
        fixture.reject_corruption(&proposal, &latest).await;
    }
}

#[tokio::test]
async fn missing_duplicate_or_divergent_preparations_refuse_admin_and_recovery_without_cleanup() {
    for defect in ["missing", "duplicate", "divergent", "orphan"] {
        let fixture = Fixture::new().await;
        let proposal = fixture.approved().await;
        if defect == "missing" {
            fixture.store.write(|db| { db.execute_batch("CREATE TRIGGER suppress_fixture_preparation BEFORE INSERT ON events WHEN NEW.kind='ext.promotion_prepared' BEGIN SELECT RAISE(IGNORE); END;")?; Ok(()) }).await.unwrap();
        }
        let operation = fixture
            .store
            .prepare_promotion(fixture.input(&proposal))
            .await
            .unwrap();
        if defect == "missing" {
            fixture
                .store
                .write(|db| {
                    db.execute_batch("DROP TRIGGER suppress_fixture_preparation")?;
                    Ok(())
                })
                .await
                .unwrap();
        } else if defect == "divergent" {
            let id = operation.operation_id.clone();
            fixture.store.write(move |db| { db.execute("UPDATE promotion_intents SET created_at=created_at+1,updated_at=updated_at+1 WHERE operation_id=?1", [id])?; Ok(()) }).await.unwrap();
        } else {
            let mut payload = preparation(&operation);
            if defect == "orphan" {
                payload["operation_id"] = json!("00000000000000000000000001");
            }
            insert_audit(
                &fixture.store,
                fixture.next_event_ids(1).await.remove(0),
                "ext.promotion_prepared",
                payload,
                operation.created_at,
            )
            .await;
        }
        fixture.reject_corruption(&proposal, &operation).await;
    }
}

#[tokio::test]
async fn a_terminal_event_inserted_later_cannot_precede_its_preparation_id() {
    let fixture = Fixture::new().await;
    let proposal = fixture.approved().await;
    let operation = fixture
        .store
        .prepare_promotion(fixture.input(&proposal))
        .await
        .unwrap();
    fixture.store.write(|db| { db.execute_batch("CREATE TRIGGER suppress_fixture_abort BEFORE INSERT ON events WHEN NEW.kind='ext.promotion_aborted' BEGIN SELECT RAISE(IGNORE); END;")?; Ok(()) }).await.unwrap();
    let aborted = fixture
        .store
        .abort_promotion(
            operation.operation_id.clone(),
            PromotionAbortReason::Interrupted,
        )
        .await
        .unwrap();
    fixture
        .store
        .write(|db| {
            db.execute_batch("DROP TRIGGER suppress_fixture_abort")?;
            Ok(())
        })
        .await
        .unwrap();
    insert_audit(&fixture.store, "00000000000000000000000001".into(), "ext.promotion_aborted", json!({"operation_id":operation.operation_id,"proposal_id":operation.proposal_id,"ext_id":operation.ext_id,"key":operation.key,"reason":"promotion:interrupted"}), aborted.updated_at).await;
    fixture.reject_corruption(&proposal, &operation).await;
}

#[tokio::test]
async fn prepared_must_be_final_and_a_committed_proposal_cannot_have_a_later_attempt() {
    for committed in [false, true] {
        let fixture = Fixture::new().await;
        let proposal = fixture.approved().await;
        let operation = fixture
            .store
            .prepare_promotion(fixture.input(&proposal))
            .await
            .unwrap();
        if committed {
            fixture
                .store
                .commit_promotion(operation.operation_id.clone())
                .await
                .unwrap();
        }
        let mut later = operation.clone();
        later.operation_id = "00000000000000000000000001".into();
        later.state = PromotionState::Aborted;
        let ids = fixture.next_event_ids(2).await;
        insert_intent(&fixture.store, later.clone()).await;
        insert_audit(
            &fixture.store,
            ids[0].clone(),
            "ext.promotion_prepared",
            preparation(&later),
            later.created_at,
        )
        .await;
        insert_audit(&fixture.store, ids[1].clone(), "ext.promotion_aborted", json!({"operation_id":later.operation_id,"proposal_id":later.proposal_id,"ext_id":later.ext_id,"key":later.key,"reason":"promotion:interrupted"}), later.updated_at).await;
        fixture.reject_corruption(&proposal, &operation).await;
    }
}

#[tokio::test]
async fn legacy_operation_ids_and_physical_insert_order_cannot_replace_preparation_order() {
    let fixture = Fixture::new().await;
    let proposal = fixture.approved().await;
    let first = fixture
        .store
        .prepare_promotion(fixture.input(&proposal))
        .await
        .unwrap();
    fixture
        .store
        .abort_promotion(
            first.operation_id.clone(),
            PromotionAbortReason::Interrupted,
        )
        .await
        .unwrap();
    let mut latest = first.clone();
    latest.operation_id = "00000000000000000000000001".into();
    latest.created_at = first.created_at - 100;
    latest.updated_at = latest.created_at;
    let id = fixture.next_event_ids(1).await.remove(0);
    insert_audit(
        &fixture.store,
        id,
        "ext.promotion_prepared",
        preparation(&latest),
        latest.created_at,
    )
    .await;
    // Intent insertion order also differs from the evidence insertion above.
    insert_intent(&fixture.store, latest.clone()).await;
    assert!(latest.operation_id < first.operation_id);
    assert_eq!(
        fixture
            .store
            .pending_promotion()
            .await
            .unwrap()
            .unwrap()
            .operation_id,
        latest.operation_id
    );
    let events = fixture.events().await;
    let (service, proxy) = fixture.service().await;
    assert_eq!(
        service
            .status(proposal.id.clone(), None)
            .await
            .unwrap()
            .promotion
            .unwrap()
            .operation_id,
        latest.operation_id
    );
    assert_eq!(
        service.promote(proposal.id).await.unwrap()["operation_id"],
        latest.operation_id
    );
    assert_eq!(fixture.events().await, events);
    close_service(service, proxy).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_promoted_without_an_intent_is_observable_and_cli_resume_never_repromotes() {
    use std::{os::unix::process::CommandExt, process::Stdio, time::Duration};
    let fixture = Fixture::new().await;
    let proposal = fixture.approved().await;
    let lease = Arc::new(InstallerLease::acquire(&fixture.home).unwrap());
    fictor::installer::promotion::materialize(
        &fixture.home,
        fixture.store.clone(),
        lease.clone(),
        proposal.id.clone(),
    )
    .await
    .unwrap();
    drop(lease);
    let snapshot = fixture.input(&proposal).after_lock;
    fs::write(fixture.home.join("extensions/lock.json"), &snapshot).unwrap();
    fs::File::open(fixture.home.join("extensions/lock.json"))
        .unwrap()
        .sync_all()
        .unwrap();
    fs::File::open(fixture.home.join("extensions"))
        .unwrap()
        .sync_all()
        .unwrap();
    assert!(
        Lock::load_required(&fixture.home)
            .unwrap()
            .extensions
            .contains_key("sample")
    );
    let id = proposal.id.clone();
    fixture
        .store
        .write(move |db| {
            db.execute("UPDATE proposals SET state='promoted' WHERE id=?1", [id])?;
            Ok(())
        })
        .await
        .unwrap();
    insert_audit(
        &fixture.store,
        fixture.next_event_ids(1).await.remove(0),
        "ext.promoted",
        json!({"proposal_id":proposal.id,"ext_id":"sample","version":"0.1.0"}),
        proposal.updated_at,
    )
    .await;
    let before = fixture.snapshot().await;
    let (service, proxy) = fixture.service().await;
    let status = service.status(proposal.id.clone(), None).await.unwrap();
    assert_eq!(status.state, ProposalState::Promoted);
    assert!(status.promotion.is_none());
    assert!(
        fictor::installer::online::InstallStatus::parse(
            serde_json::to_value(status).unwrap(),
            &proposal.id
        )
        .is_ok()
    );
    let error = service.promote(proposal.id.clone()).await.unwrap_err();
    assert_eq!(error.reason, MutationReason::InvalidState);
    assert_eq!(error.effect, Effect::None);
    let server = fictor::admin::AdminServer::builder(fixture.store.owner().clone())
        .with_installer(Arc::new(service.clone()))
        .bind()
        .await
        .unwrap();
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_fictor"));
    command
        .env("FICTOR_HOME", &fixture.home)
        .args(["ext", "install", "--resume", &proposal.id])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: setsid and an errno read are async-signal-safe after fork. The
    // legacy observation must succeed without stdin or a controlling TTY.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::from(command)
            .kill_on_drop(true)
            .spawn()
            .unwrap()
            .wait_with_output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains(&proposal.id));
    assert_eq!(fixture.snapshot().await, before);
    assert_eq!(
        fs::read(fixture.home.join("extensions/lock.json")).unwrap(),
        snapshot.as_bytes()
    );
    server.shutdown().await.unwrap();
    close_service(service, proxy).await;
}
