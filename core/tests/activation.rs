use fictor::{
    admin::MutationReason,
    gateway::PinnedCatalog,
    installer::{
        BundleBudget, BundleProfile,
        activation::{ActivationError, PromotionCoordinator},
        inspect,
        lease::InstallerLease,
        lock::{Approval, Lock, LockedExtension, LockedVersion, approval_at_ms},
        manifest::Manifest,
        overrides::Overrides,
        promotion::materialize,
        publication::{PromotionPublication, PromotionPublicationFuture},
    },
    store::{
        NewPromotionIntent, NewProposal, PromotionIntent, PromotionState, Proposal, ProposalCheck,
        ProposalIdentity, ProposalState, ProposalUpdate, ReviewBase, Store,
    },
    supervisor::controls::ControlRegistry,
};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

struct Fixture {
    root: tempfile::TempDir,
    home: PathBuf,
    store: Arc<Store>,
    lease: Arc<InstallerLease>,
}
impl Fixture {
    async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        fictor::initialize(&home).await.unwrap();
        let store = Arc::new(Store::open(&home).await.unwrap());
        let lease = Arc::new(InstallerLease::acquire(&home).unwrap());
        Self {
            root,
            home,
            store,
            lease,
        }
    }
    fn coordinator(&self) -> PromotionCoordinator {
        PromotionCoordinator::new_offline(self.store.clone(), self.lease.clone())
    }
    async fn reopen(self) -> Self {
        let Self {
            root,
            home,
            store,
            lease,
        } = self;
        drop(lease);
        Arc::try_unwrap(store)
            .ok()
            .unwrap()
            .shutdown()
            .await
            .unwrap();
        let store = Arc::new(Store::open(&home).await.unwrap());
        let lease = Arc::new(InstallerLease::acquire(&home).unwrap());
        Self {
            root,
            home,
            store,
            lease,
        }
    }
    async fn checked(&self, version: &str) -> Proposal {
        let p = self
            .store
            .begin_attempt(NewProposal {
                source: json!({"kind":"local"}),
                tainted: false,
            })
            .await
            .unwrap();
        let manifest = Manifest::parse(&json!({
            "schema":1,"id":"sample","version":version,"description":"Activation fixture",
            "runtime":{"kind":"binary","entry":"server"},"scope":"session","mcp":true,"kernel":["kv"],
            "permissions":{"env":{"APP_LABEL":"fake-private-value"}}
        }).to_string()).unwrap();
        let receipt = self.home.join("extensions/quarantine").join(&p.id);
        fs::create_dir(&receipt).unwrap();
        fs::write(
            receipt.join("fictor.yaml"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        fs::write(receipt.join("server"), b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(receipt.join("server"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(receipt.join("approved.txt"), version).unwrap();
        let bundle = inspect(
            &receipt,
            &BundleBudget::start(BundleProfile::PostDependencies),
        )
        .unwrap();
        self.store
            .transition_proposal(
                p.id.clone(),
                ProposalState::Received,
                ProposalState::Checking,
                ProposalUpdate {
                    identity: Some(ProposalIdentity {
                        ext_id: manifest.id.clone(),
                        version: manifest.version.clone(),
                        manifest: serde_json::to_value(manifest).unwrap(),
                        update_of: None,
                    }),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let lock = Lock::load(&self.home).unwrap();
        let catalog = catalog();
        self.store
            .transition_proposal(
                p.id,
                ProposalState::Checking,
                ProposalState::Checked,
                ProposalUpdate {
                    hash: Some(bundle.bundle_hash),
                    packages: Some(vec![]),
                    checks: Some(
                        [
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
                            detail: if name == "smoke" {
                                Some(
                                    json!({"tools":catalog.tools(),"tools_hash":catalog.hash()})
                                        .to_string(),
                                )
                            } else {
                                None
                            },
                        })
                        .collect(),
                    ),
                    review_base: Some(ReviewBase {
                        update_of: lock.extensions.get("sample").map(|e| e.active.clone()),
                        hash: lock.review_base_hash("sample").unwrap(),
                    }),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
    }
    async fn approve(&self, p: &Proposal, patch: Value) -> Proposal {
        let nonce = self.store.proposal_nonce(p.id.clone()).await.unwrap();
        self.coordinator()
            .approve(p.id.clone(), nonce, Overrides::from_value(patch).unwrap())
            .await
            .unwrap()
    }
    async fn prepared(&self, p: &Proposal) -> fictor::store::PromotionIntent {
        let before = Lock::read_snapshot(&self.home)
            .unwrap()
            .map(String::from_utf8)
            .transpose()
            .unwrap();
        let mut after = before
            .as_deref()
            .map(|s| Lock::parse_snapshot(s.as_bytes()).unwrap())
            .unwrap_or_default();
        let hash = p.hash.as_ref().unwrap();
        let key = format!("{}-{}", p.version.as_ref().unwrap(), &hash[7..19]);
        let catalog = catalog();
        let candidate = LockedVersion {
            version: p.version.clone().unwrap(),
            hash: hash.clone(),
            path: format!("store/sample/{key}"),
            source: p.source.clone(),
            approved: Approval {
                by: "user".into(),
                at: approval_at_ms(p.updated_at).unwrap(),
                approval_id: None,
            },
            overrides: p.overrides.clone(),
            privileges: vec![],
            tools: catalog.tools().to_vec(),
            tools_hash: catalog.hash().into(),
            packages: vec![],
            audit: None,
        };
        let extension =
            after
                .extensions
                .entry("sample".into())
                .or_insert_with(|| LockedExtension {
                    enabled: true,
                    active: key.clone(),
                    versions: Default::default(),
                });
        extension.versions.insert(key.clone(), candidate);
        extension.active = key;
        self.store
            .prepare_promotion(NewPromotionIntent {
                proposal_id: p.id.clone(),
                before_lock: before,
                after_lock: after.encode_snapshot().unwrap(),
            })
            .await
            .unwrap()
    }
    fn publish_snapshot(&self, snapshot: &str) {
        // A controlled crash boundary: exact journal bytes are durable before
        // opening a fresh Store, without running the production commit step.
        let parent = self.home.join("extensions");
        let temporary = parent.join("fixture-lock.tmp");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .unwrap();
        file.write_all(snapshot.as_bytes()).unwrap();
        file.sync_all().unwrap();
        fs::rename(temporary, parent.join("lock.json")).unwrap();
        fs::File::open(parent).unwrap().sync_all().unwrap();
    }
    async fn count(&self, kind: &str) -> usize {
        self.store
            .event_path("sys".into(), None, None)
            .await
            .unwrap()
            .events
            .iter()
            .filter(|e| e.kind == kind)
            .count()
    }
}
fn catalog() -> PinnedCatalog {
    PinnedCatalog::new(vec![
        json!({"name":"echo","description":"approved fixture","inputSchema":{"type":"object"}}),
    ])
    .unwrap()
}

#[tokio::test]
async fn approval_and_promotion_publish_exact_patch_and_original_catalog_after_commit() {
    let f = Fixture::new().await;
    let checked = f.checked("1.0.0").await;
    let patch =
        json!({"permissions":{"env":{}},"tools":{"echo":{"model_visible":false,"effect":"read"}}});
    let approved = f.approve(&checked, patch.clone()).await;
    let intent = f.coordinator().promote(approved.id.clone()).await.unwrap();
    assert_eq!(intent.state, PromotionState::Committed);
    let lock = Lock::load_required(&f.home).unwrap();
    let extension = &lock.extensions["sample"];
    assert!(extension.enabled);
    let version = &extension.versions[&extension.active];
    assert_eq!(version.overrides.as_value(), &patch);
    assert_eq!(version.tools, catalog().tools());
    assert_eq!(version.tools_hash, catalog().hash());
    assert_eq!(
        version.approved.at,
        approval_at_ms(approved.updated_at).unwrap()
    );
    let manifest = Manifest::parse(
        &fs::read_to_string(
            f.home
                .join("extensions")
                .join(&version.path)
                .join("fictor.yaml"),
        )
        .unwrap(),
    )
    .unwrap();
    let effective = fictor::installer::overrides::resolve(
        &manifest,
        &version.catalog().unwrap(),
        &version.overrides,
        &version.approved.by,
        &Default::default(),
    )
    .unwrap();
    assert!(effective.manifest().permissions.env.is_empty());
    assert!(!effective.tool_class("echo").unwrap().model_visible);
    assert_eq!(
        f.store.proposal(approved.id.clone()).await.unwrap().state,
        ProposalState::Promoted
    );
    assert!(
        !f.home
            .join("extensions/quarantine")
            .join(&approved.id)
            .exists()
    );
    assert!(f.store.pending_promotion().await.unwrap().is_none());
    assert_eq!(
        f.coordinator()
            .operation(intent.operation_id)
            .await
            .unwrap()
            .state,
        PromotionState::Committed
    );
    assert_eq!(f.count("ext.promoted").await, 1);
}

#[tokio::test]
async fn restart_with_before_lock_aborts_once_and_retains_the_approved_receipt() {
    let f = Fixture::new().await;
    let p = f.approve(&f.checked("1.0.0").await, json!({})).await;
    let intent = f.prepared(&p).await;
    let f = f.reopen().await;
    let result = f.coordinator().reconcile().await.unwrap().unwrap();
    assert_eq!(result.operation_id, intent.operation_id);
    assert_eq!(result.state, PromotionState::Aborted);
    assert_eq!(
        Lock::read_snapshot(&f.home).unwrap().as_deref(),
        intent.before_lock.as_deref().map(str::as_bytes)
    );
    assert_eq!(
        f.store.proposal(p.id.clone()).await.unwrap().state,
        ProposalState::Approved
    );
    assert!(f.home.join("extensions/quarantine").join(&p.id).is_dir());
    assert!(f.coordinator().reconcile().await.unwrap().is_none());
    assert_eq!(f.count("ext.promotion_aborted").await, 1);
    assert_eq!(f.count("ext.promoted").await, 0);
    let retry = f.coordinator().promote(p.id.clone()).await.unwrap();
    assert_ne!(retry.operation_id, intent.operation_id);
    assert_eq!(retry.state, PromotionState::Committed);
    // The aborted historical row must still decode after this proposal commits.
    assert_eq!(
        f.store
            .promotion_intent(intent.operation_id)
            .await
            .unwrap()
            .state,
        PromotionState::Aborted
    );
    assert!(f.store.pending_promotion().await.unwrap().is_none());
    assert_eq!(f.count("ext.promotion_aborted").await, 1);
    assert_eq!(f.count("ext.promoted").await, 1);
}

#[tokio::test]
async fn restart_after_lock_publication_commits_once_without_receipt_or_execution() {
    let f = Fixture::new().await;
    let p = f.approve(&f.checked("1.0.0").await, json!({})).await;
    let intent = f.prepared(&p).await;
    materialize(&f.home, f.store.clone(), f.lease.clone(), p.id.clone())
        .await
        .unwrap();
    // Recovery must depend on the published bytes, not recopy or rerun a receipt.
    fs::remove_dir_all(f.home.join("extensions/quarantine").join(&p.id)).unwrap();
    f.publish_snapshot(&intent.after_lock);
    let f = f.reopen().await;
    let recovered = f.coordinator().reconcile().await.unwrap().unwrap();
    assert_eq!(recovered.state, PromotionState::Committed);
    assert_eq!(recovered.operation_id, intent.operation_id);
    assert_eq!(
        f.store.proposal(p.id).await.unwrap().state,
        ProposalState::Promoted
    );
    assert_eq!(
        fs::read(f.home.join("extensions/lock.json")).unwrap(),
        intent.after_lock.as_bytes()
    );
    assert!(f.coordinator().reconcile().await.unwrap().is_none());
    assert_eq!(
        f.coordinator()
            .operation(intent.operation_id)
            .await
            .unwrap()
            .state,
        PromotionState::Committed
    );
    assert_eq!(f.count("ext.promoted").await, 1);
}

#[tokio::test]
async fn third_lock_and_invalid_published_bytes_retain_the_intent_without_overwrite() {
    let f = Fixture::new().await;
    let p = f.approve(&f.checked("1.0.0").await, json!({})).await;
    let intent = f.prepared(&p).await;
    let third = format!(" \n{}", intent.before_lock.as_deref().unwrap());
    f.publish_snapshot(&third);
    assert!(matches!(
        f.coordinator().reconcile().await,
        Err(ActivationError::RecoveryConflict)
    ));
    assert_eq!(
        fs::read(f.home.join("extensions/lock.json")).unwrap(),
        third.as_bytes()
    );
    assert_eq!(
        f.store
            .pending_promotion()
            .await
            .unwrap()
            .unwrap()
            .operation_id,
        intent.operation_id
    );
    // after_lock without the verified immutable store bundle is also a conflict.
    f.publish_snapshot(&intent.after_lock);
    assert!(matches!(
        f.coordinator().reconcile().await,
        Err(ActivationError::RecoveryConflict)
    ));
    assert_eq!(
        fs::read(f.home.join("extensions/lock.json")).unwrap(),
        intent.after_lock.as_bytes()
    );
    assert_eq!(
        f.store.proposal(p.id).await.unwrap().state,
        ProposalState::Approved
    );
    assert_eq!(f.count("ext.promoted").await, 0);
}

#[tokio::test]
async fn changed_base_at_approval_or_promotion_never_renews_the_review() {
    let f = Fixture::new().await;
    let first = f.approve(&f.checked("1.0.0").await, json!({})).await;
    f.coordinator().promote(first.id).await.unwrap();
    let checked = f.checked("2.0.0").await;
    let approved = f.approve(&f.checked("3.0.0").await, json!({})).await;
    let mut changed = Lock::load_required(&f.home).unwrap();
    changed.extensions.get_mut("sample").unwrap().enabled = false;
    let snapshot = changed.encode_snapshot().unwrap();
    f.publish_snapshot(&snapshot);
    let nonce = f.store.proposal_nonce(checked.id.clone()).await.unwrap();
    assert!(matches!(
        f.coordinator()
            .approve(checked.id.clone(), nonce, Overrides::default())
            .await,
        Err(ActivationError::StaleBase)
    ));
    assert!(matches!(
        f.coordinator().promote(approved.id.clone()).await,
        Err(ActivationError::StaleBase)
    ));
    assert_eq!(
        f.store.proposal(checked.id).await.unwrap().state,
        ProposalState::Checked
    );
    assert_eq!(
        f.store.proposal(approved.id).await.unwrap().state,
        ProposalState::Approved
    );
    assert!(f.store.pending_promotion().await.unwrap().is_none());
    assert_eq!(
        fs::read(f.home.join("extensions/lock.json")).unwrap(),
        snapshot.as_bytes()
    );
}

#[tokio::test]
async fn failed_commit_after_lock_publication_blocks_until_the_same_intent_is_reconciled() {
    let f = Fixture::new().await;
    let p = f.approve(&f.checked("1.0.0").await, json!({})).await;
    f.store.write(|db|{db.execute_batch("CREATE TRIGGER refuse_commit BEFORE INSERT ON events WHEN NEW.kind='ext.promoted' BEGIN SELECT RAISE(ABORT,'fixture'); END;")?;Ok(())}).await.unwrap();
    assert!(matches!(
        f.coordinator().promote(p.id.clone()).await,
        Err(ActivationError::Persistence(_))
    ));
    let pending = f.store.pending_promotion().await.unwrap().unwrap();
    assert_eq!(
        fs::read(f.home.join("extensions/lock.json")).unwrap(),
        pending.after_lock.as_bytes()
    );
    assert_eq!(
        f.store.proposal(p.id.clone()).await.unwrap().state,
        ProposalState::Approved
    );
    assert_eq!(f.count("ext.promoted").await, 0);
    f.store
        .write(|db| {
            db.execute_batch("DROP TRIGGER refuse_commit")?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        f.coordinator()
            .reconcile()
            .await
            .unwrap()
            .unwrap()
            .operation_id,
        pending.operation_id
    );
    assert_eq!(
        f.store.proposal(p.id).await.unwrap().state,
        ProposalState::Promoted
    );
    assert_eq!(f.count("ext.promoted").await, 1);
}

#[tokio::test]
async fn offline_enable_refuses_a_durable_prepared_intent_without_recovering_or_editing() {
    use fictor::installer::{
        control::{ControlError, set_enabled},
        listing::ListingError,
    };
    let f = Fixture::new().await;
    let first = f.approve(&f.checked("1.0.0").await, json!({})).await;
    f.coordinator().promote(first.id).await.unwrap();
    let update = f.approve(&f.checked("2.0.0").await, json!({})).await;
    let intent = f.prepared(&update).await;
    let before = fs::read(f.home.join("extensions/lock.json")).unwrap();
    let Fixture {
        root: _root,
        home,
        store,
        lease,
    } = f;
    drop(lease);
    Arc::try_unwrap(store)
        .ok()
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    assert!(matches!(
        set_enabled(&home, "sample", false),
        Err(ControlError::Snapshot(ListingError::RecoveryRequired))
    ));
    assert_eq!(fs::read(home.join("extensions/lock.json")).unwrap(), before);
    let reopened = Store::open(&home).await.unwrap();
    assert_eq!(
        reopened
            .pending_promotion()
            .await
            .unwrap()
            .unwrap()
            .operation_id,
        intent.operation_id
    );
    assert_eq!(
        reopened.proposal(update.id).await.unwrap().state,
        ProposalState::Approved
    );
    reopened.shutdown().await.unwrap();
}

#[tokio::test]
async fn disabled_updates_and_inactive_key_reuse_preserve_old_records_and_refuse_new_overrides() {
    let f = Fixture::new().await;
    let first = f.approve(&f.checked("1.0.0").await, json!({})).await;
    f.coordinator().promote(first.id).await.unwrap();
    let mut lock = Lock::load_required(&f.home).unwrap();
    let old_key = lock.extensions["sample"].active.clone();
    let old_record = serde_json::to_value(&lock.extensions["sample"].versions[&old_key]).unwrap();
    lock.extensions.get_mut("sample").unwrap().enabled = false;
    f.publish_snapshot(&lock.encode_snapshot().unwrap());
    let second = f.approve(&f.checked("2.0.0").await, json!({})).await;
    f.coordinator().promote(second.id).await.unwrap();
    let before = fs::read(f.home.join("extensions/lock.json")).unwrap();
    assert!(!Lock::load_required(&f.home).unwrap().extensions["sample"].enabled);

    let restricted = f
        .approve(&f.checked("1.0.0").await, json!({"permissions":{"env":{}}}))
        .await;
    assert!(matches!(
        f.coordinator().promote(restricted.id.clone()).await,
        Err(ActivationError::KeyConflict)
    ));
    assert_eq!(
        f.store.proposal(restricted.id).await.unwrap().state,
        ProposalState::Approved
    );
    assert_eq!(
        fs::read(f.home.join("extensions/lock.json")).unwrap(),
        before
    );
    assert!(f.store.pending_promotion().await.unwrap().is_none());

    let reactivation = f.approve(&f.checked("1.0.0").await, json!({})).await;
    f.coordinator().promote(reactivation.id).await.unwrap();
    let after = Lock::load_required(&f.home).unwrap();
    let extension = &after.extensions["sample"];
    assert!(!extension.enabled);
    assert_eq!(extension.active, old_key);
    assert_eq!(extension.versions.len(), 2);
    assert_eq!(
        serde_json::to_value(&extension.versions[&old_key]).unwrap(),
        old_record
    );
    assert_eq!(f.count("ext.promoted").await, 3);
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PublicationStep {
    Block,
    Publish,
    Reconcile(PromotionState),
}

/// Observe real durable boundaries, then delegate to the real admission hook.
/// Injected publication failures deliberately leave that hook's block intact.
struct CheckingPublisher {
    registry: ControlRegistry,
    store: Arc<Store>,
    lock_at_block: Option<Vec<u8>>,
    fail_publication: AtomicBool,
    steps: Mutex<Vec<PublicationStep>>,
}
impl CheckingPublisher {
    fn new(fixture: &Fixture, fail_publication: bool) -> Arc<Self> {
        Arc::new(Self {
            registry: ControlRegistry::new(fixture.store.owner().clone()),
            store: fixture.store.clone(),
            lock_at_block: Lock::read_snapshot(&fixture.home).unwrap(),
            fail_publication: AtomicBool::new(fail_publication),
            steps: Mutex::new(vec![]),
        })
    }

    fn assert_excluded(&self, ext_id: &str) {
        assert!(self.registry.allow(ext_id).is_err());
        assert!(
            self.store
                .owner()
                .installer_gate()
                .try_lock_owned()
                .is_err()
        );
    }

    async fn assert_durable(&self, intent: &PromotionIntent) {
        self.assert_excluded(&intent.ext_id);
        let stored = self
            .store
            .promotion_intent(intent.operation_id.clone())
            .await
            .unwrap();
        assert_eq!(stored.state, intent.state);
        let proposal = self
            .store
            .proposal(intent.proposal_id.clone())
            .await
            .unwrap();
        let (snapshot, state, event_kind) = match intent.state {
            PromotionState::Committed => (
                Some(intent.after_lock.as_bytes()),
                ProposalState::Promoted,
                "ext.promoted",
            ),
            PromotionState::Aborted => (
                intent.before_lock.as_deref().map(str::as_bytes),
                ProposalState::Approved,
                "ext.promotion_aborted",
            ),
            PromotionState::Prepared => panic!("publication preceded the writer commit"),
        };
        assert_eq!(proposal.state, state);
        assert_eq!(
            Lock::read_snapshot(self.store.owner().home())
                .unwrap()
                .as_deref(),
            snapshot
        );
        let events = self
            .store
            .event_path("sys".into(), None, None)
            .await
            .unwrap();
        assert_eq!(
            events
                .events
                .iter()
                .filter(|event| {
                    event.kind == event_kind && event.payload["operation_id"] == intent.operation_id
                })
                .count(),
            1,
            "the durable event must exist before publication"
        );
    }
}
impl PromotionPublication for CheckingPublisher {
    fn block_before_lock(&self, ext_id: &str) -> Result<(), MutationReason> {
        assert_eq!(ext_id, "sample");
        assert_eq!(
            Lock::read_snapshot(self.store.owner().home()).unwrap(),
            self.lock_at_block,
            "the lock must not change before the admission block"
        );
        self.registry.block_before_lock(ext_id)?;
        self.assert_excluded(ext_id);
        self.steps.lock().unwrap().push(PublicationStep::Block);
        Ok(())
    }

    fn publish_after_commit<'a>(
        &'a self,
        intent: &'a PromotionIntent,
    ) -> PromotionPublicationFuture<'a> {
        Box::pin(async move {
            self.assert_durable(intent).await;
            self.steps.lock().unwrap().push(PublicationStep::Publish);
            if self.fail_publication.load(Ordering::SeqCst) {
                return Err(MutationReason::IoError);
            }
            self.registry.publish_after_commit(intent).await
        })
    }

    fn reconcile<'a>(&'a self, intent: &'a PromotionIntent) -> PromotionPublicationFuture<'a> {
        Box::pin(async move {
            self.assert_durable(intent).await;
            self.steps
                .lock()
                .unwrap()
                .push(PublicationStep::Reconcile(intent.state));
            if self.fail_publication.load(Ordering::SeqCst) {
                return Err(MutationReason::IoError);
            }
            self.registry.reconcile(intent).await
        })
    }
}

impl fictor::installer::controls::ControlPublication for CheckingPublisher {
    fn block_admissions(&self, ext_id: &str) -> Result<(), MutationReason> {
        fictor::installer::controls::ControlPublication::block_admissions(&self.registry, ext_id)
    }
    fn publish_enabled<'a>(
        &'a self,
        ext_id: &'a str,
        key: &'a str,
        enabled: bool,
    ) -> fictor::installer::controls::PublicationFuture<'a> {
        fictor::installer::controls::ControlPublication::publish_enabled(
            &self.registry,
            ext_id,
            key,
            enabled,
        )
    }
    fn publish_reset<'a>(
        &'a self,
        selection: &'a fictor::crash_recovery::ResetCrashes,
    ) -> fictor::installer::controls::PublicationFuture<'a> {
        fictor::installer::controls::ControlPublication::publish_reset(&self.registry, selection)
    }
}

fn controls(
    f: &Fixture,
    publisher: Arc<CheckingPublisher>,
) -> fictor::installer::controls::AdminControlService {
    let secrets = fictor::secrets::SecretStore::open_with_lease(
        f.store.owner().clone(),
        fictor::secrets::BackendKind::File,
        Default::default(),
    )
    .unwrap();
    // Deliberately supply an offline coordinator: the service must bind all
    // reconciliation to its own live publication authority.
    fictor::installer::controls::AdminControlService::new(
        f.store.clone(),
        secrets,
        f.coordinator(),
        Some(publisher),
    )
}

#[tokio::test]
async fn administrative_recovery_publishes_a_previous_promotion_through_the_same_registry() {
    let f = Fixture::new().await;
    let p = f.approve(&f.checked("1.0.0").await, json!({})).await;
    let intent = f.prepared(&p).await;
    materialize(&f.home, f.store.clone(), f.lease.clone(), p.id.clone())
        .await
        .unwrap();
    f.publish_snapshot(&intent.after_lock);
    let publisher = CheckingPublisher::new(&f, false);
    let result = controls(&f, publisher.clone())
        .call(
            "ext.set_enabled",
            &json!({"ext_id":"sample","enabled":true}),
        )
        .await
        .unwrap();
    assert_eq!(result["changed"], false);
    assert_eq!(
        *publisher.steps.lock().unwrap(),
        [
            PublicationStep::Block,
            PublicationStep::Reconcile(PromotionState::Committed)
        ]
    );
    assert!(publisher.registry.allow("sample").is_ok());
    assert_eq!(f.count("ext.promoted").await, 1);
}

#[tokio::test]
async fn failed_previous_publication_never_commits_the_requested_control_or_reset() {
    let f = Fixture::new().await;
    let p = f.approve(&f.checked("1.0.0").await, json!({})).await;
    let intent = f.prepared(&p).await;
    materialize(&f.home, f.store.clone(), f.lease.clone(), p.id.clone())
        .await
        .unwrap();
    f.publish_snapshot(&intent.after_lock);
    let publisher = CheckingPublisher::new(&f, true);
    let service = controls(&f, publisher.clone());
    let request = json!({"ext_id":"sample","enabled":false});
    let error = service.call("ext.set_enabled", &request).await.unwrap_err();
    assert_eq!(
        error,
        fictor::admin::AdminMutationError::none(MutationReason::IoError)
    );
    assert_eq!(
        Lock::read_snapshot(&f.home).unwrap().unwrap(),
        intent.after_lock.as_bytes()
    );
    assert_eq!(
        f.store.proposal(p.id.clone()).await.unwrap().state,
        ProposalState::Promoted
    );
    let head = f.store.session("sys".into()).await.unwrap().head_id;
    for (method, params) in [
        ("ext.set_enabled", request.clone()),
        ("ext.reset_crashes", json!({"ext_id":"sample"})),
    ] {
        assert_eq!(
            service.call(method, &params).await.unwrap_err(),
            fictor::admin::AdminMutationError::none(MutationReason::RecoveryRequired)
        );
        assert_eq!(
            Lock::read_snapshot(&f.home).unwrap().unwrap(),
            intent.after_lock.as_bytes()
        );
        assert_eq!(f.store.session("sys".into()).await.unwrap().head_id, head);
    }
    publisher.fail_publication.store(false, Ordering::SeqCst);
    let coordinator =
        PromotionCoordinator::with_publication(f.store.clone(), f.lease.clone(), publisher.clone());
    assert_eq!(
        coordinator
            .admit_promotion(p.id)
            .await
            .unwrap()
            .operation_id,
        intent.operation_id
    );
    assert_eq!(
        service.call("ext.set_enabled", &request).await.unwrap()["changed"],
        true
    );
    assert!(!Lock::load_required(&f.home).unwrap().extensions["sample"].enabled);
    assert_eq!(f.count("ext.promoted").await, 1);
}

#[tokio::test]
async fn online_promotion_blocks_before_lock_and_publishes_only_after_the_writer_commit() {
    let f = Fixture::new().await;
    let p = f.approve(&f.checked("1.0.0").await, json!({})).await;
    let publisher = CheckingPublisher::new(&f, false);
    let coordinator =
        PromotionCoordinator::with_publication(f.store.clone(), f.lease.clone(), publisher.clone());
    assert!(publisher.registry.allow("sample").is_ok());
    let committed = coordinator.promote(p.id.clone()).await.unwrap();
    assert_eq!(committed.state, PromotionState::Committed);
    assert_eq!(
        *publisher.steps.lock().unwrap(),
        [PublicationStep::Block, PublicationStep::Publish]
    );
    assert!(publisher.registry.allow("sample").is_ok());
    assert_eq!(f.count("ext.promoted").await, 1);
    assert!(f.store.pending_promotion().await.unwrap().is_none());
    assert!(!f.home.join("extensions/quarantine").join(p.id).exists());
}

#[tokio::test]
async fn publication_failure_keeps_the_committed_lock_and_real_admission_block() {
    let f = Fixture::new().await;
    let p = f.approve(&f.checked("1.0.0").await, json!({})).await;
    let publisher = CheckingPublisher::new(&f, true);
    let coordinator =
        PromotionCoordinator::with_publication(f.store.clone(), f.lease.clone(), publisher.clone());
    assert!(matches!(
        coordinator.promote(p.id.clone()).await,
        Err(ActivationError::Publication)
    ));
    let history = f.store.event_path("sys".into(), None, None).await.unwrap();
    let event = history
        .events
        .iter()
        .find(|event| event.kind == "ext.promoted")
        .unwrap();
    let intent = f
        .store
        .promotion_intent(event.payload["operation_id"].as_str().unwrap().into())
        .await
        .unwrap();
    assert_eq!(intent.state, PromotionState::Committed);
    assert_eq!(
        f.store.proposal(p.id.clone()).await.unwrap().state,
        ProposalState::Promoted
    );
    assert_eq!(
        Lock::read_snapshot(&f.home).unwrap().as_deref(),
        Some(intent.after_lock.as_bytes())
    );
    assert_eq!(
        *publisher.steps.lock().unwrap(),
        [PublicationStep::Block, PublicationStep::Publish]
    );
    assert!(publisher.registry.allow("sample").is_err());
    assert!(f.store.pending_promotion().await.unwrap().is_none());
    assert_eq!(f.count("ext.promoted").await, 1);
    // A read of the committed result cannot claim publication or undo its block.
    assert_eq!(
        coordinator
            .operation(intent.operation_id.clone())
            .await
            .unwrap()
            .state,
        PromotionState::Committed
    );
    assert!(publisher.registry.allow("sample").is_err());
    assert_eq!(f.count("ext.promoted").await, 1);
    let lock_file = fs::File::open(f.home.join("extensions/lock.json")).unwrap();
    let original_inode = lock_file.metadata().unwrap();
    publisher.fail_publication.store(false, Ordering::SeqCst);
    let retry = coordinator.admit_promotion(p.id).await.unwrap();
    assert_eq!(retry.operation_id, intent.operation_id);
    assert_eq!(retry.state, PromotionState::Committed);
    assert!(publisher.registry.allow("sample").is_ok());
    let current_inode = fs::metadata(f.home.join("extensions/lock.json")).unwrap();
    assert_eq!(
        (current_inode.dev(), current_inode.ino()),
        (original_inode.dev(), original_inode.ino()),
        "retry publication must not replace the durable lock"
    );
    assert_eq!(
        fs::read(f.home.join("extensions/lock.json")).unwrap(),
        intent.after_lock.as_bytes()
    );
    assert_eq!(
        *publisher.steps.lock().unwrap(),
        [
            PublicationStep::Block,
            PublicationStep::Publish,
            PublicationStep::Publish
        ]
    );
    assert_eq!(f.count("ext.promotion_prepared").await, 1);
    assert_eq!(f.count("ext.promoted").await, 1);
}

#[tokio::test]
async fn recovering_a_published_lock_commits_before_reconciling_real_admissions() {
    let f = Fixture::new().await;
    let p = f.approve(&f.checked("1.0.0").await, json!({})).await;
    let intent = f.prepared(&p).await;
    materialize(&f.home, f.store.clone(), f.lease.clone(), p.id.clone())
        .await
        .unwrap();
    f.publish_snapshot(&intent.after_lock);
    let f = f.reopen().await;
    let publisher = CheckingPublisher::new(&f, false);
    let coordinator =
        PromotionCoordinator::with_publication(f.store.clone(), f.lease.clone(), publisher.clone());
    let recovered = coordinator.reconcile().await.unwrap().unwrap();
    assert_eq!(recovered.operation_id, intent.operation_id);
    assert_eq!(recovered.state, PromotionState::Committed);
    assert_eq!(
        *publisher.steps.lock().unwrap(),
        [
            PublicationStep::Block,
            PublicationStep::Reconcile(PromotionState::Committed)
        ]
    );
    assert!(publisher.registry.allow("sample").is_ok());
    assert!(coordinator.reconcile().await.unwrap().is_none());
    assert_eq!(f.count("ext.promoted").await, 1);
}

#[tokio::test]
async fn aborting_an_unpublished_update_restores_the_previous_versions_admission() {
    let f = Fixture::new().await;
    let old = f.approve(&f.checked("1.0.0").await, json!({})).await;
    let old_intent = f.coordinator().promote(old.id.clone()).await.unwrap();
    let p = f.approve(&f.checked("2.0.0").await, json!({})).await;
    let intent = f.prepared(&p).await;
    let f = f.reopen().await;
    let publisher = CheckingPublisher::new(&f, false);
    let coordinator =
        PromotionCoordinator::with_publication(f.store.clone(), f.lease.clone(), publisher.clone());
    let recovered = coordinator.reconcile().await.unwrap().unwrap();
    assert_eq!(recovered.operation_id, intent.operation_id);
    assert_eq!(recovered.state, PromotionState::Aborted);
    assert_eq!(
        *publisher.steps.lock().unwrap(),
        [
            PublicationStep::Block,
            PublicationStep::Reconcile(PromotionState::Aborted)
        ]
    );
    assert!(publisher.registry.allow("sample").is_ok());
    let lock = Lock::load_required(&f.home).unwrap();
    assert_eq!(lock.extensions["sample"].active, old_intent.key);
    assert_ne!(lock.extensions["sample"].active, intent.key);
    assert_eq!(
        Lock::read_snapshot(&f.home).unwrap().as_deref(),
        intent.before_lock.as_deref().map(str::as_bytes)
    );
    assert_eq!(
        f.store.proposal(p.id).await.unwrap().state,
        ProposalState::Approved
    );
    assert_eq!(f.count("ext.promoted").await, 1);
    assert_eq!(f.count("ext.promotion_aborted").await, 1);
}

#[tokio::test]
async fn retrying_a_historical_commit_cannot_release_a_newer_versions_publication_block() {
    let f = Fixture::new().await;
    let old = f.approve(&f.checked("1.0.0").await, json!({})).await;
    let old_intent = f.coordinator().promote(old.id.clone()).await.unwrap();
    let current = f.approve(&f.checked("2.0.0").await, json!({})).await;
    let publisher = CheckingPublisher::new(&f, true);
    let coordinator =
        PromotionCoordinator::with_publication(f.store.clone(), f.lease.clone(), publisher.clone());
    assert!(matches!(
        coordinator.promote(current.id.clone()).await,
        Err(ActivationError::Publication)
    ));
    let current_lock = Lock::read_snapshot(&f.home).unwrap().unwrap();
    let current_key = Lock::parse_snapshot(&current_lock).unwrap().extensions["sample"]
        .active
        .clone();
    assert_ne!(current_key, old_intent.key);
    assert!(publisher.registry.allow("sample").is_err());

    publisher.fail_publication.store(false, Ordering::SeqCst);
    let historical = coordinator.admit_promotion(old.id).await.unwrap();
    assert_eq!(historical.operation_id, old_intent.operation_id);
    assert!(publisher.registry.allow("sample").is_err());
    assert_eq!(
        *publisher.steps.lock().unwrap(),
        [PublicationStep::Block, PublicationStep::Publish],
        "historical success must not republish over the newer blocked state"
    );
    assert_eq!(Lock::read_snapshot(&f.home).unwrap().unwrap(), current_lock);
    assert_eq!(f.count("ext.promotion_prepared").await, 2);
    assert_eq!(f.count("ext.promoted").await, 2);

    let resumed = coordinator.admit_promotion(current.id).await.unwrap();
    assert_eq!(resumed.key, current_key);
    assert_eq!(resumed.state, PromotionState::Committed);
    assert!(publisher.registry.allow("sample").is_ok());
    assert_eq!(Lock::read_snapshot(&f.home).unwrap().unwrap(), current_lock);
    assert_eq!(f.count("ext.promotion_prepared").await, 2);
    assert_eq!(f.count("ext.promoted").await, 2);
}
