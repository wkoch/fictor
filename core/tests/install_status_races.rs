use fictor::{
    admin::MutationReason,
    config::Config,
    installer::{
        local::LocalChecker,
        lock::Lock,
        online::{InstallService, InstallStatus},
        overrides::Overrides,
    },
    ownership::HomeLease,
    proxy::{EgressProxy, nat64::Nat64Prefixes},
    secrets::{BackendKind, Redactor, SecretStore},
    store::{HumanDecision, ProposalState, ProposalUpdate, ReviewBase, Store},
    supervisor::Supervisor,
};
use serde_json::json;
use std::{fs, future::Future, pin::Pin, sync::Arc, task::Poll};

struct Fixture {
    _root: tempfile::TempDir,
    store: Arc<Store>,
    service: InstallService,
    id: String,
}

impl Fixture {
    async fn checked() -> Self {
        let root = tempfile::Builder::new()
            .prefix("fx-status-race-")
            .tempdir_in("/tmp")
            .unwrap();
        let home = root.path().join("core");
        let owner = HomeLease::create_for_init(&home).unwrap();
        fictor::initialize_owned(owner.clone()).await.unwrap();
        let store = Arc::new(Store::open_with_lease(owner).await.unwrap());
        let mut config = Config::load(&home).unwrap();
        config.providers.clear();
        config.sandbox.home_ro_files.clear();
        let secrets = Arc::new(
            SecretStore::open_with_lease(
                store.owner().clone(),
                BackendKind::File,
                Redactor::default(),
            )
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
                root.path(),
                Arc::new(config),
                secrets,
                store.clone(),
                proxy,
            )
            .unwrap(),
        );
        let checker = LocalChecker::new(
            home,
            Nat64Prefixes::default(),
            store.clone(),
            supervisor,
            Default::default(),
        );
        let service = InstallService::new(store.clone(), checker.clone())
            .await
            .unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join("fictor.yaml"),
            json!({"schema":1,"id":"status-race","version":"1.0.0","description":"Status race fixture","runtime":{"kind":"none"},"scope":"global","mcp":false}).to_string(),
        )
        .unwrap();
        let checked = checker.check_local(&source).await.unwrap();
        assert_eq!(checked.proposal.state, ProposalState::Checked);
        fs::remove_dir_all(source).unwrap();
        Self {
            _root: root,
            store,
            service,
            id: checked.proposal.id,
        }
    }

    async fn decide_under_held_gate(&self, state: ProposalState, overrides: Option<Overrides>) {
        let lock = Lock::load_required(self.store.owner().home()).unwrap();
        let review_base = (state == ProposalState::Approved).then(|| ReviewBase {
            update_of: None,
            hash: lock.review_base_hash("status-race").unwrap(),
        });
        self.store
            .transition_proposal(
                self.id.clone(),
                ProposalState::Checked,
                state,
                ProposalUpdate {
                    decision: Some(HumanDecision::User(
                        self.store.proposal_nonce(self.id.clone()).await.unwrap(),
                    )),
                    review_base,
                    overrides,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }
}

// Drive the actual status request through its first serialized snapshot and
// into the held gate. The writer barrier establishes ordering without sleeps.
async fn wait_at_gate(
    mut status: Pin<
        &mut impl Future<Output = Result<InstallStatus, fictor::admin::AdminMutationError>>,
    >,
    store: &Store,
) {
    std::future::poll_fn(|cx| {
        assert!(status.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    store.write(|_| Ok(())).await.unwrap();
    std::future::poll_fn(|cx| {
        assert!(status.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}

#[tokio::test]
async fn status_waiting_for_gate_does_not_present_a_review_after_rejection() {
    let fixture = Fixture::checked().await;
    let section = fixture.store.owner().installer_gate().lock_owned().await;
    let status = fixture.service.status(fixture.id.clone(), None);
    tokio::pin!(status);
    wait_at_gate(status.as_mut(), &fixture.store).await;
    fixture
        .decide_under_held_gate(ProposalState::Rejected, None)
        .await;
    drop(section);

    let status = status.await.unwrap();
    assert_eq!(status.state, ProposalState::Rejected);
    assert!(status.review.is_none());
    assert!(status.review_hash.is_none());
    assert!(status.nonce.is_none());
}

#[tokio::test]
async fn status_waiting_for_gate_rejects_patch_that_differs_from_committed_approval() {
    let fixture = Fixture::checked().await;
    let section = fixture.store.owner().installer_gate().lock_owned().await;
    let requested = Overrides::default();
    let approved = Overrides::from_value(json!({"permissions":{"fs":{"read":[]}}})).unwrap();
    assert_ne!(requested, approved);
    let status = fixture.service.status(fixture.id.clone(), Some(requested));
    tokio::pin!(status);
    wait_at_gate(status.as_mut(), &fixture.store).await;
    fixture
        .decide_under_held_gate(ProposalState::Approved, Some(approved.clone()))
        .await;
    drop(section);

    assert_eq!(
        status.await.err().unwrap().reason,
        MutationReason::InvalidState
    );
    let proposal = fixture.store.proposal(fixture.id.clone()).await.unwrap();
    assert_eq!(proposal.state, ProposalState::Approved);
    assert_eq!(proposal.overrides, approved);
}
