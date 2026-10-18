use fictor::store::{
    HumanDecision, NewProposal, ProposalCheck, ProposalState as State, ProposalUpdate,
    ResolvedPackage, Store,
};
use serde_json::json;
use std::sync::Arc;

async fn store() -> (tempfile::TempDir, Arc<Store>) {
    let temp = tempfile::tempdir().unwrap();
    fictor::initialize(temp.path()).await.unwrap();
    let store = Arc::new(Store::open(temp.path()).await.unwrap());
    (temp, store)
}
fn input() -> NewProposal {
    NewProposal {
        ext_id: "sample".into(),
        version: "0.1.0".into(),
        source: json!({"kind":"local","path":"/fixture"}),
        manifest: json!({"id":"sample","version":"0.1.0"}),
        tainted: false,
        update_of: None,
    }
}
fn checked() -> ProposalUpdate {
    ProposalUpdate {
        hash: Some(format!("sha256:{}", "a".repeat(64))),
        checks: Some(vec![
            ProposalCheck {
                name: "manifest".into(),
                passed: true,
                blocking: true,
                detail: None,
            },
            ProposalCheck {
                name: "smoke".into(),
                passed: true,
                blocking: true,
                detail: Some("passed".into()),
            },
        ]),
        packages: Some(vec![ResolvedPackage {
            ecosystem: "fixture".into(),
            name: "example".into(),
            version: "1.0.0".into(),
        }]),
        decision: None,
    }
}
async fn ready(store: &Store) -> String {
    let p = store.receive_proposal(input()).await.unwrap();
    store
        .transition_proposal(
            p.id.clone(),
            State::Received,
            State::Checking,
            ProposalUpdate::default(),
        )
        .await
        .unwrap();
    store
        .transition_proposal(p.id.clone(), State::Checking, State::Checked, checked())
        .await
        .unwrap();
    p.id
}

#[tokio::test]
async fn local_receive_persists_and_never_serializes_or_audits_nonce() {
    let (_root, store) = store().await;
    let p = store.receive_proposal(input()).await.unwrap();
    assert_eq!(p.state, State::Received);
    assert!(!p.tainted);
    assert!(p.hash.is_none());
    assert!(p.checks.is_none());
    let nonce = store.proposal_nonce(p.id.clone()).await.unwrap();
    assert_eq!(nonce.as_str().len(), 64);
    let encoded = serde_json::to_string(&p).unwrap();
    assert!(!encoded.contains("nonce"));
    assert!(!encoded.contains(nonce.as_str()));
    assert!(!format!("{p:?}").contains(nonce.as_str()));
    let events = store
        .event_path("sys".into(), None, None)
        .await
        .unwrap()
        .events;
    let event = events.last().unwrap();
    assert_eq!(event.kind, "ext.proposed");
    assert_eq!(event.actor, "core");
    assert_eq!(event.payload["proposal_id"], p.id);
    assert!(
        !serde_json::to_string(event)
            .unwrap()
            .contains(nonce.as_str())
    );
    assert_eq!(
        store.proposal(p.id).await.unwrap().source,
        json!({"kind":"local","path":"/fixture"})
    );
}
#[tokio::test]
async fn rejects_non_local_tainted_and_inconsistent_proposal_identity() {
    let (_root, store) = store().await;
    let mut p = input();
    p.source = json!({"kind":"ai"});
    assert!(store.receive_proposal(p).await.is_err());
    let mut p = input();
    p.tainted = true;
    assert!(store.receive_proposal(p).await.is_err());
    let mut p = input();
    p.manifest["id"] = json!("other");
    assert!(store.receive_proposal(p).await.is_err());
    let mut p = input();
    p.ext_id = "../sample".into();
    assert!(store.receive_proposal(p).await.is_err());
    let mut p = input();
    p.manifest["version"] = json!("2.0.0");
    assert!(store.receive_proposal(p).await.is_err());
}
#[tokio::test]
async fn compare_and_swap_has_one_winner_and_one_audit_event() {
    let (_root, store) = store().await;
    let p = store.receive_proposal(input()).await.unwrap();
    let (a, b) = tokio::join!(
        store.transition_proposal(
            p.id.clone(),
            State::Received,
            State::Checking,
            ProposalUpdate::default()
        ),
        store.transition_proposal(
            p.id.clone(),
            State::Received,
            State::Checking,
            ProposalUpdate::default()
        )
    );
    assert_ne!(a.is_ok(), b.is_ok());
    assert_eq!(store.proposal(p.id).await.unwrap().state, State::Checking);
    let events = store
        .event_path("sys".into(), None, None)
        .await
        .unwrap()
        .events;
    assert_eq!(
        events.iter().filter(|e| e.kind == "ext.checking").count(),
        1
    );
}
#[tokio::test]
async fn failed_checks_invalid_hash_and_missing_results_cannot_become_checked() {
    let (_root, store) = store().await;
    let p = store.receive_proposal(input()).await.unwrap();
    store
        .transition_proposal(
            p.id.clone(),
            State::Received,
            State::Checking,
            ProposalUpdate::default(),
        )
        .await
        .unwrap();
    assert!(
        store
            .transition_proposal(
                p.id.clone(),
                State::Checking,
                State::Checked,
                ProposalUpdate::default()
            )
            .await
            .is_err()
    );
    let mut results = checked();
    results.hash = Some("sha256:../bad".into());
    assert!(
        store
            .transition_proposal(p.id.clone(), State::Checking, State::Checked, results)
            .await
            .is_err()
    );
    let mut results = checked();
    results.checks.as_mut().unwrap()[0].passed = false;
    assert!(
        store
            .transition_proposal(p.id.clone(), State::Checking, State::Checked, results)
            .await
            .is_err()
    );
    let mut results = checked();
    results.checks = Some(vec![]);
    assert!(
        store
            .transition_proposal(p.id.clone(), State::Checking, State::Checked, results)
            .await
            .is_err()
    );
    assert_eq!(
        store.proposal(p.id.clone()).await.unwrap().state,
        State::Checking
    );
    let failed = store
        .transition_proposal(
            p.id,
            State::Checking,
            State::Failed,
            ProposalUpdate {
                checks: Some(vec![ProposalCheck {
                    name: "smoke".into(),
                    passed: false,
                    blocking: true,
                    detail: Some("unavailable".into()),
                }]),
                ..ProposalUpdate::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(failed.state, State::Failed);
    assert!(
        store
            .transition_proposal(
                failed.id,
                State::Failed,
                State::Checking,
                ProposalUpdate::default()
            )
            .await
            .is_err()
    );
}
#[tokio::test]
async fn human_decision_requires_matching_nonce_rotates_it_and_blocks_replay() {
    let (_root, store) = store().await;
    let id = ready(&store).await;
    let other = store.receive_proposal(input()).await.unwrap();
    assert!(
        store
            .transition_proposal(
                id.clone(),
                State::Checked,
                State::Approved,
                ProposalUpdate::default()
            )
            .await
            .is_err()
    );
    let wrong = store.proposal_nonce(other.id).await.unwrap();
    assert!(
        store
            .transition_proposal(
                id.clone(),
                State::Checked,
                State::Approved,
                ProposalUpdate {
                    decision: Some(HumanDecision::User(wrong)),
                    ..ProposalUpdate::default()
                }
            )
            .await
            .is_err()
    );
    let nonce = store.proposal_nonce(id.clone()).await.unwrap();
    let replay = store.proposal_nonce(id.clone()).await.unwrap();
    let old = nonce.as_str().to_owned();
    let approved = store
        .transition_proposal(
            id.clone(),
            State::Checked,
            State::Approved,
            ProposalUpdate {
                decision: Some(HumanDecision::User(nonce)),
                ..ProposalUpdate::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(approved.decided_by.as_deref(), Some("user"));
    assert_eq!(approved.state, State::Approved);
    assert_eq!(approved.packages.unwrap()[0].name, "example");
    assert!(store.proposal_nonce(id.clone()).await.unwrap().as_str() != old);
    assert!(
        store
            .transition_proposal(
                id.clone(),
                State::Checked,
                State::Approved,
                ProposalUpdate {
                    decision: Some(HumanDecision::User(replay)),
                    ..ProposalUpdate::default()
                }
            )
            .await
            .is_err()
    );
    assert!(
        store
            .transition_proposal(
                id,
                State::Approved,
                State::Promoted,
                ProposalUpdate::default()
            )
            .await
            .is_err()
    );
    let events = store
        .event_path("sys".into(), None, None)
        .await
        .unwrap()
        .events;
    assert_eq!(events.last().unwrap().kind, "ext.approved");
    assert_eq!(events.last().unwrap().actor, "user");
}
#[tokio::test]
async fn explicit_user_rejection_is_terminal_and_received_can_fail() {
    let (_root, store) = store().await;
    let id = ready(&store).await;
    let nonce = store.proposal_nonce(id.clone()).await.unwrap();
    let rejected = store
        .transition_proposal(
            id.clone(),
            State::Checked,
            State::Rejected,
            ProposalUpdate {
                decision: Some(HumanDecision::User(nonce)),
                ..ProposalUpdate::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(rejected.decided_by.as_deref(), Some("user"));
    assert!(
        store
            .transition_proposal(
                id,
                State::Rejected,
                State::Checking,
                ProposalUpdate::default()
            )
            .await
            .is_err()
    );
    let p = store.receive_proposal(input()).await.unwrap();
    assert_eq!(
        store
            .transition_proposal(
                p.id,
                State::Received,
                State::Failed,
                ProposalUpdate::default()
            )
            .await
            .unwrap()
            .state,
        State::Failed
    );
}
#[tokio::test]
async fn audit_failure_rolls_back_both_receive_and_transition() {
    let (_root, store) = store().await;
    store.write(|db|{db.execute_batch("CREATE TRIGGER reject_proposal_audit BEFORE INSERT ON events WHEN NEW.kind='ext.proposed' BEGIN SELECT RAISE(ABORT,'fixture'); END;")?;Ok(())}).await.unwrap();
    assert!(store.receive_proposal(input()).await.is_err());
    let count: i64 = store
        .write(|db| Ok(db.query_row("SELECT count(*) FROM proposals", [], |r| r.get(0))?))
        .await
        .unwrap();
    assert_eq!(count, 0);
    store
        .write(|db| {
            db.execute_batch("DROP TRIGGER reject_proposal_audit;")?;
            Ok(())
        })
        .await
        .unwrap();
    let p = store.receive_proposal(input()).await.unwrap();
    let head = store.session("sys".into()).await.unwrap().head_id;
    store.write(|db|{db.execute_batch("CREATE TRIGGER reject_transition_audit BEFORE INSERT ON events WHEN NEW.kind='ext.checking' BEGIN SELECT RAISE(ABORT,'fixture'); END;")?;Ok(())}).await.unwrap();
    assert!(
        store
            .transition_proposal(
                p.id.clone(),
                State::Received,
                State::Checking,
                ProposalUpdate::default()
            )
            .await
            .is_err()
    );
    assert_eq!(store.proposal(p.id).await.unwrap().state, State::Received);
    assert_eq!(store.session("sys".into()).await.unwrap().head_id, head);
}
#[tokio::test]
async fn proposals_survive_reopen_with_nonce_and_checked_results() {
    let root = tempfile::tempdir().unwrap();
    fictor::initialize(root.path()).await.unwrap();
    let store = Store::open(root.path()).await.unwrap();
    let id = ready(&store).await;
    let nonce = store
        .proposal_nonce(id.clone())
        .await
        .unwrap()
        .as_str()
        .to_owned();
    store.shutdown().await.unwrap();
    let reopened = Store::open(root.path()).await.unwrap();
    let p = reopened.proposal(id.clone()).await.unwrap();
    assert_eq!(p.state, State::Checked);
    assert!(p.hash.is_some());
    assert_eq!(p.checks.unwrap().len(), 2);
    assert!(reopened.proposal_nonce(id).await.unwrap().as_str() == nonce);
    reopened.shutdown().await.unwrap();
}
