use fictor::store::{
    HumanDecision, NewProposal, ProposalCheck, ProposalIdentity, ProposalState as State,
    ProposalUpdate, ResolvedPackage, ReviewBase, Store,
};
use serde_json::json;
use std::{os::unix::fs::PermissionsExt, sync::Arc};

async fn store() -> (tempfile::TempDir, Arc<Store>) {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    fictor::initialize(temp.path()).await.unwrap();
    let store = Arc::new(Store::open(temp.path()).await.unwrap());
    (temp, store)
}
fn input() -> NewProposal {
    NewProposal {
        source: json!({"kind":"local","path":"/fixture"}),
        tainted: false,
    }
}
fn identifying() -> ProposalUpdate {
    let manifest = fictor::installer::manifest::Manifest::parse(
        &json!({
            "schema":1,"id":"sample","version":"0.1.0","description":"Fixture",
            "runtime":{"kind":"none"}
        })
        .to_string(),
    )
    .unwrap();
    ProposalUpdate {
        identity: Some(ProposalIdentity {
            ext_id: manifest.id.clone(),
            version: manifest.version.clone(),
            manifest: serde_json::to_value(&manifest).unwrap(),
            update_of: None,
        }),
        ..Default::default()
    }
}
fn receipt_failure(reason: &str) -> ProposalUpdate {
    ProposalUpdate {
        failure_reason: Some(reason.into()),
        checks: Some(vec![ProposalCheck {
            name: "receipt".into(),
            passed: false,
            blocking: true,
            detail: Some(reason.into()),
        }]),
        ..Default::default()
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
                detail: Some(smoke_detail()),
            },
            passed("dependencies"),
            passed("bundle"),
            passed("declarations"),
        ]),
        packages: Some(vec![ResolvedPackage {
            ecosystem: "fixture".into(),
            name: "example".into(),
            version: "1.0.0".into(),
        }]),
        decision: None,
        review_base: Some(base()),
        ..Default::default()
    }
}
fn passed(name: &str) -> ProposalCheck {
    ProposalCheck {
        name: name.into(),
        passed: true,
        blocking: true,
        detail: None,
    }
}
fn base() -> ReviewBase {
    ReviewBase {
        update_of: None,
        hash: fictor::installer::lock::Lock::default()
            .review_base_hash("sample")
            .unwrap(),
    }
}
fn smoke_detail() -> String {
    let catalog = fictor::gateway::PinnedCatalog::new(vec![]).unwrap();
    json!({"tools":catalog.tools(),"tools_hash":catalog.hash()}).to_string()
}
async fn ready(store: &Store) -> String {
    let p = store.begin_attempt(input()).await.unwrap();
    store
        .transition_proposal(
            p.id.clone(),
            State::Received,
            State::Checking,
            identifying(),
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
async fn checked_binds_current_base_and_approval_never_refreshes_a_stale_review() {
    let (_root, store) = store().await;
    let p = store.begin_attempt(input()).await.unwrap();
    let mut identity = identifying();
    identity.identity.as_mut().unwrap().update_of = Some("0.0.1-0123456789ab".into());
    store
        .transition_proposal(p.id.clone(), State::Received, State::Checking, identity)
        .await
        .unwrap();
    let mut incomplete = checked();
    incomplete.review_base = None;
    assert!(
        store
            .transition_proposal(p.id.clone(), State::Checking, State::Checked, incomplete)
            .await
            .is_err()
    );
    let reviewed = store
        .transition_proposal(p.id.clone(), State::Checking, State::Checked, checked())
        .await
        .unwrap();
    assert_eq!(reviewed.update_of, None);
    assert_eq!(reviewed.review_base_hash, Some(base().hash));
    let nonce = store
        .proposal_nonce(p.id.clone())
        .await
        .unwrap()
        .as_str()
        .to_owned();
    let head = store.session("sys".into()).await.unwrap().head_id;
    for review_base in [
        None,
        Some(ReviewBase {
            update_of: Some("0.0.2-abcdef123456".into()),
            ..base()
        }),
        Some(ReviewBase {
            hash: format!("sha256:{}", "f".repeat(64)),
            ..base()
        }),
    ] {
        let decision = store.proposal_nonce(p.id.clone()).await.unwrap();
        let result = store
            .transition_proposal(
                p.id.clone(),
                State::Checked,
                State::Approved,
                ProposalUpdate {
                    decision: Some(HumanDecision::User(decision)),
                    review_base,
                    ..Default::default()
                },
            )
            .await;
        assert!(matches!(
            result,
            Err(fictor::store::StoreError::Invalid("promotion:stale_base"))
        ));
        let current = store.proposal(p.id.clone()).await.unwrap();
        assert_eq!(current.state, State::Checked);
        assert_eq!(current.review_base_hash, reviewed.review_base_hash);
        assert_eq!(
            store.proposal_nonce(p.id.clone()).await.unwrap().as_str(),
            nonce
        );
        assert_eq!(store.session("sys".into()).await.unwrap().head_id, head);
    }
    // A migrated approval without a review base must be reviewed again.
    let id = p.id.clone();
    store
        .write(move |db| {
            db.execute(
                "UPDATE proposals SET review_base_hash=NULL WHERE id=?1",
                [id],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let decision = store.proposal_nonce(p.id.clone()).await.unwrap();
    assert!(matches!(
        store
            .transition_proposal(
                p.id,
                State::Checked,
                State::Approved,
                ProposalUpdate {
                    decision: Some(HumanDecision::User(decision)),
                    review_base: Some(base()),
                    ..Default::default()
                }
            )
            .await,
        Err(fictor::store::StoreError::Invalid("promotion:stale_base"))
    ));
}

#[tokio::test]
async fn exact_overrides_commit_with_decision_and_survive_reopen_while_expansion_fails() {
    use fictor::installer::overrides::Overrides;
    let (root, store) = store().await;
    let p = store.begin_attempt(input()).await.unwrap();
    let mut identity = identifying();
    identity.identity.as_mut().unwrap().manifest["runtime"] =
        json!({"kind":"node","entry":"index.mjs"});
    identity.identity.as_mut().unwrap().manifest["scope"] = json!("session");
    identity.identity.as_mut().unwrap().manifest["mcp"] = json!(false);
    identity.identity.as_mut().unwrap().manifest["kernel"] = json!(["kv"]);
    identity.identity.as_mut().unwrap().manifest["permissions"] =
        json!({"env":{"APP_LABEL":"fake-only"}});
    store
        .transition_proposal(p.id.clone(), State::Received, State::Checking, identity)
        .await
        .unwrap();
    store
        .transition_proposal(p.id.clone(), State::Checking, State::Checked, checked())
        .await
        .unwrap();
    let original_nonce = store
        .proposal_nonce(p.id.clone())
        .await
        .unwrap()
        .as_str()
        .to_owned();
    let head = store.session("sys".into()).await.unwrap().head_id;
    for patch in [
        json!({"permissions":{"env":{"NEW":"forbidden"}}}),
        json!({"tools":{"missing":{}}}),
    ] {
        let nonce = store.proposal_nonce(p.id.clone()).await.unwrap();
        assert!(
            store
                .transition_proposal(
                    p.id.clone(),
                    State::Checked,
                    State::Approved,
                    ProposalUpdate {
                        decision: Some(HumanDecision::User(nonce)),
                        review_base: Some(base()),
                        overrides: Some(Overrides::from_value(patch).unwrap()),
                        ..Default::default()
                    }
                )
                .await
                .is_err()
        );
        assert_eq!(
            store.proposal(p.id.clone()).await.unwrap().state,
            State::Checked
        );
        assert_eq!(
            store.proposal_nonce(p.id.clone()).await.unwrap().as_str(),
            original_nonce
        );
        assert_eq!(store.session("sys".into()).await.unwrap().head_id, head);
    }
    let exact = json!({"permissions":{"env":{}},"tools":{"default":{"model_visible":false}}});
    let nonce = store.proposal_nonce(p.id.clone()).await.unwrap();
    let approved = store
        .transition_proposal(
            p.id.clone(),
            State::Checked,
            State::Approved,
            ProposalUpdate {
                decision: Some(HumanDecision::User(nonce)),
                review_base: Some(base()),
                overrides: Some(Overrides::from_value(exact.clone()).unwrap()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(approved.overrides.as_value(), &exact);
    assert!(
        store
            .transition_proposal(
                p.id.clone(),
                State::Approved,
                State::Promoted,
                ProposalUpdate {
                    overrides: Some(Overrides::default()),
                    ..Default::default()
                }
            )
            .await
            .is_err()
    );
    Arc::try_unwrap(store)
        .ok()
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    let reopened = Store::open(root.path()).await.unwrap();
    let persisted = reopened.proposal(p.id).await.unwrap();
    assert_eq!(persisted.overrides.as_value(), &exact);
    assert_eq!(persisted.review_base_hash, Some(base().hash));
    reopened.shutdown().await.unwrap();
}

#[tokio::test]
async fn approval_audit_failure_rolls_back_patch_decision_and_nonce_together() {
    let (_root, store) = store().await;
    let id = ready(&store).await;
    let old_nonce = store
        .proposal_nonce(id.clone())
        .await
        .unwrap()
        .as_str()
        .to_owned();
    let head = store.session("sys".into()).await.unwrap().head_id;
    store.write(|db| { db.execute_batch("CREATE TRIGGER refuse_approval BEFORE INSERT ON events WHEN NEW.kind='ext.approved' BEGIN SELECT RAISE(ABORT,'fixture'); END;")?;Ok(()) }).await.unwrap();
    let nonce = store.proposal_nonce(id.clone()).await.unwrap();
    assert!(
        store
            .transition_proposal(
                id.clone(),
                State::Checked,
                State::Approved,
                ProposalUpdate {
                    decision: Some(HumanDecision::User(nonce)),
                    review_base: Some(base()),
                    overrides: Some(
                        fictor::installer::overrides::Overrides::parse("{\"permissions\":{}}")
                            .unwrap()
                    ),
                    ..Default::default()
                }
            )
            .await
            .is_err()
    );
    let current = store.proposal(id.clone()).await.unwrap();
    assert_eq!(current.state, State::Checked);
    assert!(current.decided_by.is_none());
    assert_eq!(
        current.overrides,
        fictor::installer::overrides::Overrides::default()
    );
    assert_eq!(store.proposal_nonce(id).await.unwrap().as_str(), old_nonce);
    assert_eq!(store.session("sys".into()).await.unwrap().head_id, head);
}

#[tokio::test]
async fn local_receive_persists_and_never_serializes_or_audits_nonce() {
    let (_root, store) = store().await;
    let p = store.begin_attempt(input()).await.unwrap();
    assert_eq!(p.state, State::Received);
    assert!(!p.tainted);
    assert!(p.hash.is_none());
    assert!(p.checks.is_none());
    assert!(p.ext_id.is_none() && p.version.is_none());
    assert!(p.manifest.is_none() && p.update_of.is_none());
    assert!(p.packages.is_none() && p.audit_blob.is_none());
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
    assert_eq!(event.payload["ext_id"], json!(null));
    assert_eq!(event.payload["version"], json!(null));
    assert_eq!(event.payload["from"], json!(null));
    assert_eq!(event.payload["state"], "received");
    assert!(event.payload.get("reason").is_none());
    let json = serde_json::to_value(&p).unwrap();
    assert_eq!(json["ext_id"], json!(null));
    assert_eq!(json["version"], json!(null));
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
async fn rejects_non_local_and_inconsistent_identity_and_preserves_taint_metadata() {
    let (_root, store) = store().await;
    let mut p = input();
    p.source = json!({"kind":"ai"});
    assert!(store.begin_attempt(p).await.is_err());
    let mut p = input();
    p.tainted = true;
    let received = store.begin_attempt(p).await.unwrap();
    assert!(received.tainted);
    let mut update = identifying();
    update.identity.as_mut().unwrap().manifest["id"] = json!("other");
    assert!(
        store
            .transition_proposal(
                received.id.clone(),
                State::Received,
                State::Checking,
                update
            )
            .await
            .is_err()
    );
    let mut update = identifying();
    update.identity.as_mut().unwrap().ext_id = "../sample".into();
    assert!(
        store
            .transition_proposal(
                received.id.clone(),
                State::Received,
                State::Checking,
                update
            )
            .await
            .is_err()
    );
    let mut update = identifying();
    update.identity.as_mut().unwrap().manifest["version"] = json!("2.0.0");
    assert!(
        store
            .transition_proposal(
                received.id.clone(),
                State::Received,
                State::Checking,
                update
            )
            .await
            .is_err()
    );
    assert!(
        store
            .transition_proposal(
                received.id,
                State::Received,
                State::Checking,
                ProposalUpdate::default()
            )
            .await
            .is_err()
    );
}
#[tokio::test]
async fn compare_and_swap_has_one_winner_and_one_audit_event() {
    let (_root, store) = store().await;
    let p = store.begin_attempt(input()).await.unwrap();
    let (a, b) = tokio::join!(
        store.transition_proposal(
            p.id.clone(),
            State::Received,
            State::Checking,
            identifying()
        ),
        store.transition_proposal(
            p.id.clone(),
            State::Received,
            State::Checking,
            identifying()
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
    let p = store.begin_attempt(input()).await.unwrap();
    store
        .transition_proposal(
            p.id.clone(),
            State::Received,
            State::Checking,
            identifying(),
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
    let events = store
        .event_path("sys".into(), None, None)
        .await
        .unwrap()
        .events;
    let failure = events.last().unwrap();
    assert_eq!(failure.payload["reason"], "check:failed");
    assert_eq!(failure.payload["ext_id"], "sample");
    assert_eq!(failure.payload["version"], "0.1.0");
    assert_eq!(failure.payload["from"], "checking");
    assert!(!failure.payload.to_string().contains("unavailable"));
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
    let other = store.begin_attempt(input()).await.unwrap();
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
                    review_base: Some(base()),
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
                review_base: Some(base()),
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
                    review_base: Some(base()),
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
    let p = store.begin_attempt(input()).await.unwrap();
    assert_eq!(
        store
            .transition_proposal(
                p.id,
                State::Received,
                State::Failed,
                receipt_failure("receipt:io")
            )
            .await
            .unwrap()
            .state,
        State::Failed
    );
}

#[tokio::test]
async fn receipt_failure_persists_checks_without_accepting_success_results() {
    let (_root, store) = store().await;
    let proposal = store.begin_attempt(input()).await.unwrap();
    let failure = ProposalCheck {
        name: "receipt".into(),
        passed: false,
        blocking: true,
        detail: Some("receipt:io".into()),
    };
    for update in [
        ProposalUpdate {
            hash: Some(format!("sha256:{}", "1".repeat(64))),
            ..Default::default()
        },
        ProposalUpdate {
            packages: Some(vec![]),
            ..Default::default()
        },
        receipt_failure("/private/path/must-not-be-a-reason"),
        ProposalUpdate::default(),
    ] {
        assert!(
            store
                .transition_proposal(proposal.id.clone(), State::Received, State::Failed, update)
                .await
                .is_err()
        );
        assert_eq!(
            store.proposal(proposal.id.clone()).await.unwrap().state,
            State::Received
        );
    }
    let failed = store
        .transition_proposal(
            proposal.id.clone(),
            State::Received,
            State::Failed,
            ProposalUpdate {
                checks: Some(vec![failure.clone()]),
                failure_reason: Some("receipt:io".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(failed.checks, Some(vec![failure.clone()]));
    assert_eq!(
        store.proposal(proposal.id).await.unwrap().checks,
        Some(vec![failure])
    );
    let events = store
        .event_path("sys".into(), None, None)
        .await
        .unwrap()
        .events;
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind == "ext.failed")
            .count(),
        1
    );
    let event = events.last().unwrap();
    assert_eq!(event.payload["reason"], "receipt:io");
    assert_eq!(event.payload["ext_id"], json!(null));
    assert_eq!(event.payload["version"], json!(null));
    assert!(!event.payload.to_string().contains("/private"));
}
#[tokio::test]
async fn audit_failure_rolls_back_both_receive_and_transition() {
    let (_root, store) = store().await;
    store.write(|db|{db.execute_batch("CREATE TRIGGER reject_proposal_audit BEFORE INSERT ON events WHEN NEW.kind='ext.proposed' BEGIN SELECT RAISE(ABORT,'fixture'); END;")?;Ok(())}).await.unwrap();
    assert!(store.begin_attempt(input()).await.is_err());
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
    let p = store.begin_attempt(input()).await.unwrap();
    let head = store.session("sys".into()).await.unwrap().head_id;
    store.write(|db|{db.execute_batch("CREATE TRIGGER reject_transition_audit BEFORE INSERT ON events WHEN NEW.kind='ext.checking' BEGIN SELECT RAISE(ABORT,'fixture'); END;")?;Ok(())}).await.unwrap();
    assert!(
        store
            .transition_proposal(
                p.id.clone(),
                State::Received,
                State::Checking,
                identifying()
            )
            .await
            .is_err()
    );
    let unchanged = store.proposal(p.id).await.unwrap();
    assert_eq!(unchanged.state, State::Received);
    assert!(unchanged.ext_id.is_none() && unchanged.version.is_none());
    assert!(unchanged.manifest.is_none() && unchanged.update_of.is_none());
    assert_eq!(store.session("sys".into()).await.unwrap().head_id, head);
    store.write(|db| {
        db.execute_batch("CREATE TRIGGER reject_failure_audit BEFORE INSERT ON events WHEN NEW.kind='ext.failed' BEGIN SELECT RAISE(ABORT,'fixture'); END;")?;
        Ok(())
    }).await.unwrap();
    assert!(
        store
            .transition_proposal(
                unchanged.id.clone(),
                State::Received,
                State::Failed,
                receipt_failure("receipt:invalid_path")
            )
            .await
            .is_err()
    );
    let unchanged = store.proposal(unchanged.id).await.unwrap();
    assert_eq!(unchanged.state, State::Received);
    assert!(unchanged.checks.is_none());
    assert_eq!(store.session("sys".into()).await.unwrap().head_id, head);
}
#[tokio::test]
async fn proposals_survive_reopen_with_nonce_and_checked_results() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
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
    assert_eq!(p.checks.unwrap().len(), 5);
    assert!(reopened.proposal_nonce(id).await.unwrap().as_str() == nonce);
    reopened.shutdown().await.unwrap();
}

#[tokio::test]
async fn binding_revalidates_manifest_and_identity_is_written_once_with_checking() {
    let (_root, store) = store().await;
    let proposal = store.begin_attempt(input()).await.unwrap();
    let head = store.session("sys".into()).await.unwrap().head_id;
    for manifest in [
        json!({"id":"sample","version":"0.1.0"}),
        json!({"schema":1,"id":"sample","version":"not-semver","description":"x","runtime":{"kind":"none"}}),
        json!({"schema":1,"id":"sample","version":"0.1.0","description":"x","runtime":{"kind":"node","entry":"../escape.mjs"}}),
        json!({"schema":1,"id":"sample","version":"0.1.0","description":"x","runtime":{"kind":"node","entry":"x.mjs"},"permissions":{"env":{"NODE_OPTIONS":"private-untrusted-content"}}}),
        json!({"schema":1,"id":"sample","version":"0.1.0","description":"x","role":"harness","runtime":{"kind":"node","entry":"x.mjs"},"scope":"session","mcp":false,"kernel":["tools"],"permissions":{"fs":{"read":["${workspace}"]}}}),
    ] {
        let mut update = identifying();
        update.identity.as_mut().unwrap().manifest = manifest;
        assert!(
            store
                .transition_proposal(
                    proposal.id.clone(),
                    State::Received,
                    State::Checking,
                    update
                )
                .await
                .is_err()
        );
        let current = store.proposal(proposal.id.clone()).await.unwrap();
        assert_eq!(current.state, State::Received);
        assert!(current.ext_id.is_none() && current.version.is_none());
        assert!(current.manifest.is_none());
        assert_eq!(store.session("sys".into()).await.unwrap().head_id, head);
    }
    let mut update = identifying();
    update.identity.as_mut().unwrap().update_of = Some("0.0.1-0123456789ab".into());
    let bound = store
        .transition_proposal(
            proposal.id.clone(),
            State::Received,
            State::Checking,
            update,
        )
        .await
        .unwrap();
    assert_eq!(bound.ext_id.as_deref(), Some("sample"));
    assert_eq!(bound.version.as_deref(), Some("0.1.0"));
    assert_eq!(bound.update_of.as_deref(), Some("0.0.1-0123456789ab"));
    assert!(bound.manifest.is_some());
    let event = store
        .event_path("sys".into(), None, None)
        .await
        .unwrap()
        .events
        .pop()
        .unwrap();
    assert_eq!(event.kind, "ext.checking");
    assert_eq!(event.payload["ext_id"], "sample");
    assert_eq!(event.payload["version"], "0.1.0");
    assert_eq!(event.payload["from"], "received");
    assert_eq!(event.payload["state"], "checking");
    let mut replacement = checked();
    replacement.identity = identifying().identity;
    assert!(
        store
            .transition_proposal(proposal.id, State::Checking, State::Checked, replacement)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn legacy_identified_received_preserves_identity_and_refuses_replacement() {
    let (_root, store) = store().await;
    let proposal = store.begin_attempt(input()).await.unwrap();
    let identity = identifying().identity.unwrap();
    let id = proposal.id.clone();
    store.write(move |db| {
        db.execute("UPDATE proposals SET ext_id=?1,version=?2,manifest=?3,update_of='legacy-active' WHERE id=?4",
            rusqlite::params![identity.ext_id, identity.version, identity.manifest.to_string(), id])?;
        Ok(())
    }).await.unwrap();
    assert!(
        store
            .transition_proposal(
                proposal.id.clone(),
                State::Received,
                State::Checking,
                identifying()
            )
            .await
            .is_err()
    );
    let bound = store
        .transition_proposal(
            proposal.id,
            State::Received,
            State::Checking,
            ProposalUpdate::default(),
        )
        .await
        .unwrap();
    assert_eq!(bound.ext_id.as_deref(), Some("sample"));
    assert_eq!(bound.version.as_deref(), Some("0.1.0"));
    assert_eq!(bound.update_of.as_deref(), Some("legacy-active"));
}

#[tokio::test]
async fn recovery_preserves_checks_identity_and_terminal_states_and_is_idempotent() {
    let (_root, store) = store().await;
    let received = store.begin_attempt(input()).await.unwrap();
    let checking = store.begin_attempt(input()).await.unwrap();
    let preserved = checked().checks.unwrap();
    let mut binding = identifying();
    binding.checks = Some(preserved.clone());
    store
        .transition_proposal(
            checking.id.clone(),
            State::Received,
            State::Checking,
            binding,
        )
        .await
        .unwrap();
    let checked_id = ready(&store).await;
    let approved_id = ready(&store).await;
    let nonce = store.proposal_nonce(approved_id.clone()).await.unwrap();
    store
        .transition_proposal(
            approved_id.clone(),
            State::Checked,
            State::Approved,
            ProposalUpdate {
                decision: Some(HumanDecision::User(nonce)),
                review_base: Some(base()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let old_failed = store.begin_attempt(input()).await.unwrap();
    store
        .transition_proposal(
            old_failed.id.clone(),
            State::Received,
            State::Failed,
            receipt_failure("receipt:io"),
        )
        .await
        .unwrap();
    let nonce = store
        .proposal_nonce(received.id.clone())
        .await
        .unwrap()
        .as_str()
        .to_owned();
    let failures = store.recover_interrupted_proposals().await.unwrap();
    assert_eq!(failures.len(), 3);
    let failed_received = failures.iter().find(|p| p.id == received.id).unwrap();
    assert!(failed_received.ext_id.is_none() && failed_received.version.is_none());
    assert_eq!(
        failed_received.checks.as_ref().unwrap()[0]
            .detail
            .as_deref(),
        Some("recovery:interrupted")
    );
    let failed_checking = failures.iter().find(|p| p.id == checking.id).unwrap();
    assert_eq!(failed_checking.ext_id.as_deref(), Some("sample"));
    let checks = failed_checking.checks.as_ref().unwrap();
    assert!(checks.starts_with(&preserved));
    assert_eq!(checks.len(), preserved.len() + 1);
    assert_eq!(
        checks.last().unwrap().detail.as_deref(),
        Some("recovery:interrupted")
    );
    assert_eq!(
        store.proposal(checked_id).await.unwrap().state,
        State::Checked
    );
    assert_eq!(
        store.proposal(approved_id).await.unwrap().state,
        State::Approved
    );
    assert_eq!(
        store.proposal_nonce(received.id).await.unwrap().as_str(),
        nonce
    );
    let head = store.session("sys".into()).await.unwrap().head_id;
    let before = serde_json::to_value(failures).unwrap();
    let after = store.recover_interrupted_proposals().await.unwrap();
    assert_eq!(serde_json::to_value(after).unwrap(), before);
    assert_eq!(store.session("sys".into()).await.unwrap().head_id, head);
    let events = store
        .event_path("sys".into(), None, None)
        .await
        .unwrap()
        .events;
    assert_eq!(
        events
            .iter()
            .filter(|event| event.payload["reason"] == "recovery:interrupted")
            .count(),
        2
    );
}

#[tokio::test]
async fn recovery_audit_failure_rolls_back_the_entire_batch() {
    let (_root, store) = store().await;
    let first = store.begin_attempt(input()).await.unwrap();
    let second = store.begin_attempt(input()).await.unwrap();
    let id = second.id.clone();
    store.write(move |db| {
        db.execute_batch(&format!("CREATE TRIGGER fail_second_recovery BEFORE INSERT ON events WHEN NEW.kind='ext.failed' AND json_extract(NEW.payload,'$.proposal_id')='{id}' BEGIN SELECT RAISE(ABORT,'fixture'); END;"))?;
        Ok(())
    }).await.unwrap();
    let head = store.session("sys".into()).await.unwrap().head_id;
    assert!(store.recover_interrupted_proposals().await.is_err());
    assert_eq!(
        store.proposal(first.id).await.unwrap().state,
        State::Received
    );
    assert_eq!(
        store.proposal(second.id).await.unwrap().state,
        State::Received
    );
    assert_eq!(store.session("sys".into()).await.unwrap().head_id, head);
}
