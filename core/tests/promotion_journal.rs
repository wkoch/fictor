use fictor::{
    gateway::PinnedCatalog,
    installer::{
        lock::{Approval, Lock, LockedExtension, LockedVersion, approval_at_ms},
        overrides::Overrides,
    },
    store::{
        HumanDecision, NewPromotionIntent, NewProposal, PromotionAbortReason, PromotionState,
        Proposal, ProposalCheck, ProposalIdentity, ProposalState as State, ProposalUpdate,
        ReviewBase, Store, StoreError,
    },
};
use serde_json::{Value, json};

async fn setup() -> (tempfile::TempDir, Store) {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    fictor::initialize(&home).await.unwrap();
    let store = Store::open(&home).await.unwrap();
    (root, store)
}
fn base(lock: &Lock) -> ReviewBase {
    ReviewBase {
        update_of: lock.extensions.get("sample").map(|e| e.active.clone()),
        hash: lock.review_base_hash("sample").unwrap(),
    }
}
async fn approved(store: &Store, lock: &Lock, hash_byte: char, patch: Value) -> Proposal {
    let p = store
        .begin_attempt(NewProposal {
            source: json!({"kind":"local","path":"/private-source-fixture"}),
            tainted: false,
        })
        .await
        .unwrap();
    let manifest = json!({"schema":1,"id":"sample","version":"0.1.0","description":"journal fixture","scope":"session","runtime":{"kind":"node","entry":"index.mjs"},"mcp":false,"kernel":["kv"],"permissions":{"env":{"APP_LABEL":"private-fake-value"}}});
    store
        .transition_proposal(
            p.id.clone(),
            State::Received,
            State::Checking,
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
        detail: if name == "smoke" {
            Some(json!({"tools":catalog.tools(),"tools_hash":catalog.hash()}).to_string())
        } else {
            None
        },
    })
    .collect();
    store
        .transition_proposal(
            p.id.clone(),
            State::Checking,
            State::Checked,
            ProposalUpdate {
                hash: Some(format!("sha256:{}", hash_byte.to_string().repeat(64))),
                checks: Some(checks),
                packages: Some(vec![]),
                review_base: Some(base(lock)),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let nonce = store.proposal_nonce(p.id.clone()).await.unwrap();
    store
        .transition_proposal(
            p.id,
            State::Checked,
            State::Approved,
            ProposalUpdate {
                decision: Some(HumanDecision::User(nonce)),
                review_base: Some(base(lock)),
                overrides: Some(Overrides::from_value(patch).unwrap()),
                ..Default::default()
            },
        )
        .await
        .unwrap()
}
fn next(lock: &Lock, p: &Proposal) -> Lock {
    let mut next = lock.clone();
    let hash = p.hash.as_ref().unwrap();
    let key = format!("0.1.0-{}", &hash[7..19]);
    let catalog = PinnedCatalog::new(vec![]).unwrap();
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
    if let Some(extension) = next.extensions.get_mut("sample") {
        extension.active = key.clone();
        extension.versions.entry(key).or_insert(candidate);
    } else {
        next.extensions.insert(
            "sample".into(),
            LockedExtension {
                enabled: true,
                active: key.clone(),
                versions: [(key, candidate)].into(),
            },
        );
    }
    next
}
fn input(before: Option<String>, after: &Lock, p: &Proposal) -> NewPromotionIntent {
    NewPromotionIntent {
        proposal_id: p.id.clone(),
        before_lock: before,
        after_lock: after.encode_snapshot().unwrap(),
    }
}
async fn kinds(store: &Store) -> Vec<String> {
    store
        .event_path("sys".into(), None, None)
        .await
        .unwrap()
        .events
        .into_iter()
        .map(|event| event.kind)
        .collect()
}

#[tokio::test]
async fn exact_private_snapshots_and_prepared_event_commit_together_before_publication() {
    let (_root, store) = setup().await;
    let empty = Lock::default();
    let patch = json!({"permissions":{"env":{"APP_LABEL":"private-fake-value"}}});
    let p = approved(&store, &empty, 'a', patch).await;
    let after = next(&empty, &p);
    let before = format!(" \n{}\n", empty.encode_snapshot().unwrap());
    let expected_after = after.encode_snapshot().unwrap();
    let intent = store
        .prepare_promotion(input(Some(before.clone()), &after, &p))
        .await
        .unwrap();
    assert_eq!(intent.state, PromotionState::Prepared);
    assert_eq!(intent.before_lock, Some(before));
    assert_eq!(intent.after_lock, expected_after);
    assert_eq!(store.proposal(p.id).await.unwrap().state, State::Approved);
    assert_eq!(
        store
            .pending_promotion()
            .await
            .unwrap()
            .unwrap()
            .operation_id,
        intent.operation_id
    );
    let events = store
        .event_path("sys".into(), None, None)
        .await
        .unwrap()
        .events;
    let prepared = events.last().unwrap();
    assert_eq!(prepared.kind, "ext.promotion_prepared");
    assert_eq!(
        prepared.payload,
        json!({"operation_id":intent.operation_id,"proposal_id":intent.proposal_id,"ext_id":"sample","key":intent.key,"before_hash":intent.before_hash,"after_hash":intent.after_hash})
    );
    let encoded = serde_json::to_string(prepared).unwrap();
    for private in [
        "private-fake-value",
        "private-source-fixture",
        "before_lock",
        "after_lock",
    ] {
        assert!(!encoded.contains(private));
        assert!(!format!("{intent:?}").contains(private));
    }
}

#[tokio::test]
async fn commit_is_atomic_with_proposal_and_audit_and_retries_do_not_duplicate_events() {
    let (_root, store) = setup().await;
    let empty = Lock::default();
    let p = approved(&store, &empty, 'a', json!({})).await;
    let intent = store
        .prepare_promotion(input(None, &next(&empty, &p), &p))
        .await
        .unwrap();
    let head = store.session("sys".into()).await.unwrap().head_id;
    store.write(|db| {db.execute_batch("CREATE TRIGGER refuse_commit BEFORE INSERT ON events WHEN NEW.kind='ext.promoted' BEGIN SELECT RAISE(ABORT,'fixture'); END;")?;Ok(())}).await.unwrap();
    assert!(
        store
            .commit_promotion(intent.operation_id.clone())
            .await
            .is_err()
    );
    assert_eq!(
        store.proposal(p.id.clone()).await.unwrap().state,
        State::Approved
    );
    assert_eq!(
        store.pending_promotion().await.unwrap().unwrap().state,
        PromotionState::Prepared
    );
    assert_eq!(store.session("sys".into()).await.unwrap().head_id, head);
    store
        .write(|db| {
            db.execute_batch("DROP TRIGGER refuse_commit")?;
            Ok(())
        })
        .await
        .unwrap();
    let done = store
        .commit_promotion(intent.operation_id.clone())
        .await
        .unwrap();
    assert_eq!(done.state, PromotionState::Committed);
    assert_eq!(store.proposal(p.id).await.unwrap().state, State::Promoted);
    assert!(store.pending_promotion().await.unwrap().is_none());
    let retry = store.commit_promotion(intent.operation_id).await.unwrap();
    assert_eq!(retry.updated_at, done.updated_at);
    assert_eq!(
        kinds(&store)
            .await
            .iter()
            .filter(|kind| kind.as_str() == "ext.promoted")
            .count(),
        1
    );
}

#[tokio::test]
async fn abort_is_atomic_keeps_approval_and_explicit_retry_gets_a_new_operation() {
    let (_root, store) = setup().await;
    let empty = Lock::default();
    let p = approved(&store, &empty, 'a', json!({})).await;
    let after = next(&empty, &p);
    let first = store
        .prepare_promotion(input(None, &after, &p))
        .await
        .unwrap();
    store.write(|db|{db.execute_batch("CREATE TRIGGER refuse_abort BEFORE INSERT ON events WHEN NEW.kind='ext.promotion_aborted' BEGIN SELECT RAISE(ABORT,'fixture'); END;")?;Ok(())}).await.unwrap();
    assert!(
        store
            .abort_promotion(
                first.operation_id.clone(),
                PromotionAbortReason::Interrupted
            )
            .await
            .is_err()
    );
    assert_eq!(
        store
            .pending_promotion()
            .await
            .unwrap()
            .unwrap()
            .operation_id,
        first.operation_id
    );
    store
        .write(|db| {
            db.execute_batch("DROP TRIGGER refuse_abort")?;
            Ok(())
        })
        .await
        .unwrap();
    let aborted = store
        .abort_promotion(
            first.operation_id.clone(),
            PromotionAbortReason::Interrupted,
        )
        .await
        .unwrap();
    assert_eq!(aborted.state, PromotionState::Aborted);
    assert_eq!(
        store.proposal(p.id.clone()).await.unwrap().state,
        State::Approved
    );
    assert!(store.pending_promotion().await.unwrap().is_none());
    assert!(
        store
            .commit_promotion(first.operation_id.clone())
            .await
            .is_err()
    );
    let same = store
        .abort_promotion(first.operation_id.clone(), PromotionAbortReason::Io)
        .await
        .unwrap();
    assert_eq!(same.updated_at, aborted.updated_at);
    let second = store
        .prepare_promotion(input(None, &after, &p))
        .await
        .unwrap();
    assert_ne!(second.operation_id, first.operation_id);
    store.commit_promotion(second.operation_id).await.unwrap();
    // Historical aborted rows remain valid after a later attempt commits.
    assert_eq!(
        store
            .promotion_intent(first.operation_id)
            .await
            .unwrap()
            .state,
        PromotionState::Aborted
    );
    assert!(store.pending_promotion().await.unwrap().is_none());
    assert_eq!(
        kinds(&store)
            .await
            .iter()
            .filter(|kind| kind.as_str() == "ext.promotion_aborted")
            .count(),
        1
    );
}

#[tokio::test]
async fn one_pending_intent_and_audit_failure_cannot_leave_an_invisible_preparation() {
    let (_root, store) = setup().await;
    let empty = Lock::default();
    let p = approved(&store, &empty, 'a', json!({})).await;
    let after = next(&empty, &p);
    let head = store.session("sys".into()).await.unwrap().head_id;
    store.write(|db|{db.execute_batch("CREATE TRIGGER refuse_prepared BEFORE INSERT ON events WHEN NEW.kind='ext.promotion_prepared' BEGIN SELECT RAISE(ABORT,'fixture'); END;")?;Ok(())}).await.unwrap();
    assert!(
        store
            .prepare_promotion(input(None, &after, &p))
            .await
            .is_err()
    );
    assert!(store.pending_promotion().await.unwrap().is_none());
    assert_eq!(store.session("sys".into()).await.unwrap().head_id, head);
    store
        .write(|db| {
            db.execute_batch("DROP TRIGGER refuse_prepared")?;
            Ok(())
        })
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        store.prepare_promotion(input(None, &after, &p)),
        store.prepare_promotion(input(None, &after, &p))
    );
    assert_ne!(a.is_ok(), b.is_ok());
    assert_eq!(
        kinds(&store)
            .await
            .iter()
            .filter(|kind| kind.as_str() == "ext.promotion_prepared")
            .count(),
        1
    );
}

#[tokio::test]
async fn stale_base_and_changes_outside_the_candidate_are_refused_without_a_journal() {
    let (_root, store) = setup().await;
    let empty = Lock::default();
    let p = approved(&store, &empty, 'a', json!({})).await;
    let first_lock = next(&empty, &p);
    let first = store
        .prepare_promotion(input(None, &first_lock, &p))
        .await
        .unwrap();
    store.commit_promotion(first.operation_id).await.unwrap();
    let mut disabled = first_lock.clone();
    disabled.extensions.get_mut("sample").unwrap().enabled = false;
    let update = approved(&store, &disabled, 'b', json!({})).await;
    let valid_after = next(&disabled, &update);
    assert!(matches!(
        store
            .prepare_promotion(input(
                Some(first_lock.encode_snapshot().unwrap()),
                &valid_after,
                &update
            ))
            .await,
        Err(StoreError::Invalid("promotion:stale_base"))
    ));
    let mut enabling = valid_after.clone();
    enabling.extensions.get_mut("sample").unwrap().enabled = true;
    assert!(
        store
            .prepare_promotion(input(
                Some(disabled.encode_snapshot().unwrap()),
                &enabling,
                &update
            ))
            .await
            .is_err()
    );
    let mut losing_version = valid_after.clone();
    let old_key = disabled.extensions["sample"].active.clone();
    losing_version
        .extensions
        .get_mut("sample")
        .unwrap()
        .versions
        .remove(&old_key);
    assert!(
        store
            .prepare_promotion(input(
                Some(disabled.encode_snapshot().unwrap()),
                &losing_version,
                &update
            ))
            .await
            .is_err()
    );
    assert!(store.pending_promotion().await.unwrap().is_none());
    let prepared = store
        .prepare_promotion(input(
            Some(disabled.encode_snapshot().unwrap()),
            &valid_after,
            &update,
        ))
        .await
        .unwrap();
    assert!(
        !Lock::parse_snapshot(prepared.after_lock.as_bytes())
            .unwrap()
            .extensions["sample"]
            .enabled
    );
}

#[tokio::test]
async fn inactive_key_keeps_original_decision_and_refuses_a_different_override() {
    let (_root, store) = setup().await;
    let empty = Lock::default();
    let first = approved(&store, &empty, 'a', json!({})).await;
    let first_lock = next(&empty, &first);
    let operation = store
        .prepare_promotion(input(None, &first_lock, &first))
        .await
        .unwrap();
    store
        .commit_promotion(operation.operation_id)
        .await
        .unwrap();
    let second = approved(&store, &first_lock, 'b', json!({})).await;
    let second_lock = next(&first_lock, &second);
    let operation = store
        .prepare_promotion(input(
            Some(first_lock.encode_snapshot().unwrap()),
            &second_lock,
            &second,
        ))
        .await
        .unwrap();
    store
        .commit_promotion(operation.operation_id)
        .await
        .unwrap();
    let changed = approved(&store, &second_lock, 'a', json!({"permissions":{"env":{}}})).await;
    let after = next(&second_lock, &changed); // existing key intentionally unchanged
    assert!(matches!(
        store
            .prepare_promotion(input(
                Some(second_lock.encode_snapshot().unwrap()),
                &after,
                &changed
            ))
            .await,
        Err(StoreError::Invalid("promotion:key_conflict"))
    ));
    let same = approved(&store, &second_lock, 'a', json!({})).await;
    let after = next(&second_lock, &same);
    let operation = store
        .prepare_promotion(input(
            Some(second_lock.encode_snapshot().unwrap()),
            &after,
            &same,
        ))
        .await
        .unwrap();
    let active = &Lock::parse_snapshot(operation.after_lock.as_bytes())
        .unwrap()
        .extensions["sample"];
    assert_eq!(
        active.versions[&active.active].approved.at,
        approval_at_ms(first.updated_at).unwrap()
    );
}

#[tokio::test]
async fn corrupted_private_snapshots_or_terminal_history_never_look_like_an_empty_journal() {
    let (_root, store) = setup().await;
    let empty = Lock::default();
    let p = approved(&store, &empty, 'a', json!({})).await;
    let operation = store
        .prepare_promotion(input(None, &next(&empty, &p), &p))
        .await
        .unwrap();
    let id = operation.operation_id.clone();
    store
        .write(move |db| {
            db.execute(
                "UPDATE promotion_intents SET after_hash=?1 WHERE operation_id=?2",
                rusqlite::params![format!("sha256:{}", "0".repeat(64)), id],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(store.pending_promotion().await.is_err());
    assert!(
        store
            .commit_promotion(operation.operation_id.clone())
            .await
            .is_err()
    );
    let id = operation.operation_id.clone();
    let original = operation.after_hash.clone();
    store
        .write(move |db| {
            db.execute(
                "UPDATE promotion_intents SET after_hash=?1 WHERE operation_id=?2",
                rusqlite::params![original, id],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    store
        .abort_promotion(
            operation.operation_id.clone(),
            PromotionAbortReason::Integrity,
        )
        .await
        .unwrap();
    let id = operation.operation_id;
    // Even a terminal intent must remain consistent with its immutable audit.
    store
        .write(move |db| {
            db.execute(
                "UPDATE promotion_intents SET updated_at=updated_at+1 WHERE operation_id=?1",
                [id],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(store.pending_promotion().await.is_err());
}

#[tokio::test]
async fn legacy_approved_without_a_review_base_is_stale_before_old_smoke_is_replayed() {
    let (_root, store) = setup().await;
    let empty = Lock::default();
    let p = approved(&store, &empty, 'a', json!({})).await;
    let after = next(&empty, &p);
    let id = p.id.clone();
    store
        .write(move |db| {
            db.execute(
                "UPDATE proposals SET review_base_hash=NULL,checks='[]' WHERE id=?1",
                [id],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let head = store.session("sys".into()).await.unwrap().head_id;
    assert!(matches!(
        store.prepare_promotion(input(None, &after, &p)).await,
        Err(StoreError::Invalid("promotion:stale_base"))
    ));
    assert_eq!(store.proposal(p.id).await.unwrap().state, State::Approved);
    assert!(store.pending_promotion().await.unwrap().is_none());
    assert_eq!(store.session("sys".into()).await.unwrap().head_id, head);
}
