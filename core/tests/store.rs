use fictor::{
    config::Mode,
    store::{
        AppendEvent, EventQuery, Flags, NewSession, Provenance, Sensitivity, Store, StoreError,
        Trust,
    },
};
use serde_json::json;
use tempfile::{TempDir, tempdir};

async fn fixture() -> (TempDir, Store, String) {
    let root = tempdir().unwrap();
    let home = root.path().join("data");
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    fictor::initialize(&home).await.unwrap();
    let store = Store::open(&home).await.unwrap();
    let session = store
        .create_session(NewSession {
            title: "test".into(),
            workspace,
            workspace_trust: Trust::Trusted,
            harness: "harness".into(),
            mode: Mode::Default,
            model: None,
        })
        .await
        .unwrap();
    (root, store, session.id)
}

fn input(session: &str, text: &str, trust: Trust, sensitivity: Sensitivity) -> AppendEvent {
    AppendEvent {
        session_id: session.into(),
        parent_id: None,
        kind: "tool.result".into(),
        actor: "core".into(),
        payload: json!({"content": [{"type":"text","text":text}]}),
        blob_refs: vec![],
        provenance: Provenance {
            trust,
            sensitivity,
            source: "tool:test__read".into(),
        },
    }
}

#[tokio::test]
async fn flags_accumulate_and_taint_is_recorded_once_atomically() {
    let (_root, store, id) = fixture().await;
    let private = store
        .append(input(&id, "private", Trust::Trusted, Sensitivity::Private))
        .await
        .unwrap();
    assert_eq!(
        private.flags,
        Flags {
            untrusted: false,
            private: true
        }
    );
    store
        .append(input(
            &id,
            "external",
            Trust::Untrusted,
            Sensitivity::Public,
        ))
        .await
        .unwrap();
    store
        .append(input(&id, "clean", Trust::Trusted, Sensitivity::Public))
        .await
        .unwrap();
    let path = store.event_path(id.clone(), None, None).await.unwrap();
    let taints: Vec<_> = path
        .events
        .iter()
        .filter(|e| e.kind == "session.tainted")
        .collect();
    assert_eq!(taints.len(), 2);
    assert_eq!(taints[0].payload["flag"], "P");
    assert_eq!(taints[0].payload["source_event_id"], private.id);
    assert_eq!(taints[1].payload["flag"], "U");
    assert_eq!(
        store.session(id).await.unwrap().flags,
        Flags {
            untrusted: true,
            private: true
        }
    );
    for pair in path.events.windows(2) {
        assert_eq!(pair[1].parent_id.as_deref(), Some(pair[0].id.as_str()));
        assert!(pair[0].id < pair[1].id);
    }
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn stale_parent_fails_without_changing_head_or_history() {
    let (_root, store, id) = fixture().await;
    let old_head = store.session(id.clone()).await.unwrap().head_id;
    let event = store
        .append(input(&id, "first", Trust::Trusted, Sensitivity::Public))
        .await
        .unwrap();
    let mut stale = input(&id, "bad", Trust::Untrusted, Sensitivity::Private);
    stale.parent_id = old_head;
    assert!(matches!(
        store.append(stale).await,
        Err(StoreError::HeadMoved)
    ));
    assert_eq!(
        store.session(id.clone()).await.unwrap().head_id,
        Some(event.id)
    );
    assert_eq!(
        store.event_path(id, None, None).await.unwrap().events.len(),
        2
    );
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn fork_traverses_ancestors_and_inherits_only_flags_at_fork() {
    let (_root, store, id) = fixture().await;
    let clean = store
        .append(input(&id, "before", Trust::Trusted, Sensitivity::Public))
        .await
        .unwrap();
    store
        .append(input(&id, "after", Trust::Untrusted, Sensitivity::Private))
        .await
        .unwrap();
    let original_head = store.session(id.clone()).await.unwrap().head_id;
    let fork = store
        .fork_session(clean.id.clone(), Some("branch".into()))
        .await
        .unwrap();
    assert_eq!(fork.flags, Flags::default());
    assert_eq!(fork.parent_session_id.as_deref(), Some(id.as_str()));
    assert_eq!(fork.fork_event_id.as_deref(), Some(clean.id.as_str()));
    assert_eq!(store.session(id).await.unwrap().head_id, original_head);
    let path = store.event_path(fork.id.clone(), None, None).await.unwrap();
    assert_eq!(path.events.len(), 3);
    assert_eq!(path.events[1].id, clean.id);
    assert_eq!(path.events[2].kind, "session.forked");
    store
        .append(input(
            &fork.id,
            "branch text",
            Trust::Trusted,
            Sensitivity::Public,
        ))
        .await
        .unwrap();
    let matches = store
        .query_events(EventQuery {
            session_id: Some(fork.id.clone()),
            text: Some("after".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(matches.is_empty());
    let inherited = store
        .query_events(EventQuery {
            session_id: Some(fork.id.clone()),
            text: Some("before".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(inherited.len(), 1);
    let nested = store
        .fork_session(path.events[2].id.clone(), None)
        .await
        .unwrap();
    assert_eq!(
        store
            .event_path(nested.id, None, None)
            .await
            .unwrap()
            .events
            .len(),
        4
    );
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn history_pagination_returns_most_recent_events_in_order() {
    let (_root, store, id) = fixture().await;
    let mut events = Vec::new();
    for i in 0..5 {
        events.push(
            store
                .append(input(
                    &id,
                    &format!("item {i}"),
                    Trust::Trusted,
                    Sensitivity::Public,
                ))
                .await
                .unwrap(),
        );
    }
    let page = store.event_path(id.clone(), None, Some(2)).await.unwrap();
    assert!(page.truncated);
    assert_eq!(page.events[0].id, events[3].id);
    let page = store
        .event_path(id.clone(), Some(events[2].id.clone()), Some(10))
        .await
        .unwrap();
    assert!(!page.truncated);
    assert_eq!(page.events.len(), 2);
    assert!(
        store
            .event_path(id, Some("not-in-lineage".into()), None)
            .await
            .is_err()
    );
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn large_payloads_spill_to_blobs_and_short_text_is_searchable() {
    let (_root, store, id) = fixture().await;
    let mut data = input(&id, "café unicode", Trust::Trusted, Sensitivity::Public);
    data.payload["padding"] = json!("x".repeat(65536));
    let original = data.payload.clone();
    let event = store.append(data).await.unwrap();
    let hash = event.payload["$blob"].as_str().unwrap().to_string();
    assert!(event.blob_refs.contains(&hash));
    let payload: serde_json::Value =
        serde_json::from_slice(&store.get_blob(hash).await.unwrap()).unwrap();
    assert_eq!(payload, original);
    let results = store
        .query_events(EventQuery {
            session_id: Some(id.clone()),
            text: Some("cafe".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(results[0].id, event.id);
    let too_long = store
        .append(input(
            &id,
            &"z".repeat(32769),
            Trust::Trusted,
            Sensitivity::Public,
        ))
        .await
        .unwrap();
    assert!(too_long.text.is_none());
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn blobs_are_deduplicated_and_hashes_cannot_escape_the_root() {
    let (root, store, _id) = fixture().await;
    let first = store.put_blob(b"hello".to_vec()).await.unwrap();
    let second = store.put_blob(b"hello".to_vec()).await.unwrap();
    assert_eq!(first, second);
    assert_eq!(store.get_blob(first.clone()).await.unwrap(), b"hello");
    for hash in ["../../config.toml", "sha256:../../outside", "sha256:ABCD"] {
        assert!(store.get_blob(hash.into()).await.is_err());
    }
    let hex = first.strip_prefix("sha256:").unwrap();
    let path = root
        .path()
        .join("data/blobs")
        .join(&hex[..2])
        .join(&hex[2..]);
    std::fs::write(path, b"changed").unwrap();
    assert!(store.get_blob(first).await.is_err());
    assert!(store.put_blob(b"hello".to_vec()).await.is_err());
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn kv_is_namespaced_bounded_and_uses_literal_prefixes() {
    let (_root, store, _id) = fixture().await;
    store
        .kv_set("one".into(), "a_%".into(), json!({"count":1}))
        .await
        .unwrap();
    store
        .kv_set("two".into(), "a_%".into(), json!(2))
        .await
        .unwrap();
    store
        .kv_set("one".into(), "abc".into(), json!(3))
        .await
        .unwrap();
    assert_eq!(
        store.kv_get("one".into(), "a_%".into()).await.unwrap(),
        Some(json!({"count":1}))
    );
    assert_eq!(
        store
            .kv_list("one".into(), "a_%".into(), 100)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        store
            .kv_set("one".into(), "large".into(), json!("x".repeat(1024 * 1024)))
            .await
            .is_err()
    );
    store.kv_delete("one".into(), "a_%".into()).await.unwrap();
    assert_eq!(
        store.kv_get("one".into(), "a_%".into()).await.unwrap(),
        None
    );
    assert_eq!(
        store.kv_get("two".into(), "a_%".into()).await.unwrap(),
        Some(json!(2))
    );
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn reopening_store_retains_context_and_cumulative_flags() {
    let (root, store, id) = fixture().await;
    store
        .append(input(&id, "state", Trust::Untrusted, Sensitivity::Private))
        .await
        .unwrap();
    store
        .kv_set("harness".into(), "cursor".into(), json!("saved"))
        .await
        .unwrap();
    let old_head = store.session(id.clone()).await.unwrap().head_id.unwrap();
    store.shutdown().await.unwrap();
    let reopened = Store::open(&root.path().join("data")).await.unwrap();
    assert_eq!(
        reopened.session(id.clone()).await.unwrap().flags,
        Flags {
            untrusted: true,
            private: true
        }
    );
    assert_eq!(
        reopened
            .kv_get("harness".into(), "cursor".into())
            .await
            .unwrap(),
        Some(json!("saved"))
    );
    let new = reopened
        .append(input(&id, "next", Trust::Trusted, Sensitivity::Public))
        .await
        .unwrap();
    assert_eq!(new.parent_id.as_deref(), Some(old_head.as_str()));
    assert!(new.id > old_head);
    assert_eq!(
        reopened
            .event_path(id, None, None)
            .await
            .unwrap()
            .events
            .len(),
        5
    );
    reopened.shutdown().await.unwrap();
}

#[tokio::test]
async fn concurrent_appends_are_linearized_and_cas_has_one_winner() {
    let (_root, store, id) = fixture().await;
    let head = store.session(id.clone()).await.unwrap().head_id;
    let mut left = input(&id, "left", Trust::Trusted, Sensitivity::Public);
    let mut right = input(&id, "right", Trust::Trusted, Sensitivity::Public);
    left.parent_id = head.clone();
    right.parent_id = head;
    let (left, right) = tokio::join!(store.append(left), store.append(right));
    assert!(left.is_ok() ^ right.is_ok());
    assert_eq!(
        store.event_path(id, None, None).await.unwrap().events.len(),
        2
    );
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn proxy_taint_is_atomic_idempotent_and_keeps_control_metadata_trusted() {
    let (_root, store, id) = fixture().await;
    store
        .append(input(&id, "private", Trust::Trusted, Sensitivity::Private))
        .await
        .unwrap();
    let flags = store
        .taint_from_network(id.clone(), "example.com".into())
        .await
        .unwrap();
    assert_eq!(
        flags,
        Flags {
            untrusted: true,
            private: true
        }
    );
    let head = store.session(id.clone()).await.unwrap().head_id.unwrap();
    let event = store.event(head.clone()).await.unwrap();
    assert_eq!(event.kind, "session.tainted");
    assert_eq!(event.trust, Trust::Trusted);
    assert_eq!(event.sensitivity, Sensitivity::Public);
    assert_eq!(event.payload["reason"], "net:example.com");
    store
        .taint_from_network(id.clone(), "another.example".into())
        .await
        .unwrap();
    assert_eq!(store.session(id).await.unwrap().head_id, Some(head));
    assert!(
        store
            .taint_from_network("sys".into(), "example.com".into())
            .await
            .is_err()
    );
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn unsafe_workspaces_are_rejected_and_canonical_paths_are_saved() {
    let (root, store, _id) = fixture().await;
    for workspace in [
        root.path().join("data"),
        root.path().join("data/extensions"),
        root.path().to_path_buf(),
        "/".into(),
        "relative".into(),
        root.path().join("missing"),
    ] {
        assert!(
            store
                .create_session(NewSession {
                    title: "bad".into(),
                    workspace,
                    workspace_trust: Trust::Untrusted,
                    harness: "harness".into(),
                    mode: Mode::Plan,
                    model: None,
                })
                .await
                .is_err()
        );
    }
    let session = store
        .create_session(NewSession {
            title: "ok".into(),
            workspace: root.path().join("workspace/../workspace"),
            workspace_trust: Trust::Untrusted,
            harness: "harness".into(),
            mode: Mode::Plan,
            model: None,
        })
        .await
        .unwrap();
    assert_eq!(
        session.workspace.as_deref(),
        root.path()
            .join("workspace")
            .canonicalize()
            .unwrap()
            .to_str()
    );
    assert!(!session.flags.untrusted);
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn corrupted_blob_reference_cannot_enter_the_event_log() {
    let dir = tempfile::tempdir().unwrap();
    fictor::initialize(dir.path()).await.unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let hash = store.put_blob(b"audited response".to_vec()).await.unwrap();
    let hex = hash.strip_prefix("sha256:").unwrap();
    std::fs::write(
        dir.path().join("blobs").join(&hex[..2]).join(&hex[2..]),
        b"tampered response",
    )
    .unwrap();
    let result = store
        .append(fictor::store::AppendEvent {
            session_id: "sys".into(),
            parent_id: None,
            kind: "model.call".into(),
            actor: "core".into(),
            payload: serde_json::json!({}),
            blob_refs: vec![hash],
            provenance: fictor::store::Provenance::core(),
        })
        .await;
    assert!(matches!(
        result,
        Err(fictor::store::StoreError::Blob(
            fictor::store::blobs::BlobError::Corrupt
        ))
    ));
    assert!(
        store
            .query_events(fictor::store::EventQuery {
                session_id: Some("sys".into()),
                kinds: vec!["model.call".into()],
                ..Default::default()
            })
            .await
            .unwrap()
            .is_empty()
    );
    store.shutdown().await.unwrap();
}
