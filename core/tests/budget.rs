//! Durable, transactional admission budgets from ADR-017.
use fictor::{
    config::Mode,
    store::{BudgetExceeded, EventQuery, NewSession, Store, StoreError, Trust, local_day},
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Barrier;

type Snapshot = BTreeMap<(String, String), i64>;

struct Fixture {
    _root: tempfile::TempDir,
    home: PathBuf,
    workspace: PathBuf,
    store: Arc<Store>,
}
impl Fixture {
    async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("data");
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        fictor::initialize(&home).await.unwrap();
        let store = Arc::new(Store::open(&home).await.unwrap());
        Self {
            _root: root,
            home,
            workspace,
            store,
        }
    }
    async fn session(&self, title: &str) -> String {
        self.store
            .create_session(NewSession {
                title: title.into(),
                workspace: self.workspace.clone(),
                workspace_trust: Trust::Trusted,
                harness: "harness".into(),
                mode: Mode::Default,
                model: None,
            })
            .await
            .unwrap()
            .id
    }
    fn snapshot(&self) -> Snapshot {
        snapshot(&self.home)
    }
}
fn snapshot(home: &Path) -> Snapshot {
    let connection =
        Connection::open_with_flags(home.join("fictor.db"), OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let mut query = connection
        .prepare("SELECT scope,key,count FROM budget_usage ORDER BY scope,key")
        .unwrap();
    query
        .query_map([], |row| Ok(((row.get(0)?, row.get(1)?), row.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}
fn daily_total(snapshot: &Snapshot) -> i64 {
    snapshot
        .iter()
        .filter(|((scope, _), _)| scope == "day")
        .map(|(_, count)| count)
        .sum()
}
fn session_count(snapshot: &Snapshot, session: &str) -> Option<i64> {
    snapshot.get(&("session".into(), session.into())).copied()
}
async fn shutdown(store: Arc<Store>) {
    let store = match Arc::try_unwrap(store) {
        Ok(store) => store,
        Err(_) => panic!("test left outstanding Store owners"),
    };
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn concurrent_admissions_cannot_overspend_the_shared_day_budget() {
    let fixture = Fixture::new().await;
    let sessions = [fixture.session("one").await, fixture.session("two").await];
    let barrier = Arc::new(Barrier::new(32));
    let before = local_day().unwrap();
    let mut tasks = Vec::new();
    for index in 0..32 {
        let store = fixture.store.clone();
        let barrier = barrier.clone();
        let session = sessions[index % 2].clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .reserve_model_budget(Some(session), 7, 100)
                .await
                .unwrap()
        }));
    }
    let mut admitted = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(()) => admitted += 1,
            Err(exceeded) => assert_eq!(
                exceeded,
                BudgetExceeded {
                    scope: "day",
                    limit: 7
                }
            ),
        }
    }
    let after = local_day().unwrap();
    let counters = fixture.snapshot();
    assert_eq!(daily_total(&counters), admitted);
    assert_eq!(
        sessions
            .iter()
            .filter_map(|session| session_count(&counters, session))
            .sum::<i64>(),
        admitted
    );
    assert!(
        counters
            .iter()
            .filter(|((scope, _), _)| scope == "day")
            .all(|(_, count)| *count <= 7)
    );
    if before == after {
        assert_eq!(admitted, 7);
    } else {
        assert!((7..=14).contains(&admitted));
    }
}

#[tokio::test]
async fn concurrent_admissions_cannot_overspend_a_session_budget() {
    let fixture = Fixture::new().await;
    let session = fixture.session("limited").await;
    let barrier = Arc::new(Barrier::new(32));
    let mut tasks = Vec::new();
    for _ in 0..32 {
        let store = fixture.store.clone();
        let barrier = barrier.clone();
        let session = session.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .reserve_model_budget(Some(session), 100, 5)
                .await
                .unwrap()
        }));
    }
    let mut admitted = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(()) => admitted += 1,
            Err(exceeded) => assert_eq!(
                exceeded,
                BudgetExceeded {
                    scope: "session",
                    limit: 5
                }
            ),
        }
    }
    assert_eq!(admitted, 5);
    let counters = fixture.snapshot();
    assert_eq!(daily_total(&counters), 5);
    assert_eq!(session_count(&counters, &session), Some(5));
}

#[tokio::test]
async fn either_exhausted_scope_rolls_back_the_whole_admission() {
    let fixture = Fixture::new().await;
    let first = fixture.session("first").await;
    let second = fixture.session("second").await;
    let third = fixture.session("third").await;
    fixture
        .store
        .reserve_model_budget(Some(first.clone()), 2, 1)
        .await
        .unwrap()
        .unwrap();
    let before = fixture.snapshot();
    assert_eq!(
        fixture
            .store
            .reserve_model_budget(Some(first.clone()), 2, 1)
            .await
            .unwrap(),
        Err(BudgetExceeded {
            scope: "session",
            limit: 1
        })
    );
    assert_eq!(
        fixture.snapshot(),
        before,
        "session refusal consumed day budget"
    );
    fixture
        .store
        .reserve_model_budget(Some(second.clone()), 2, 1)
        .await
        .unwrap()
        .unwrap();
    let before = fixture.snapshot();
    assert_eq!(
        fixture
            .store
            .reserve_model_budget(Some(third.clone()), 0, 1)
            .await
            .unwrap(),
        Err(BudgetExceeded {
            scope: "day",
            limit: 0
        })
    );
    assert_eq!(
        fixture.snapshot(),
        before,
        "day refusal consumed session budget"
    );
    assert_eq!(session_count(&before, &first), Some(1));
    assert_eq!(session_count(&before, &second), Some(1));
    assert_eq!(session_count(&before, &third), None);
    assert_eq!(daily_total(&before), 2);
    // A zero session limit must also reject without inserting/incrementing day usage.
    assert_eq!(
        fixture
            .store
            .reserve_model_budget(Some(third), 100, 0)
            .await
            .unwrap(),
        Err(BudgetExceeded {
            scope: "session",
            limit: 0
        })
    );
    assert_eq!(fixture.snapshot(), before);
}

#[tokio::test]
async fn admitted_usage_survives_store_shutdown_and_reopen() {
    let fixture = Fixture::new().await;
    let session = fixture.session("persistent").await;
    for _ in 0..2 {
        fixture
            .store
            .reserve_model_budget(Some(session.clone()), 10, 2)
            .await
            .unwrap()
            .unwrap();
    }
    let before = fixture.snapshot();
    let Fixture {
        _root,
        home,
        workspace: _,
        store,
    } = fixture;
    shutdown(store).await;
    let reopened = Arc::new(Store::open(&home).await.unwrap());
    assert_eq!(snapshot(&home), before);
    assert_eq!(
        reopened
            .reserve_model_budget(Some(session), 10, 2)
            .await
            .unwrap(),
        Err(BudgetExceeded {
            scope: "session",
            limit: 2
        })
    );
    let current_count = before
        .get(&("day".into(), local_day().unwrap()))
        .copied()
        .unwrap_or(0) as u64;
    assert_eq!(
        reopened
            .reserve_model_budget(None, current_count, 0)
            .await
            .unwrap(),
        Err(BudgetExceeded {
            scope: "day",
            limit: current_count
        })
    );
    assert_eq!(
        snapshot(&home),
        before,
        "reopening refunded durable admission counters"
    );
    shutdown(reopened).await;
}

#[tokio::test]
async fn global_instances_use_only_the_shared_day_counter_and_sys_is_not_a_session() {
    let fixture = Fixture::new().await;
    let session = fixture.session("normal").await;
    fixture
        .store
        .reserve_model_budget(None, 100, 0)
        .await
        .unwrap()
        .unwrap();
    fixture
        .store
        .reserve_model_budget(Some(session.clone()), 100, 1)
        .await
        .unwrap()
        .unwrap();
    let counters = fixture.snapshot();
    assert_eq!(daily_total(&counters), 2);
    assert_eq!(session_count(&counters, &session), Some(1));
    assert_eq!(session_count(&counters, "sys"), None);
    assert_eq!(
        counters
            .iter()
            .filter(|((scope, _), _)| scope == "session")
            .count(),
        1
    );
    let current_count = counters
        .get(&("day".into(), local_day().unwrap()))
        .copied()
        .unwrap_or(0) as u64;
    assert_eq!(
        fixture
            .store
            .reserve_model_budget(None, current_count, 0)
            .await
            .unwrap(),
        Err(BudgetExceeded {
            scope: "day",
            limit: current_count
        })
    );
    for invalid in ["sys", "missing-session"] {
        assert!(matches!(
            fixture
                .store
                .reserve_model_budget(Some(invalid.into()), 100, 100)
                .await,
            Err(StoreError::NotFound)
        ));
    }
    assert_eq!(
        fixture.snapshot(),
        counters,
        "invalid scope consumed a budget"
    );
}

#[tokio::test]
async fn version_one_upgrade_adds_budget_tables_without_changing_historical_events() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("legacy");
    std::fs::create_dir(&home).unwrap();
    let event_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    {
        let connection = Connection::open(home.join("fictor.db")).unwrap();
        connection
            .execute_batch(include_str!("../migrations/0001_init.sql"))
            .unwrap();
        connection
            .execute(
                "INSERT INTO sessions(id,kind,created_at,updated_at) VALUES('sys','system',1,1)",
                [],
            )
            .unwrap();
        connection.execute("INSERT INTO events(id,session_id,kind,actor,payload,trust,sensitivity,source,flags,text,created_at) VALUES(?1,'sys','user.message','user',?2,'trusted','public','legacy',0,'retained',1)",params![event_id,"{\"text\":\"retained\"}"]).unwrap();
        connection
            .execute("UPDATE sessions SET head_id=?1 WHERE id='sys'", [event_id])
            .unwrap();
        connection.pragma_update(None, "user_version", 1).unwrap();
    }
    let store = Store::open(&home).await.unwrap();
    let event = store.event(event_id.into()).await.unwrap();
    assert_eq!(event.payload, serde_json::json!({"text":"retained"}));
    assert_eq!(event.actor, "user");
    assert_eq!(event.source, "legacy");
    assert_eq!(event.created_at, 1);
    assert_eq!(
        store
            .session("sys".into())
            .await
            .unwrap()
            .head_id
            .as_deref(),
        Some(event_id)
    );
    let matches = store
        .query_events(EventQuery {
            text: Some("retained".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].id, event_id);
    store
        .reserve_model_budget(None, 1, 0)
        .await
        .unwrap()
        .unwrap();
    store.shutdown().await.unwrap();
    let connection = Connection::open(home.join("fictor.db")).unwrap();
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        3
    );
    for table in ["budget_usage", "workspace_flags", "ext_flags"] {
        assert_eq!(
            connection
                .query_row(
                    "SELECT name FROM sqlite_schema WHERE type='table' AND name=?1",
                    [table],
                    |row| row.get::<_, String>(0)
                )
                .optional()
                .unwrap()
                .as_deref(),
            Some(table)
        );
    }
    assert!(
        connection
            .execute("UPDATE events SET payload=payload WHERE id=?1", [event_id])
            .is_err()
    );
    assert!(
        connection
            .execute("DELETE FROM events WHERE id=?1", [event_id])
            .is_err()
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM events", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
}
