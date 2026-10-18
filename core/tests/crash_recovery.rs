use fictor::{
    crash_recovery::*,
    store::{AppendEvent, Event, EventQuery, NewSession, Provenance, Store, StoreError, Trust},
};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{Arc, Mutex},
};

const BOOT_A: &str = "11111111-1111-4111-8111-111111111111";
const BOOT_B: &str = "22222222-2222-4222-8222-222222222222";
const BUNDLE: &str = "1.0.0-0123456789ab";
struct FakeClock(Mutex<Option<CrashTime>>);
impl CrashClock for FakeClock {
    fn now(&self) -> Result<CrashTime, StoreError> {
        self.0.lock().unwrap().clone().ok_or(StoreError::Clock)
    }
}
impl FakeClock {
    fn set(&self, boot: &str, at: i64, civil: i64) {
        *self.0.lock().unwrap() = Some(CrashTime {
            boot_id: boot.into(),
            boottime_ms: at,
            unix_ms: civil,
        });
    }
}
struct Fixture {
    root: tempfile::TempDir,
    home: PathBuf,
    workspace: PathBuf,
    store: Arc<Store>,
    clock: Arc<FakeClock>,
}
impl Fixture {
    async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let home = root.path().join("core");
        let workspace = root.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        fictor::initialize(&home).await.unwrap();
        let store = Arc::new(Store::open(&home).await.unwrap());
        let clock = Arc::new(FakeClock(Mutex::new(None)));
        clock.set(BOOT_A, 100_000, 1_700_000_000_000);
        Self {
            root,
            home,
            workspace,
            store,
            clock,
        }
    }
    async fn restart(self) -> Self {
        let Self {
            root,
            home,
            workspace,
            store,
            clock,
        } = self;
        match Arc::try_unwrap(store) {
            Ok(store) => store.shutdown().await.unwrap(),
            Err(_) => panic!("unexpected Store owner"),
        }
        let store = Arc::new(Store::open(&home).await.unwrap());
        Self {
            root,
            home,
            workspace,
            store,
            clock,
        }
    }
    async fn session(&self) -> String {
        self.store
            .create_session(NewSession {
                title: "Crash fixture".into(),
                workspace: self.workspace.clone(),
                workspace_trust: Trust::Trusted,
                harness: "crash-tool".into(),
                mode: fictor::config::Mode::Plan,
                model: None,
            })
            .await
            .unwrap()
            .id
    }
    fn key(&self, session: Option<&str>) -> RecoveryKey {
        RecoveryKey {
            ext_id: "crash-tool".into(),
            key: BUNDLE.into(),
            session_id: session.map(str::to_owned),
        }
    }
    async fn availability(&self, key: &RecoveryKey) -> RecoveryStatus {
        self.store
            .crash_availability(key.clone(), self.clock.clone())
            .await
            .unwrap()
    }
    async fn record(&self, observation: &CrashObservation) -> CrashRecorded {
        self.store
            .record_crash(observation.clone(), self.clock.clone())
            .await
            .unwrap()
    }
    async fn events(&self) -> Vec<Event> {
        let mut events = self
            .store
            .query_events(EventQuery {
                session_id: Some("sys".into()),
                kinds: vec![
                    "ext.crashed".into(),
                    "ext.crash_blocked".into(),
                    "ext.crash_reset".into(),
                ],
                limit: Some(1000),
                ..Default::default()
            })
            .await
            .unwrap();
        events.sort_by(|left, right| left.id.cmp(&right.id));
        events
    }
    async fn rows(&self) -> Vec<Value> {
        self.store.write(|db| {
            let mut statement=db.prepare("SELECT ext_id,bundle_key,session_id,boot_id,crashes,retry_at_ms,blocked,updated_at FROM extension_crash_recovery ORDER BY ext_id,bundle_key,session_id")?;
            Ok(statement.query_map([],|row| Ok(json!({"ext_id":row.get::<_,String>(0)?,"key":row.get::<_,String>(1)?,"session_id":row.get::<_,Option<String>>(2)?,"boot_id":row.get::<_,String>(3)?,"crashes":row.get::<_,String>(4)?,"retry_at_ms":row.get::<_,i64>(5)?,"blocked":row.get::<_,bool>(6)?,"updated_at":row.get::<_,i64>(7)?})))?.collect::<Result<Vec<_>,_>>()?)
        }).await.unwrap()
    }
}
fn observation(key: &RecoveryKey) -> CrashObservation {
    CrashObservation {
        recovery: key.clone(),
        instance_id: ulid::Ulid::generate().to_string(),
        code: Some(0),
        signal: None,
        stderr: CrashStderr::unavailable(),
    }
}
fn selection(key: &RecoveryKey, scope: RecoveryScope) -> ResetCrashes {
    ResetCrashes {
        ext_id: key.ext_id.clone(),
        key: key.key.clone(),
        scope,
        session_id: key.session_id.clone(),
    }
}
fn samples(row: &Value) -> Value {
    serde_json::from_str(row["crashes"].as_str().unwrap()).unwrap()
}

#[tokio::test]
async fn delays_block_sixth_crash_and_keep_other_identities_independent() {
    let f = Fixture::new().await;
    let session = f.session().await;
    let other = f.session().await;
    let key = f.key(Some(&session));
    let mut at = 100_000;
    let mut ids = vec![];
    for delay in [1000, 2000, 4000, 8000, 16000] {
        f.clock.set(BOOT_A, at, 1_700_000_000_000);
        let crash = observation(&key);
        ids.push(crash.instance_id.clone());
        assert_eq!(
            f.record(&crash).await,
            CrashRecorded {
                recorded: true,
                status: RecoveryStatus::Backoff {
                    retry_after_ms: delay
                }
            }
        );
        assert_eq!(
            f.availability(&key).await,
            RecoveryStatus::Backoff {
                retry_after_ms: delay
            }
        );
        at += delay;
        f.clock.set(BOOT_A, at, -50_000); // Civil clock rollback cannot affect deadlines.
        assert_eq!(f.availability(&key).await, RecoveryStatus::Ready);
    }
    let sixth = observation(&key);
    ids.push(sixth.instance_id.clone());
    assert_eq!(f.record(&sixth).await.status, RecoveryStatus::CrashLoop);
    let events = f.events().await;
    let crashes: Vec<_> = events
        .iter()
        .filter(|event| event.kind == "ext.crashed")
        .collect();
    assert_eq!(crashes.len(), 6);
    for (index, event) in crashes.iter().enumerate() {
        assert_eq!(event.payload["recovery_count"], index + 1);
        assert_eq!(event.payload["code"], 0); // Spontaneous exit 0 still counts.
        assert_eq!(event.payload["session_id"], session);
        assert_eq!(event.session_id, "sys");
        assert_eq!(event.actor, "core");
        assert_eq!(event.payload["instance_id"], ids[index]);
    }
    assert_eq!(crashes[5].payload["backoff_ms"], Value::Null);
    let blocked = events
        .iter()
        .find(|event| event.kind == "ext.crash_blocked")
        .unwrap();
    assert_eq!(blocked.parent_id.as_ref(), Some(&crashes[5].id));
    assert_eq!(blocked.payload["crashes"], 6);
    assert_eq!(blocked.payload["window_ms"], 60_000);
    let other_session = f.key(Some(&other));
    let mut other_key = key.clone();
    other_key.key = "2.0.0-0123456789ab".into();
    let mut other_ext = key.clone();
    other_ext.ext_id = "other-tool".into();
    for independent in [&other_session, &other_key, &other_ext, &f.key(None)] {
        assert_eq!(f.availability(independent).await, RecoveryStatus::Ready);
    }
    f.clock.set(BOOT_B, 0, 0);
    let f = f.restart().await;
    assert_eq!(f.availability(&key).await, RecoveryStatus::CrashLoop);
    f.clock.set(BOOT_B, 10_000_000, 99);
    assert_eq!(f.availability(&key).await, RecoveryStatus::CrashLoop);
    assert_eq!(samples(&f.rows().await[0]).as_array().unwrap().len(), 6);
    assert_eq!(f.rows().await[0]["boot_id"], BOOT_A);
    assert_eq!(
        f.store
            .reset_crashes(selection(&key, RecoveryScope::Session), 42)
            .await
            .unwrap()
            .cleared,
        1
    );
    assert_eq!(f.availability(&key).await, RecoveryStatus::Ready);
    let reset = f.events().await.pop().unwrap();
    assert_eq!(reset.kind, "ext.crash_reset");
    assert_eq!(reset.payload["previous_count"], 6);
    assert_eq!(reset.payload["was_blocked"], true);
    assert_eq!(
        f.record(&observation(&key)).await.status,
        RecoveryStatus::Backoff {
            retry_after_ms: 1000
        }
    );
}

#[tokio::test]
async fn exact_window_boundary_expires_without_shortening_an_existing_wait() {
    let f = Fixture::new().await;
    let key = f.key(None);
    let first = observation(&key);
    f.record(&first).await;
    f.clock.set(BOOT_A, 159_999, 0);
    let second = observation(&key);
    assert_eq!(
        f.record(&second).await.status,
        RecoveryStatus::Backoff {
            retry_after_ms: 2000
        }
    );
    f.clock.set(BOOT_A, 160_000, 0);
    assert_eq!(
        f.availability(&key).await,
        RecoveryStatus::Backoff {
            retry_after_ms: 1999
        }
    );
    assert_eq!(samples(&f.rows().await[0]).as_array().unwrap().len(), 1);
    assert!(!f.record(&first).await.recorded); // Dedup consults durable history.
    f.clock.set(BOOT_A, 220_000, 0);
    assert_eq!(f.availability(&key).await, RecoveryStatus::Ready);
    assert!(f.rows().await.is_empty());
    assert_eq!(
        f.record(&first).await,
        CrashRecorded {
            recorded: false,
            status: RecoveryStatus::Ready
        }
    );
    assert_eq!(f.events().await.len(), 2);
    assert_eq!(
        f.record(&observation(&key)).await.status,
        RecoveryStatus::Backoff {
            retry_after_ms: 1000
        }
    );
}

#[tokio::test]
async fn restart_preserves_deadlines_and_new_boot_rebases_stored_samples_once() {
    let f = Fixture::new().await;
    let key = f.key(None);
    let first = observation(&key);
    f.record(&first).await;
    f.clock.set(BOOT_A, 100_500, 500);
    let f = f.restart().await;
    assert_eq!(
        f.availability(&key).await,
        RecoveryStatus::Backoff {
            retry_after_ms: 500
        }
    );
    f.clock.set(BOOT_A, 101_000, i64::MIN);
    assert_eq!(f.availability(&key).await, RecoveryStatus::Ready);
    assert_eq!(
        f.record(&observation(&key)).await.status,
        RecoveryStatus::Backoff {
            retry_after_ms: 2000
        }
    );
    f.clock.set(BOOT_B, 10, 8);
    assert_eq!(
        f.availability(&key).await,
        RecoveryStatus::Backoff {
            retry_after_ms: 2000
        }
    );
    let rows = f.rows().await;
    assert_eq!(rows[0]["boot_id"], BOOT_B);
    assert_eq!(samples(&rows[0])[0]["instance_id"], first.instance_id);
    assert!(
        samples(&rows[0])
            .as_array()
            .unwrap()
            .iter()
            .all(|sample| sample["at_ms"] == 10)
    );
    f.clock.set(BOOT_B, 1010, 7);
    let f = f.restart().await;
    assert_eq!(
        f.availability(&key).await,
        RecoveryStatus::Backoff {
            retry_after_ms: 1000
        }
    );
    f.clock.set(BOOT_B, 2010, 6);
    assert_eq!(f.availability(&key).await, RecoveryStatus::Ready);
    assert_eq!(f.events().await.len(), 2); // Queries/time passage never spawn or emit crashes.
}

#[tokio::test]
async fn failed_crash_or_block_audit_rolls_back_the_entire_transition() {
    let f = Fixture::new().await;
    let key = f.key(None);
    let first = observation(&key);
    f.store.write(|db| { db.execute_batch("CREATE TRIGGER crash_failure BEFORE INSERT ON events WHEN NEW.kind='ext.crashed' BEGIN SELECT RAISE(ABORT,'test crash failure'); END;")?; Ok(()) }).await.unwrap();
    assert!(
        f.store
            .record_crash(first.clone(), f.clock.clone())
            .await
            .is_err()
    );
    assert!(f.rows().await.is_empty());
    assert!(f.events().await.is_empty());
    f.store
        .write(|db| {
            db.execute_batch("DROP TRIGGER crash_failure")?;
            Ok(())
        })
        .await
        .unwrap();
    f.record(&first).await;
    let mut at = 101_000;
    for delay in [2000, 4000, 8000, 16000] {
        f.clock.set(BOOT_A, at, 0);
        f.record(&observation(&key)).await;
        at += delay;
    }
    let before = f.rows().await;
    f.store.write(|db| {db.execute_batch("CREATE TRIGGER block_failure BEFORE INSERT ON events WHEN NEW.kind='ext.crash_blocked' BEGIN SELECT RAISE(ABORT,'test block failure'); END;")?;Ok(())}).await.unwrap();
    f.clock.set(BOOT_A, at, 0);
    let sixth = observation(&key);
    assert!(
        f.store
            .record_crash(sixth.clone(), f.clock.clone())
            .await
            .is_err()
    );
    assert_eq!(f.rows().await, before);
    assert_eq!(f.events().await.len(), 5);
    f.store
        .write(|db| {
            db.execute_batch("DROP TRIGGER block_failure")?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(f.record(&sixth).await.status, RecoveryStatus::CrashLoop);
    assert!(!f.record(&sixth).await.recorded);
    assert_eq!(f.events().await.len(), 7);
}

#[tokio::test]
async fn human_reset_is_selective_atomic_and_does_not_resurrect_a_duplicate() {
    let f = Fixture::new().await;
    let a = f.session().await;
    let b = f.session().await;
    let ka = f.key(Some(&a));
    let kb = f.key(Some(&b));
    let ca = observation(&ka);
    f.record(&ca).await;
    f.record(&observation(&kb)).await;
    let before = f.rows().await;
    f.store.write(|db|{db.execute_batch("CREATE TRIGGER reset_failure BEFORE INSERT ON events WHEN NEW.kind='ext.crash_reset' BEGIN SELECT RAISE(ABORT,'test reset failure'); END;")?;Ok(())}).await.unwrap();
    assert!(
        f.store
            .reset_crashes(selection(&ka, RecoveryScope::Session), 99)
            .await
            .is_err()
    );
    assert_eq!(f.rows().await, before);
    assert_eq!(f.events().await.len(), 2);
    f.store
        .write(|db| {
            db.execute_batch("DROP TRIGGER reset_failure")?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        f.store
            .reset_crashes(selection(&ka, RecoveryScope::Session), 100)
            .await
            .unwrap()
            .cleared,
        1
    );
    assert_eq!(f.availability(&ka).await, RecoveryStatus::Ready);
    assert!(matches!(
        f.availability(&kb).await,
        RecoveryStatus::Backoff { .. }
    ));
    assert!(!f.record(&ca).await.recorded); // Audit survives reset as well as expiry.
    let events = f.events().await;
    let reset = events.last().unwrap();
    assert_eq!(reset.kind, "ext.crash_reset");
    assert_eq!(reset.actor, "user");
    assert_eq!(reset.payload["previous_count"], 1);
    assert_eq!(reset.payload["was_blocked"], false);
    let all = selection(&f.key(None), RecoveryScope::Session);
    assert_eq!(
        f.store
            .reset_crashes(all.clone(), 101)
            .await
            .unwrap()
            .cleared,
        1
    );
    assert_eq!(f.store.reset_crashes(all, 102).await.unwrap().cleared, 0);
    assert_eq!(
        f.events()
            .await
            .iter()
            .filter(|e| e.kind == "ext.crash_reset")
            .count(),
        2
    );
    assert!(
        f.store
            .reset_crashes(selection(&ka, RecoveryScope::Global), 103)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn unavailable_stderr_still_counts_and_captured_tail_is_referenced() {
    let f = Fixture::new().await;
    let key = f.key(None);
    let hash = f
        .store
        .put_blob(b"fake filtered stderr".to_vec())
        .await
        .unwrap();
    let mut first = observation(&key);
    first.stderr = CrashStderr {
        blob: Some(hash.clone()),
        unavailable: true,
    };
    f.record(&first).await;
    let events = f.events().await;
    assert_eq!(events[0].blob_refs, vec![hash.clone()]);
    assert_eq!(events[0].payload["stderr_blob"], hash);
    assert_eq!(events[0].payload["stderr_unavailable"], true);
    f.clock.set(BOOT_A, 101_000, 0);
    let mut missing = observation(&key);
    missing.stderr = CrashStderr {
        blob: Some(format!("sha256:{}", "0".repeat(64))),
        unavailable: false,
    };
    f.record(&missing).await;
    let events = f.events().await;
    assert_eq!(events[1].payload["recovery_count"], 2);
    assert_eq!(events[1].payload["stderr_unavailable"], true);
    assert!(events[1].blob_refs.is_empty());
}

#[tokio::test]
async fn legacy_crash_history_is_deduplicated_without_rewriting_or_counting_it() {
    let f = Fixture::new().await;
    let key = f.key(None);
    let crash = observation(&key);
    let event=f.store.append(AppendEvent {session_id:"sys".into(),parent_id:None,kind:"ext.crashed".into(),actor:"core".into(),
        payload:json!({"ext_id":key.ext_id,"key":key.key,"instance_id":crash.instance_id,"code":0,"signal":null,"smoke":false}),blob_refs:vec![],provenance:Provenance::core()}).await.unwrap();
    assert_eq!(
        f.record(&crash).await,
        CrashRecorded {
            recorded: false,
            status: RecoveryStatus::Ready
        }
    );
    assert!(f.rows().await.is_empty());
    assert_eq!(f.events().await[0].payload, event.payload);
    let mut forged = crash;
    forged.recovery.key = "2.0.0-0123456789ab".into();
    assert!(f.store.record_crash(forged, f.clock.clone()).await.is_err());
}

#[tokio::test]
async fn malformed_recovery_or_clock_fails_closed_without_state_or_events() {
    let f = Fixture::new().await;
    let key = f.key(None);
    let one = ulid::Ulid::generate().to_string();
    let two = ulid::Ulid::generate().to_string();
    for (boot, crashes, retry) in [
        (
            BOOT_A,
            json!([{"instance_id":one,"at_ms":1,"extra":true}]),
            1001,
        ),
        (
            BOOT_A,
            json!([{"instance_id":one,"at_ms":1},{"instance_id":one,"at_ms":2}]),
            1002,
        ),
        (
            BOOT_A,
            json!([{"instance_id":one,"at_ms":2},{"instance_id":two,"at_ms":1}]),
            1001,
        ),
        (BOOT_A, json!([{"instance_id":one,"at_ms":-1}]), 1000),
        (BOOT_A, json!([{"instance_id":one,"at_ms":0.5}]), 1000),
        (BOOT_A, json!([{"instance_id":"invalid","at_ms":1}]), 1001),
        (BOOT_A, json!([{"instance_id":one,"at_ms":100_001}]), 101001),
        (BOOT_A, json!([{"instance_id":one,"at_ms":1}]), 1250),
        (BOOT_A, json!([{"instance_id":one,"at_ms":99_999}]), 0),
        (
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            json!([{"instance_id":one,"at_ms":1}]),
            1001,
        ),
    ] {
        let boot = boot.to_owned();
        let raw = crashes.to_string();
        let raw_copy = raw.clone();
        f.store.write(move |db| {db.execute("DELETE FROM extension_crash_recovery",[])?;
            db.execute("INSERT INTO extension_crash_recovery(ext_id,bundle_key,session_id,boot_id,crashes,retry_at_ms,blocked,updated_at) VALUES ('crash-tool',?1,NULL,?2,?3,?4,0,0)",rusqlite::params![BUNDLE,boot,raw,retry])?;Ok(())}).await.unwrap();
        assert!(
            f.store
                .crash_availability(key.clone(), f.clock.clone())
                .await
                .is_err()
        );
        assert_eq!(f.rows().await[0]["crashes"], raw_copy);
        assert!(f.events().await.is_empty());
    }
    f.store
        .write(|db| {
            db.execute("DELETE FROM extension_crash_recovery", [])?;
            Ok(())
        })
        .await
        .unwrap();
    for (boot, at) in [("bad", 0), (BOOT_A, -1), (BOOT_A, i64::MAX)] {
        f.clock.set(boot, at, 0);
        assert!(
            f.store
                .record_crash(observation(&key), f.clock.clone())
                .await
                .is_err()
        );
        assert!(f.rows().await.is_empty());
        assert!(f.events().await.is_empty());
    }
    *f.clock.0.lock().unwrap() = None;
    assert!(
        f.store
            .crash_availability(key, f.clock.clone())
            .await
            .is_err()
    );
}
