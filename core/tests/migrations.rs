use fictor::store::{Store, StoreError};
use rusqlite::{Connection, params, types::Value};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

fn legacy(home: &Path) -> Connection {
    let db = Connection::open(home.join("fictor.db")).unwrap();
    db.execute_batch(include_str!("../migrations/0001_init.sql"))
        .unwrap();
    db.execute_batch(include_str!("../migrations/0002_flow_budget.sql"))
        .unwrap();
    db.pragma_update(None, "user_version", 2).unwrap();
    db.execute(
        "INSERT INTO sessions(id,kind,created_at,updated_at) VALUES('sys','system',1,1)",
        [],
    )
    .unwrap();
    db
}

fn snapshot(db: &Connection, table: &str) -> Vec<Vec<Value>> {
    let mut statement = db
        .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
        .unwrap();
    statement
        // SQLite may reprepare SELECT * on the first step after another
        // connection migrates the schema. Count columns from that stepped row.
        .query_map([], |row| {
            (0..row.as_ref().column_count())
                .map(|index| row.get(index))
                .collect()
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[tokio::test]
async fn version_three_preserves_every_legacy_proposal_column_and_append_only_events() {
    let root = tempfile::tempdir().unwrap();
    let db = legacy(root.path());
    db.pragma_update(None, "journal_mode", "WAL").unwrap();
    db.execute("INSERT INTO events(id,session_id,kind,actor,payload,trust,sensitivity,source,flags,text,created_at) VALUES('01ARZ3NDEKTSV4RRFFQ69G5FAV','sys','ext.proposed','core','{\"legacy\":true}','trusted','public','legacy',0,'history',1)", []).unwrap();
    for (index, state) in [
        "received", "checking", "checked", "approved", "rejected", "promoted", "failed",
    ]
    .into_iter()
    .enumerate()
    {
        db.execute("INSERT INTO proposals(id,ext_id,version,hash,source,state,update_of,tainted,manifest,checks,packages,audit_blob,nonce,decided_by,note,created_at,updated_at) VALUES(?1,'legacy','0.1.0','hash','{\"kind\":\"local\"}',?2,'old-key',1,'{\"retained\":true}','[]','[]','audit','retained-nonce','user','note',1,2)", params![format!("proposal-{index}"),state]).unwrap();
    }
    let proposals = snapshot(&db, "proposals");
    let events = snapshot(&db, "events");
    let store = Store::open(root.path()).await.unwrap();
    store.shutdown().await.unwrap();
    let upgraded = snapshot(&db, "proposals");
    for (row, original) in upgraded.iter().zip(&proposals) {
        assert_eq!(&row[..original.len()], original);
        assert_eq!(
            &row[original.len()..],
            &[
                Value::Null,
                Value::Text("{\"permissions\":{},\"tools\":{}}".into())
            ]
        );
    }
    assert_eq!(upgraded.len(), proposals.len());
    assert_eq!(snapshot(&db, "events"), events);
    assert_eq!(
        db.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        5
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type='index' AND name='proposals_state'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert!(db.execute("UPDATE events SET payload='{}'", []).is_err());
    assert!(db.execute("DELETE FROM events", []).is_err());
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM events_fts WHERE events_fts MATCH 'history'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    let backup_path = root.path().join("fictor.db.bak-2");
    assert_eq!(
        fs::metadata(&backup_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let backup = Connection::open(backup_path).unwrap();
    assert_eq!(
        backup
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(snapshot(&backup, "proposals"), proposals);
    assert_eq!(
        snapshot(&backup, "events"),
        events,
        "backup must include committed WAL frames"
    );
}

#[tokio::test]
async fn database_enforces_joint_identity_and_restricts_unidentified_states() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).await.unwrap();
    store.shutdown().await.unwrap();
    let db = Connection::open(root.path().join("fictor.db")).unwrap();
    for (index, state) in [
        "received", "failed", "checking", "checked", "approved", "rejected", "promoted",
    ]
    .into_iter()
    .enumerate()
    {
        let result = db.execute("INSERT INTO proposals(id,source,state,nonce,created_at,updated_at) VALUES(?1,'{}',?2,'nonce',0,0)",params![format!("null-{index}"),state]);
        assert_eq!(result.is_ok(), matches!(state, "received" | "failed"));
    }
    for (id, ext_id, version) in [
        ("partial-id", Some("valid"), None),
        ("partial-version", None, Some("0.1.0")),
    ] {
        assert!(db.execute("INSERT INTO proposals(id,ext_id,version,source,state,nonce,created_at,updated_at) VALUES(?1,?2,?3,'{}','received','nonce',0,0)",params![id,ext_id,version]).is_err());
    }
}

#[tokio::test]
async fn failed_backup_prevents_schema_upgrade_and_symlink_backup_targets_are_not_followed() {
    let root = tempfile::tempdir().unwrap();
    let db = legacy(root.path());
    let target = root.path().join("fictor.db.bak-2");
    fs::create_dir(&target).unwrap();
    assert!(Store::open(root.path()).await.is_err());
    assert_eq!(
        db.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        2
    );
    fs::remove_dir(&target).unwrap();
    let external = root.path().join("external");
    fs::write(&external, b"preserve me").unwrap();
    std::os::unix::fs::symlink(&external, &target).unwrap();
    Store::open(root.path())
        .await
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    assert_eq!(fs::read(external).unwrap(), b"preserve me");
    assert!(
        !fs::symlink_metadata(target)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[tokio::test]
async fn future_schema_is_untouched_and_backups_are_pruned_only_during_upgrade() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("fictor.db");
    let db = Connection::open(&path).unwrap();
    db.pragma_update(None, "user_version", 99).unwrap();
    drop(db);
    let before = fs::read(&path).unwrap();
    assert!(matches!(
        Store::open(root.path()).await,
        Err(StoreError::NewerSchema(99))
    ));
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(!root.path().join("fictor.db.bak-99").exists());
    fs::remove_file(path).unwrap();
    let db = legacy(root.path());
    drop(db);
    for version in [0, 1, 9] {
        fs::write(
            root.path().join(format!("fictor.db.bak-{version}")),
            b"old backup",
        )
        .unwrap();
    }
    let future = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
    for version in [0, 1, 9] {
        fs::File::open(root.path().join(format!("fictor.db.bak-{version}")))
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(future))
            .unwrap();
    }
    let unknown = root.path().join("fictor.db.bak-unknown");
    fs::write(&unknown, b"keep").unwrap();
    Store::open(root.path())
        .await
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    let backups = fs::read_dir(root.path())
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_prefix("fictor.db.bak-"))
                .and_then(|suffix| suffix.parse::<u32>().ok())
                .is_some()
        })
        .count();
    assert_eq!(backups, 3);
    assert_eq!(fs::read(unknown).unwrap(), b"keep");
    assert!(root.path().join("fictor.db.bak-2").exists());
}

#[test]
fn future_wal_fixture_process() {
    let Some(home) = std::env::var_os("FICTOR_TEST_FUTURE_WAL") else {
        return;
    };
    let db = Connection::open(Path::new(&home).join("fictor.db")).unwrap();
    db.pragma_update(None, "journal_mode", "WAL").unwrap();
    db.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
    db.execute_batch("CREATE TABLE future_data(value TEXT); INSERT INTO future_data VALUES('committed'); PRAGMA user_version=99;").unwrap();
    // Simulate a crash leaving committed WAL frames without SQLite cleanup.
    std::process::exit(0);
}

#[tokio::test]
async fn future_schema_in_crashed_wal_is_refused_without_checkpoint_or_wal_removal() {
    let root = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "future_wal_fixture_process"])
        .env_clear()
        .env("FICTOR_TEST_FUTURE_WAL", root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let database = root.path().join("fictor.db");
    let wal = root.path().join("fictor.db-wal");
    let main_before = fs::read(&database).unwrap();
    let wal_before = fs::read(&wal).unwrap();
    assert!(!wal_before.is_empty());
    assert!(matches!(
        Store::open(root.path()).await,
        Err(StoreError::NewerSchema(99))
    ));
    assert_eq!(fs::read(database).unwrap(), main_before);
    assert_eq!(fs::read(wal).unwrap(), wal_before);
    assert!(!root.path().join("fictor.db.bak-99").exists());
}

fn version_three(home: &Path) -> Connection {
    let db = legacy(home);
    db.execute_batch(include_str!("../migrations/0003_proposal_receipts.sql"))
        .unwrap();
    db.pragma_update(None, "user_version", 3).unwrap();
    db.pragma_update(None, "foreign_keys", true).unwrap();
    db
}

#[tokio::test]
async fn promotion_and_crash_schemas_preserve_receipts_and_enforce_their_constraints() {
    let root = tempfile::tempdir().unwrap();
    let db = version_three(root.path());
    db.pragma_update(None, "journal_mode", "WAL").unwrap();
    db.execute("INSERT INTO proposals(id,source,state,nonce,created_at,updated_at) VALUES('receipt','{}','received','private-nonce',1,1)", []).unwrap();
    db.execute("INSERT INTO sessions(id,kind,created_at,updated_at) VALUES('session-a','normal',1,1),('session-b','normal',1,1)", []).unwrap();
    db.execute("INSERT INTO events(id,session_id,kind,actor,payload,trust,sensitivity,source,flags,created_at) VALUES('01ARZ3NDEKTSV4RRFFQ69G5FAV','sys','ext.proposed','core','{}','trusted','public','migration',0,1)", []).unwrap();
    let proposals = snapshot(&db, "proposals");
    let events = snapshot(&db, "events");
    Store::open(root.path())
        .await
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    let upgraded = snapshot(&db, "proposals");
    assert_eq!(&upgraded[0][..proposals[0].len()], &proposals[0]);
    assert_eq!(
        db.query_row(
            "SELECT review_base_hash,overrides FROM proposals WHERE id='receipt'",
            [],
            |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, String>(1)?))
        )
        .unwrap(),
        (None, "{\"permissions\":{},\"tools\":{}}".into())
    );
    assert_eq!(snapshot(&db, "events"), events);
    let backup_path = root.path().join("fictor.db.bak-3");
    assert_eq!(
        fs::metadata(&backup_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let backup = Connection::open(backup_path).unwrap();
    assert_eq!(
        backup
            .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        3
    );
    assert_eq!(snapshot(&backup, "proposals"), proposals);
    assert_eq!(snapshot(&backup, "events"), events);

    db.execute("INSERT INTO promotion_intents VALUES('first','receipt',NULL,NULL,'after','hash','prepared',1,1)", []).unwrap();
    assert!(db.execute("INSERT INTO promotion_intents VALUES('second','receipt',NULL,NULL,'after','hash','prepared',1,1)", []).is_err());
    assert!(db.execute("INSERT INTO promotion_intents VALUES('unknown','missing',NULL,NULL,'after','hash','committed',1,1)", []).is_err());
    assert!(db.execute("INSERT INTO promotion_intents VALUES('unpaired','receipt','before',NULL,'after','hash','committed',1,1)", []).is_err());
    db.execute(
        "UPDATE promotion_intents SET state='committed' WHERE operation_id='first'",
        [],
    )
    .unwrap();
    db.execute("INSERT INTO promotion_intents VALUES('second','receipt',NULL,NULL,'after','hash','prepared',1,1)", []).unwrap();

    let boot = "00000000-0000-0000-0000-000000000000";
    for session in [None, Some("session-a"), Some("session-b")] {
        db.execute("INSERT INTO extension_crash_recovery(ext_id,bundle_key,session_id,boot_id,updated_at) VALUES('extension','key',?1,?2,1)", params![session,boot]).unwrap();
        assert!(db.execute("INSERT INTO extension_crash_recovery(ext_id,bundle_key,session_id,boot_id,updated_at) VALUES('extension','key',?1,?2,1)", params![session,boot]).is_err());
    }
    assert!(db.execute("INSERT INTO extension_crash_recovery(ext_id,bundle_key,session_id,boot_id,updated_at) VALUES('extension','key','sys',?1,1)",[boot]).is_err());
    for (crashes, retry, blocked) in [
        ("not-json", 0, 0),
        ("{}", 0, 0),
        ("[1,2,3,4,5,6,7]", 0, 0),
        ("[]", -1, 0),
        ("[]", 0, 1),
    ] {
        assert!(db.execute("UPDATE extension_crash_recovery SET crashes=?1,retry_at_ms=?2,blocked=?3 WHERE session_id='session-a'",params![crashes,retry,blocked]).is_err());
    }
    let crashes = serde_json::to_string(&(0..6).map(|at_ms| serde_json::json!({"instance_id":ulid::Ulid::generate().to_string(),"at_ms":at_ms})).collect::<Vec<_>>()).unwrap();
    db.execute("UPDATE extension_crash_recovery SET crashes=?1,retry_at_ms=0,blocked=1 WHERE session_id='session-a'",[crashes]).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT blocked FROM extension_crash_recovery WHERE session_id='session-b'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert!(db.execute("UPDATE events SET payload='null'", []).is_err());
    assert!(db.execute("DELETE FROM events", []).is_err());
    assert_eq!(snapshot(&db, "events"), events);
}

#[tokio::test]
async fn failure_in_migration_five_rolls_back_migration_four_too() {
    let root = tempfile::tempdir().unwrap();
    let db = version_three(root.path());
    db.execute_batch("CREATE TABLE extension_crash_recovery(existing TEXT)")
        .unwrap();
    let schema = snapshot(&db, "sqlite_schema");
    assert!(Store::open(root.path()).await.is_err());
    assert_eq!(
        db.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        3
    );
    assert_eq!(snapshot(&db, "sqlite_schema"), schema);
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name='promotion_intents'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    db.execute_batch("DROP TABLE extension_crash_recovery")
        .unwrap();
    Store::open(root.path())
        .await
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    assert_eq!(
        db.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        5
    );
}

#[tokio::test]
async fn writer_refuses_jobs_after_full_durability_is_lost_and_reopen_restores_it() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).await.unwrap();
    store
        .write(|db| {
            assert_eq!(
                db.pragma_query_value(None, "synchronous", |r| r.get::<_, i64>(0))?,
                2
            );
            db.pragma_update(None, "synchronous", "NORMAL")?;
            Ok(())
        })
        .await
        .unwrap();
    let ran = Arc::new(AtomicBool::new(false));
    let observed = ran.clone();
    assert!(matches!(
        store
            .write(move |_| {
                observed.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await,
        Err(StoreError::Invalid(
            "durabilidade SQLite FULL não confirmada"
        ))
    ));
    assert!(!ran.load(Ordering::SeqCst));
    store.shutdown().await.unwrap();
    let store = Store::open(root.path()).await.unwrap();
    store
        .write(|db| {
            assert_eq!(
                db.pragma_query_value(None, "synchronous", |r| r.get::<_, i64>(0))?,
                2
            );
            Ok(())
        })
        .await
        .unwrap();
    store.shutdown().await.unwrap();
}
