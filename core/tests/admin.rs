use fictor::{
    admin::{self, AdminServer},
    installer::listing::{self, ListingError},
    ownership::HomeLease,
};
use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::{
        fs::{PermissionsExt, symlink},
        net::UnixListener as StdListener,
    },
    path::Path,
    process::Command,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
};

async fn fixture() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fictor::initialize(home.path()).await.unwrap();
    home
}
fn save_lock(home: &Path, lock: &Value) {
    fs::write(
        home.join("extensions/lock.json"),
        serde_json::to_vec(lock).unwrap(),
    )
    .unwrap();
    fs::set_permissions(
        home.join("extensions/lock.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
}
fn configured(home: &Path) {
    let tools = fictor::gateway::PinnedCatalog::new(vec![]).unwrap();
    let mut extensions = serde_json::Map::new();
    // Deliberately insert reverse order and include a disabled extension.
    for (id, enabled, digit) in [("zeta", false, "b"), ("alpha", true, "a")] {
        let key = format!("1.0.0-{}", digit.repeat(12));
        fs::create_dir_all(home.join("extensions/store").join(id).join(&key)).unwrap();
        extensions.insert(id.into(), json!({"enabled":enabled,"active":key,"versions":{
            (key.clone()):{"version":"1.0.0","hash":format!("sha256:{}",digit.repeat(64)),"path":format!("store/{id}/{key}"),
            "source":{"kind":"local"},"approved":{"by":"user","at":"2026-10-18T12:00:00Z","approval_id":null},
            "overrides":{"permissions":{},"tools":{}},"privileges":[],"tools":[],"tools_hash":tools.hash(),"packages":[],"audit":null}
        }}));
    }
    save_lock(
        home,
        &json!({"schema":1,"extensions":extensions,"runtimes":{}}),
    );
}
fn cli(home: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_fictor"))
        .args(["ext", "list"])
        .env("FICTOR_HOME", home)
        .output()
        .unwrap()
}
fn logical_state(home: &Path) -> (String, i64, i64, i64) {
    let connection =
        Connection::open_with_flags(home.join("fictor.db"), OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    (
        fs::read_to_string(home.join("extensions/lock.json")).unwrap(),
        connection
            .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
            .unwrap(),
        connection
            .query_row("SELECT count(*) FROM proposals", [], |row| row.get(0))
            .unwrap(),
        connection
            .query_row("SELECT count(*) FROM promotion_intents", [], |row| {
                row.get(0)
            })
            .unwrap(),
    )
}
async fn raw(home: &Path, mut bytes: Vec<u8>) -> Vec<u8> {
    let mut stream = UnixStream::connect(home.join("run/admin.sock"))
        .await
        .unwrap();
    bytes.push(b'\n');
    // Oversized input may be refused while the sender is still writing it.
    let _ = stream.write_all(&bytes).await;
    let mut response = Vec::new();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(7),
        stream.read_to_end(&mut response),
    )
    .await
    .unwrap();
    if let Err(error) = result {
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    }
    response
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_online_and_offline_show_the_same_configuration_without_mutation() {
    let home = fixture().await;
    configured(home.path());
    let before = logical_state(home.path());
    let offline = cli(home.path());
    assert!(
        offline.status.success(),
        "{}",
        String::from_utf8_lossy(&offline.stderr)
    );
    let owner = HomeLease::acquire(home.path()).unwrap();
    let server = AdminServer::bind(owner.clone()).await.unwrap();
    let online = cli(home.path());
    assert!(
        online.status.success(),
        "{}",
        String::from_utf8_lossy(&online.stderr)
    );
    assert_eq!(offline.stdout, online.stdout);
    let human = String::from_utf8(online.stdout).unwrap();
    assert_eq!(
        human,
        "ID\tCHAVE\tVERSÃO\tHABILITADA\nalpha\t1.0.0-aaaaaaaaaaaa\t1.0.0\ttrue\nzeta\t1.0.0-bbbbbbbbbbbb\t1.0.0\tfalse\n"
    );
    assert!(!human.contains("running") && !human.contains("healthy"));
    assert_eq!(logical_state(home.path()), before);
    server.shutdown().await.unwrap();
    assert!(!home.path().join("run/admin.sock").exists());
    drop(owner);
    let empty = fixture().await;
    let snapshot = listing::list(empty.path()).await.unwrap();
    assert_eq!(snapshot.extensions.len(), 0);
    let output = cli(empty.path());
    assert!(output.status.success());
    assert_eq!(output.stdout, b"ID\tCHAVE\tVERS\xc3\x83O\tHABILITADA\n");
}

#[tokio::test]
async fn missing_unsupported_and_malformed_offline_state_is_never_initialized_or_repaired() {
    let root = tempfile::tempdir().unwrap();
    let absent = root.path().join("absent");
    assert!(matches!(
        listing::list(&absent).await,
        Err(admin::AdminError::Listing(ListingError::NotInitialized))
    ));
    assert!(!absent.exists());
    for case in [
        "database",
        "lock",
        "older",
        "newer",
        "duplicate",
        "missing-table",
        "invalid-state",
    ] {
        let home = fixture().await;
        let db = home.path().join("fictor.db");
        let lock = home.path().join("extensions/lock.json");
        match case {
            "database" => fs::remove_file(&db).unwrap(),
            "lock" => fs::remove_file(&lock).unwrap(),
            "older" | "newer" => {
                let connection = Connection::open(&db).unwrap();
                connection
                    .pragma_update(None, "user_version", if case == "older" { 4 } else { 6 })
                    .unwrap();
            }
            "duplicate" => fs::write(
                &lock,
                br#"{"schema":1,"extensions":{},"extensions":{},"runtimes":{}}"#,
            )
            .unwrap(),
            "missing-table" => {
                Connection::open(&db)
                    .unwrap()
                    .execute_batch("DROP TABLE promotion_intents")
                    .unwrap();
            }
            "invalid-state" => {
                Connection::open(&db).unwrap().execute_batch("ALTER TABLE promotion_intents RENAME TO old_intents; CREATE TABLE promotion_intents(state TEXT); INSERT INTO promotion_intents VALUES('surprise')").unwrap();
            }
            _ => unreachable!(),
        }
        let before_lock = fs::read(&lock).ok();
        let backups = || {
            let mut names: Vec<_> = fs::read_dir(home.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .filter(|name| name.to_string_lossy().contains(".bak-"))
                .collect();
            names.sort();
            names
        };
        let before_backups = backups();
        let result = listing::list(home.path()).await;
        let reason = match case {
            "database" | "lock" => ListingError::NotInitialized,
            "older" | "newer" => ListingError::DataVersionUnsupported,
            _ => ListingError::InvalidSnapshot,
        };
        assert!(
            matches!(result, Err(admin::AdminError::Listing(actual)) if actual == reason),
            "{case}: {result:?}"
        );
        assert_eq!(fs::read(&lock).ok(), before_lock);
        assert_eq!(db.exists(), case != "database");
        assert!(!home.path().join("run/admin.sock").exists());
        assert_eq!(backups(), before_backups);
    }
}

#[tokio::test]
async fn occupied_owner_and_bad_endpoint_never_fall_back_to_valid_files() {
    let home = fixture().await;
    let owner = HomeLease::acquire(home.path()).unwrap();
    assert!(listing::list(home.path()).await.is_err());
    let socket = home.path().join("run/admin.sock");
    let other = home.path().join("run/other.sock");
    let _listener = StdListener::bind(&other).unwrap();
    fs::set_permissions(&other, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&other, &socket).unwrap();
    assert!(matches!(
        listing::list(home.path()).await,
        Err(admin::AdminError::Identity)
    ));
    fs::remove_file(&socket).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let fake = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut request = String::new();
        reader.read_line(&mut request).await.unwrap();
        // Even an owner exiting mid-attempt does not authorize a mode switch.
        drop(owner);
        reader.get_mut().write_all(b"{\"jsonrpc\":\"2.0\",\"id\":\"cli-1\",\"result\":{\"schema\":2,\"extensions\":[]}}\n").await.unwrap();
    });
    assert!(listing::list(home.path()).await.is_err());
    fake.await.unwrap();
    // A fresh command may acquire the now-free home; the failed one did not.
    assert!(listing::list(home.path()).await.is_ok());
}

#[tokio::test]
async fn busy_snapshot_returns_a_small_domain_error_and_releases_the_waiter() {
    let home = fixture().await;
    let owner = HomeLease::acquire(home.path()).unwrap();
    let server = AdminServer::bind(owner.clone()).await.unwrap();
    let guard = owner.installer_gate().lock_owned().await;
    let before = logical_state(home.path());
    let response = raw(
        home.path(),
        br#"{"jsonrpc":"2.0","id":"waiting","method":"ext.list","params":{}}"#.to_vec(),
    )
    .await;
    let response: Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(response["id"], "waiting");
    assert_eq!(response["error"]["code"], -32000);
    assert_eq!(response["error"]["data"]["reason"], "busy");
    assert!(response.get("result").is_none());
    assert_eq!(logical_state(home.path()), before);
    drop(guard);
    assert!(
        admin::request(home.path())
            .await
            .unwrap()
            .extensions
            .is_empty()
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn admin_rejects_protocol_violations_and_oversized_frames_before_snapshot() {
    let home = fixture().await;
    let owner = HomeLease::acquire(home.path()).unwrap();
    let server = AdminServer::bind(owner.clone()).await.unwrap();
    let _guard = owner.installer_gate().lock_owned().await;
    for (request, code) in [
        (b"\xff".as_slice(), -32700),
        (b"[]", -32600),
        (
            br#"{"jsonrpc":"2.0","id":"x","method":"other","params":{}}"#,
            -32601,
        ),
        (
            br#"{"jsonrpc":"2.0","id":"x","method":"ext.list","params":{"x":1}}"#,
            -32602,
        ),
        (
            br#"{"jsonrpc":"2.0","id":"x","method":"ext.list","params":{},"unknown":1}"#,
            -32600,
        ),
        (
            br#"{"jsonrpc":"2.0","id":"x","method":"ext.list","params":{"x":1,"x":2}}"#,
            -32600,
        ),
    ] {
        let response = raw(home.path(), request.to_vec()).await;
        let response: Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response["error"]["code"], code);
        assert!(response.get("result").is_none());
    }
    assert!(
        raw(
            home.path(),
            br#"{"jsonrpc":"2.0","method":"ext.list","params":{}}"#.to_vec()
        )
        .await
        .is_empty()
    );
    assert!(
        raw(home.path(), vec![b' '; listing::MAX_MESSAGE_BYTES + 1])
            .await
            .is_empty()
    );
    drop(_guard);
    let mut exact = br#"{"jsonrpc":"2.0","id":"exact","method":"ext.list","params":{}}"#.to_vec();
    exact.resize(listing::MAX_MESSAGE_BYTES, b' ');
    let response: Value = serde_json::from_slice(&raw(home.path(), exact).await).unwrap();
    assert_eq!(response["id"], "exact");
    assert_eq!(response["result"]["extensions"], json!([]));
    server.shutdown().await.unwrap();
}

// Trusted fake inputs exercise persistence only; no bundle is executed or
// represented as having passed a real installer/smoke run by these tests.
async fn prepare_pending(
    store: &fictor::store::Store,
    home: &Path,
) -> fictor::store::PromotionIntent {
    use fictor::{
        installer::{
            lock::{Approval, Lock, LockedExtension, LockedVersion, approval_at_ms},
            manifest::Manifest,
        },
        store::{
            HumanDecision, NewPromotionIntent, NewProposal, ProposalCheck, ProposalIdentity,
            ProposalState, ProposalUpdate, ReviewBase,
        },
    };
    let before = Lock::load_required(home).unwrap();
    let base = ReviewBase {
        update_of: None,
        hash: before.review_base_hash("candidate").unwrap(),
    };
    let catalog = fictor::gateway::PinnedCatalog::new(vec![]).unwrap();
    let manifest = Manifest::parse(&json!({"schema":1,"id":"candidate","version":"1.0.0","description":"Fake metadata for journal reads","runtime":{"kind":"binary","entry":"unused"},"scope":"session","mcp":false,"kernel":["config"]}).to_string()).unwrap();
    let proposal = store
        .begin_attempt(NewProposal {
            source: json!({"kind":"local"}),
            tainted: false,
        })
        .await
        .unwrap();
    store
        .transition_proposal(
            proposal.id.clone(),
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
    let hash = format!("sha256:{}", "c".repeat(64));
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
            .then(|| json!({"tools":[],"tools_hash":catalog.hash()}).to_string()),
    })
    .collect();
    store
        .transition_proposal(
            proposal.id.clone(),
            ProposalState::Checking,
            ProposalState::Checked,
            ProposalUpdate {
                hash: Some(hash.clone()),
                packages: Some(vec![]),
                checks: Some(checks),
                review_base: Some(base.clone()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let nonce = store.proposal_nonce(proposal.id.clone()).await.unwrap();
    let approved = store
        .transition_proposal(
            proposal.id.clone(),
            ProposalState::Checked,
            ProposalState::Approved,
            ProposalUpdate {
                decision: Some(HumanDecision::User(nonce)),
                review_base: Some(base),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let key = format!("1.0.0-{}", "c".repeat(12));
    fs::create_dir_all(home.join("extensions/store/candidate").join(&key)).unwrap();
    let mut after = before.clone();
    after.extensions.insert(
        "candidate".into(),
        LockedExtension {
            enabled: true,
            active: key.clone(),
            versions: [(
                key.clone(),
                LockedVersion {
                    version: "1.0.0".into(),
                    hash,
                    path: format!("store/candidate/{key}"),
                    source: json!({"kind":"local"}),
                    approved: Approval {
                        by: "user".into(),
                        at: approval_at_ms(approved.updated_at).unwrap(),
                        approval_id: None,
                    },
                    overrides: Default::default(),
                    privileges: vec![],
                    tools: vec![],
                    tools_hash: catalog.hash().into(),
                    packages: vec![],
                    audit: None,
                },
            )]
            .into(),
        },
    );
    store
        .prepare_promotion(NewPromotionIntent {
            proposal_id: proposal.id,
            before_lock: Some(before.encode_snapshot().unwrap()),
            after_lock: after.encode_snapshot().unwrap(),
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn admin_wal_child() {
    let Some(home) = std::env::var_os("FICTOR_TEST_ADMIN_WAL_HOME") else {
        return;
    };
    let home = std::path::PathBuf::from(home);
    let store = fictor::store::Store::open(&home).await.unwrap();
    let _guard = store.owner().installer_gate().lock_owned().await;
    let intent = prepare_pending(&store, &home).await;
    // Simulate the durable lock publication before its logical commit. Exiting
    // without destructors preserves SQLite's real uncheckpointed WAL.
    save_lock(&home, &serde_json::from_str(&intent.after_lock).unwrap());
    std::process::exit(0);
}

#[tokio::test]
async fn offline_reads_prepared_journal_from_wal_without_reconciliation() {
    let home = fixture().await;
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "admin_wal_child", "--nocapture"])
        .env("FICTOR_TEST_ADMIN_WAL_HOME", home.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(home.path().join("fictor.db-wal").metadata().unwrap().len() > 0);
    // Verify this is the promised WAL-only case, using only a fake copy of the
    // main database. The real query must never use immutable/nolock mode.
    let copied = tempfile::tempdir().unwrap();
    let path = copied.path().join("main-only.db");
    fs::copy(home.path().join("fictor.db"), &path).unwrap();
    let main_only = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    assert_eq!(
        main_only
            .query_row("SELECT count(*) FROM promotion_intents", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    let before = logical_state(home.path());
    assert_eq!(before.3, 1);
    assert!(matches!(
        listing::list(home.path()).await,
        Err(admin::AdminError::Listing(ListingError::RecoveryRequired))
    ));
    let command = cli(home.path());
    assert!(!command.status.success());
    assert!(command.stdout.is_empty());
    assert_eq!(logical_state(home.path()), before);
}

#[tokio::test]
async fn online_snapshots_share_the_promotion_section_and_never_expose_prepared_lock() {
    use std::{future::Future, task::Poll};
    let home = fixture().await;
    let owner = HomeLease::acquire(home.path()).unwrap();
    let store = fictor::store::Store::open_with_lease(owner.clone())
        .await
        .unwrap();
    let server = AdminServer::bind(owner.clone()).await.unwrap();
    let guard = owner.installer_gate().lock_owned().await;
    let intent = prepare_pending(&store, home.path()).await;
    save_lock(
        home.path(),
        &serde_json::from_str(&intent.after_lock).unwrap(),
    );
    drop(guard);
    let before = logical_state(home.path());
    assert!(matches!(
        listing::list(home.path()).await,
        Err(admin::AdminError::Listing(ListingError::RecoveryRequired))
    ));
    assert_eq!(logical_state(home.path()), before);
    let guard = owner.installer_gate().lock_owned().await;
    let mut waiting = Box::pin(listing::snapshot(owner.clone()));
    // Poll the actual snapshot until its gate wait is registered. No sleep or
    // production hook is used to arrange the overlap with the commit.
    std::future::poll_fn(|context| {
        assert!(waiting.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    store.commit_promotion(intent.operation_id).await.unwrap();
    drop(guard);
    let snapshot = waiting.await.unwrap();
    assert_eq!(snapshot.extensions.len(), 1);
    assert_eq!(snapshot.extensions[0].id, "candidate");
    assert_eq!(snapshot.extensions[0].active, "1.0.0-cccccccccccc");
    assert_eq!(admin::request(home.path()).await.unwrap(), snapshot);
    server.shutdown().await.unwrap();
    store.shutdown().await.unwrap();
}
