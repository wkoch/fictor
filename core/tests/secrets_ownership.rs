use fictor::{
    ownership::{HomeLease, OwnershipError},
    secrets::{BackendKind, Redactor, SecretError, SecretStore},
    store::Store,
};
use std::{path::Path, process::Stdio, time::Duration};

// A concurrently forked fixture can briefly inherit another test's flock FD
// before exec closes it. Keep lifetime assertions separate from that launch.
static PROCESS_FIXTURE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const CHILD_HOME: &str = "FICTOR_TEST_OWNED_SECRET_HOME";

#[test]
fn owned_file_backend_fixture_process() {
    let Some(home) = std::env::var_os(CHILD_HOME) else {
        return;
    };
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let home = Path::new(&home);
        fictor::initialize(home).await.unwrap();
        let store = Store::open(home).await.unwrap();
        let first = SecretStore::open_with_lease(
            store.owner().clone(),
            BackendKind::File,
            Redactor::default(),
        )
        .unwrap();
        let second = SecretStore::open_with_lease(
            store.owner().clone(),
            BackendKind::File,
            Redactor::default(),
        )
        .unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let worker_barrier = barrier.clone();
        let writer = std::thread::spawn(move || {
            worker_barrier.wait();
            first.set("first", "fake-owned-first").unwrap();
            first
        });
        barrier.wait();
        second.set("second", "fake-owned-second").unwrap();
        let first = writer.join().unwrap();
        second.reload().unwrap();
        assert_eq!(second.list().unwrap(), ["first", "second"]);
        assert_eq!(second.get("first").unwrap().expose(), "fake-owned-first");
        assert_eq!(second.get("second").unwrap().expose(), "fake-owned-second");
        store.shutdown().await.unwrap();
        assert!(matches!(
            HomeLease::acquire(home),
            Err(OwnershipError::Busy)
        ));
        drop(first);
        assert!(matches!(
            HomeLease::acquire(home),
            Err(OwnershipError::Busy)
        ));
        drop(second);
        assert!(HomeLease::acquire(home).is_ok());
    });
}

#[tokio::test]
async fn file_mutations_share_store_ownership_without_reflocking_or_losing_updates() {
    let _fixture = PROCESS_FIXTURE.lock().await;
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    // Bound and reap the actual helper: the original independent directory
    // flock would block permanently while Store owns the same home inode.
    let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "owned_file_backend_fixture_process"])
        .env_clear()
        .env(CHILD_HOME, &home)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
    if result.is_err() {
        child.kill().await.unwrap();
    }
    let output = child.wait_with_output().await.unwrap();
    assert!(
        result.is_ok(),
        "file mutation deadlocked under Store's home ownership"
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let secrets = SecretStore::open(&home, BackendKind::File, Redactor::default()).unwrap();
    assert_eq!(secrets.list().unwrap(), ["first", "second"]);
}

#[test]
fn native_secret_store_retains_ownership_without_connecting_to_a_keyring() {
    let _fixture = PROCESS_FIXTURE.blocking_lock();
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    fictor::home::prepare(&home).unwrap();
    let owner = HomeLease::acquire(&home).unwrap();
    let secrets =
        SecretStore::open_with_lease(owner, BackendKind::Keyring, Redactor::default()).unwrap();
    assert!(matches!(
        HomeLease::acquire(&home),
        Err(OwnershipError::Busy)
    ));
    drop(secrets);
    assert!(HomeLease::acquire(&home).is_ok());
}

#[test]
fn owned_file_backend_refuses_a_replaced_home_before_mutation() {
    let _fixture = PROCESS_FIXTURE.blocking_lock();
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let original = root.path().join("original");
    fictor::home::prepare(&home).unwrap();
    let owner = HomeLease::acquire(&home).unwrap();
    let secrets =
        SecretStore::open_with_lease(owner, BackendKind::File, Redactor::default()).unwrap();
    secrets.set("first", "fake-original-value").unwrap();
    let before = std::fs::read(home.join("secrets.toml")).unwrap();
    std::fs::rename(&home, &original).unwrap();
    fictor::home::prepare(&home).unwrap();
    assert_eq!(
        secrets.set("second", "fake-replacement-value"),
        Err(SecretError::FileIo)
    );
    assert_eq!(secrets.remove("first"), Err(SecretError::FileIo));
    assert!(!home.join("secrets.toml").exists());
    assert_eq!(
        std::fs::read(original.join("secrets.toml")).unwrap(),
        before
    );
}
