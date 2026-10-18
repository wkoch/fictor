use fictor::{
    ownership::{HomeLease, OwnershipError},
    store::{Store, StoreError},
};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    process::Command,
    sync::Arc,
};

// Fork briefly inherits even CLOEXEC descriptors before exec. Serialize
// launches with lifetime assertions so a sibling test cannot retain a lease.
static PROCESS_FIXTURE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn private_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    home
}

#[test]
fn inode_aliases_compete_without_mutating_the_home() {
    let _fixture = PROCESS_FIXTURE.blocking_lock();
    let home = private_home();
    let aliases = tempfile::tempdir().unwrap();
    let alias = aliases.path().join("alias");
    symlink(home.path(), &alias).unwrap();
    let owner = HomeLease::acquire(&alias).unwrap();
    assert_eq!(owner.home(), home.path().canonicalize().unwrap());
    assert!(ulid::Ulid::from_string(owner.owner_id()).is_ok());
    assert!(matches!(
        HomeLease::acquire(home.path()),
        Err(OwnershipError::Busy)
    ));
    assert!(matches!(
        HomeLease::acquire(&alias),
        Err(OwnershipError::Busy)
    ));
    assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
    drop(owner);
    let next = HomeLease::acquire(home.path()).unwrap();
    assert_eq!(next.home(), home.path().canonicalize().unwrap());
}

#[test]
fn home_bind_alias_helper() {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let Some(home) = std::env::var_os("FICTOR_TEST_OWNERSHIP_HOME") else {
        return;
    };
    let alias = std::env::var_os("FICTOR_TEST_OWNERSHIP_ALIAS").unwrap();
    let source = CString::new(home.as_bytes()).unwrap();
    let destination = CString::new(alias.as_bytes()).unwrap();
    // SAFETY: both are live C strings naming only this test's private empty
    // directories. The caller created a private mount namespace beforehand.
    let status = unsafe {
        libc::mount(
            source.as_ptr(),
            destination.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    assert_eq!(status, 0, "{}", std::io::Error::last_os_error());
    assert!(matches!(
        HomeLease::acquire(std::path::Path::new(&alias)),
        Err(OwnershipError::Busy)
    ));
}

#[test]
fn a_bind_alias_in_a_private_namespace_competes_for_the_same_inode() {
    let _fixture = PROCESS_FIXTURE.blocking_lock();
    let home = private_home();
    let alias = private_home();
    let _owner = HomeLease::acquire(home.path()).unwrap();
    let result = Command::new("/usr/bin/unshare")
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--propagation",
            "private",
            "--",
        ])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "home_bind_alias_helper", "--nocapture"])
        .env_clear()
        .env("FICTOR_TEST_OWNERSHIP_HOME", home.path())
        .env("FICTOR_TEST_OWNERSHIP_ALIAS", alias.path())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{} {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read_dir(alias.path()).unwrap().count(), 0);
}

#[test]
fn insecure_homes_are_refused_without_repair_or_children() {
    let _fixture = PROCESS_FIXTURE.blocking_lock();
    let home = private_home();
    for mode in [0o755, 0o770, 0o1700] {
        fs::set_permissions(home.path(), fs::Permissions::from_mode(mode)).unwrap();
        assert!(matches!(
            HomeLease::create_for_init(home.path()),
            Err(OwnershipError::Unsafe)
        ));
        assert_eq!(
            fs::metadata(home.path()).unwrap().permissions().mode() & 0o7777,
            mode
        );
        assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
    }
}

#[test]
fn an_active_owner_blocks_offline_cli_before_config_or_database_writes() {
    let _fixture = PROCESS_FIXTURE.blocking_lock();
    let home = private_home();
    let _owner = HomeLease::acquire(home.path()).unwrap();
    for args in [
        vec!["init"],
        vec!["ext", "enable", "sample"],
        vec!["ext", "disable", "sample"],
        vec!["secrets", "list"],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_fictor"))
            .args(args)
            .env_clear()
            .env("FICTOR_HOME", home.path())
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("FICTOR_HOME ocupado"),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
    }
}

#[tokio::test]
async fn a_shared_home_owner_still_allows_only_one_database_writer() {
    let _fixture = PROCESS_FIXTURE.lock().await;
    let home = private_home();
    let owner = HomeLease::acquire(home.path()).unwrap();
    let first = Store::open_with_lease(owner.clone()).await.unwrap();
    assert!(matches!(
        Store::open_with_lease(owner.clone()).await,
        Err(StoreError::Ownership(OwnershipError::Busy))
    ));
    first.shutdown().await.unwrap();
    Store::open_with_lease(owner.clone())
        .await
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    assert!(matches!(
        HomeLease::acquire(home.path()),
        Err(OwnershipError::Busy)
    ));
    drop(owner);
    drop(HomeLease::acquire(home.path()).unwrap());
}

#[tokio::test]
async fn a_live_capture_retains_global_ownership_after_store_shutdown() {
    let _fixture = PROCESS_FIXTURE.lock().await;
    let home = private_home();
    let store = Store::open(home.path()).await.unwrap();
    let mut capture = store.begin_capture().unwrap();
    capture.append(b"unfinished").unwrap();
    store.shutdown().await.unwrap();
    assert!(matches!(
        Store::open(home.path()).await,
        Err(StoreError::Ownership(OwnershipError::Busy))
    ));
    drop(capture);
    Store::open(home.path())
        .await
        .unwrap()
        .shutdown()
        .await
        .unwrap();
}

#[tokio::test]
async fn cancelled_waiter_keeps_ownership_until_its_writer_job_finishes() {
    let _fixture = PROCESS_FIXTURE.lock().await;
    let home = private_home();
    let store = Arc::new(Store::open(home.path()).await.unwrap());
    let (started, entered) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let waiter_store = store.clone();
    let waiter = tokio::spawn(async move {
        waiter_store.write(move |db| {
            started.send(()).unwrap();
            released.recv().unwrap();
            db.execute("INSERT INTO kv(ns,key,value,updated_at) VALUES('ownership','completed','true',0)", [])?;
            Ok(())
        }).await
    });
    entered.await.unwrap();
    waiter.abort();
    let _ = waiter.await;
    drop(store);
    assert!(matches!(
        HomeLease::acquire(home.path()),
        Err(OwnershipError::Busy)
    ));
    release.send(()).unwrap();
    // Wait for the OS lock to be released, bounded by Tokio's timeout. No
    // assumption about how quickly the detached blocking worker is scheduled.
    let owner = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match HomeLease::acquire(home.path()) {
                Ok(owner) => break owner,
                Err(OwnershipError::Busy) => tokio::task::yield_now().await,
                Err(error) => panic!("{error}"),
            }
        }
    })
    .await
    .unwrap();
    let store = Store::open_with_lease(owner).await.unwrap();
    assert_eq!(
        store
            .kv_get("ownership".into(), "completed".into())
            .await
            .unwrap(),
        Some(serde_json::json!(true))
    );
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_replaced_home_cannot_reuse_a_previous_owner() {
    let _fixture = PROCESS_FIXTURE.lock().await;
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let owner = HomeLease::create_for_init(&home).unwrap();
    fs::rename(&home, root.path().join("previous")).unwrap();
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        Store::open_with_lease(owner).await,
        Err(StoreError::Ownership(OwnershipError::Changed))
    ));
    assert_eq!(fs::read_dir(home).unwrap().count(), 0);
}
