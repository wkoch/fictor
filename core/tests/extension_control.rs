use fictor::installer::{
    control::{ControlError, set_enabled},
    lease::InstallerLease,
    lock::Lock,
};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::UnixListener,
    },
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{Mutex, MutexGuard},
};

// A parallel CLI fork briefly inherits other tests' flock descriptors until
// exec closes CLOEXEC fds. Keep those forks outside each fixture's lease lifetime.
// https://man7.org/linux/man-pages/man2/flock.2.html
static CONTROL_FIXTURES: Mutex<()> = Mutex::new(());

struct Fixture {
    _root: tempfile::TempDir,
    home: PathBuf,
    _serial: MutexGuard<'static, ()>,
}
impl Fixture {
    fn new() -> Self {
        let serial = CONTROL_FIXTURES.lock().unwrap();
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        fictor::home::prepare(&home).unwrap();
        let versions = [version(&home, "1.0.0", "a"), version(&home, "2.0.0", "b")];
        let mut other_version = versions[0].1.clone();
        other_version["path"] = format!("store/other/{}", versions[0].0).into();
        let lock = json!({"schema":1,"extensions":{
            "sample":{"enabled":true,"active":versions[1].0,"versions":{
                (versions[0].0.clone()):versions[0].1.clone(), (versions[1].0.clone()):versions[1].1.clone()
            }},
            "other":{"enabled":false,"active":versions[0].0,"versions":{(versions[0].0.clone()):other_version}}
        }});
        fs::create_dir_all(home.join("extensions/store/other").join(&versions[0].0)).unwrap();
        fs::write(
            home.join("extensions/lock.json"),
            serde_json::to_vec_pretty(&lock).unwrap(),
        )
        .unwrap();
        fs::set_permissions(
            home.join("extensions/lock.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        Lock::load(&home).unwrap();
        Self {
            _root: root,
            home,
            _serial: serial,
        }
    }
    fn path(&self) -> PathBuf {
        self.home.join("extensions/lock.json")
    }
    fn bytes(&self) -> Vec<u8> {
        fs::read(self.path()).unwrap()
    }
    fn value(&self) -> Value {
        serde_json::from_slice(&self.bytes()).unwrap()
    }
    fn cli(&self, action: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_fictor"))
            .env_clear()
            .env("FICTOR_HOME", &self.home)
            .args(["ext", action, "sample"])
            .output()
            .unwrap()
    }
}
fn version(home: &Path, version: &str, hex: &str) -> (String, Value) {
    let hash = format!("sha256:{}", hex.repeat(64));
    let key = format!("{version}-{}", hex.repeat(12));
    fs::create_dir_all(home.join("extensions/store/sample").join(&key)).unwrap();
    (
        key.clone(),
        json!({
            "version":version,"hash":hash,"path":format!("store/sample/{key}"),
            "source":{"kind":"local","path":"/preserved/source"},
            "approved":{"by":"user","at":"2026-10-18T12:00:00Z","approval_id":null},
            "overrides":{"permissions":{},"tools":{}},"privileges":[],
            "tools":[],"tools_hash":fictor::gateway::PinnedCatalog::new(vec![]).unwrap().hash(),
            "packages":[{"ecosystem":"npm","name":"preserved","version":"1.2.3"}],"audit":null
        }),
    )
}

#[test]
fn disable_and_enable_change_only_the_requested_flag_and_preserve_versions_and_metadata() {
    let fixture = Fixture::new();
    let original = fixture.value();
    let changed = set_enabled(&fixture.home, "sample", false).unwrap();
    assert!(changed.changed);
    assert!(!changed.enabled);
    let mut expected = original.clone();
    expected["extensions"]["sample"]["enabled"] = false.into();
    assert_eq!(fixture.value(), expected);
    assert_eq!(
        fs::metadata(fixture.path()).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    assert!(!fixture.home.join("fictor.db").exists());
    let changed = set_enabled(&fixture.home, "sample", true).unwrap();
    assert!(changed.changed && changed.enabled);
    assert_eq!(fixture.value(), original);

    let disabled = fixture.cli("disable");
    assert!(disabled.status.success(), "{:?}", disabled);
    assert_eq!(
        serde_json::from_slice::<Value>(&disabled.stdout).unwrap(),
        json!({"ext_id":"sample","enabled":false,"changed":true})
    );
    assert_eq!(fixture.value(), expected);
    let before_noop = fixture.bytes();
    let inode = fs::metadata(fixture.path()).unwrap().ino();
    let unchanged = fixture.cli("disable");
    assert!(unchanged.status.success(), "{:?}", unchanged);
    assert_eq!(
        serde_json::from_slice::<Value>(&unchanged.stdout).unwrap(),
        json!({"ext_id":"sample","enabled":false,"changed":false})
    );
    assert_eq!(fixture.bytes(), before_noop);
    assert_eq!(fs::metadata(fixture.path()).unwrap().ino(), inode);
    let enabled = fixture.cli("enable");
    assert!(enabled.status.success(), "{:?}", enabled);
    assert_eq!(
        serde_json::from_slice::<Value>(&enabled.stdout).unwrap(),
        json!({"ext_id":"sample","enabled":true,"changed":true})
    );
    assert_eq!(fixture.value(), original);
    assert!(!fixture.home.join("fictor.db").exists());
}

#[test]
fn unchanged_flag_is_a_validated_noop_and_missing_extension_does_not_create_a_lock() {
    let fixture = Fixture::new();
    let before = fixture.bytes();
    let inode = fs::metadata(fixture.path()).unwrap().ino();
    assert!(!set_enabled(&fixture.home, "sample", true).unwrap().changed);
    assert_eq!(fixture.bytes(), before);
    assert_eq!(fs::metadata(fixture.path()).unwrap().ino(), inode);
    assert!(matches!(
        set_enabled(&fixture.home, "missing", false),
        Err(ControlError::NotFound)
    ));
    assert_eq!(fixture.bytes(), before);
    fs::remove_file(fixture.path()).unwrap();
    assert!(matches!(
        set_enabled(&fixture.home, "sample", false),
        Err(ControlError::NotFound)
    ));
    assert!(!fixture.path().exists());
}

#[test]
fn another_installer_lease_excludes_control_before_lock_access() {
    let fixture = Fixture::new();
    let before = fixture.bytes();
    let lease = InstallerLease::acquire(&fixture.home).unwrap();
    assert!(matches!(
        set_enabled(&fixture.home, "sample", false),
        Err(ControlError::Admission(_))
    ));
    assert_eq!(fixture.bytes(), before);
    drop(lease);
    assert!(set_enabled(&fixture.home, "sample", false).unwrap().changed);
}

#[test]
fn admin_socket_or_any_admin_marker_refuses_control_before_parsing_the_lock() {
    let fixture = Fixture::new();
    fs::write(
        fixture.path(),
        b"invalid lock proves marker is checked first",
    )
    .unwrap();
    let before = fixture.bytes();
    let socket = fixture.home.join("run/admin.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    assert!(matches!(
        set_enabled(&fixture.home, "sample", false),
        Err(ControlError::ServerPresent)
    ));
    for action in ["enable", "disable"] {
        let result = fixture.cli(action);
        assert!(!result.status.success(), "{:?}", result);
        assert!(String::from_utf8_lossy(&result.stderr).contains("endpoint administrativo"));
        assert_eq!(fixture.bytes(), before);
    }
    drop(listener);
    fs::remove_file(&socket).unwrap();
    std::os::unix::fs::symlink("/nonexistent/admin-target", &socket).unwrap();
    assert!(matches!(
        set_enabled(&fixture.home, "sample", false),
        Err(ControlError::ServerPresent)
    ));
    assert_eq!(fixture.bytes(), before);
    fs::remove_file(&socket).unwrap();
    fs::write(&socket, b"stale marker").unwrap();
    assert!(matches!(
        set_enabled(&fixture.home, "sample", false),
        Err(ControlError::ServerPresent)
    ));
    assert_eq!(fixture.bytes(), before);
    fs::remove_file(&socket).unwrap();
    fs::create_dir(&socket).unwrap();
    assert!(matches!(
        set_enabled(&fixture.home, "sample", false),
        Err(ControlError::ServerPresent)
    ));
    assert_eq!(fixture.bytes(), before);
}

#[test]
fn invalid_lock_or_existing_writer_temporary_never_loses_the_previous_lock() {
    let fixture = Fixture::new();
    let before = fixture.bytes();
    let pending = fixture.home.join("extensions/lock.json.tmp");
    fs::write(&pending, b"another writer").unwrap();
    let result = set_enabled(&fixture.home, "sample", false);
    assert!(matches!(&result, Err(ControlError::Lock(_))), "{result:?}");
    assert_eq!(fixture.bytes(), before);
    assert_eq!(fs::read(&pending).unwrap(), b"another writer");
    fs::remove_file(pending).unwrap();
    fs::write(fixture.path(), b"{malformed").unwrap();
    let result = set_enabled(&fixture.home, "sample", false);
    assert!(matches!(&result, Err(ControlError::Lock(_))), "{result:?}");
    assert_eq!(fixture.bytes(), b"{malformed");
}

#[test]
fn symlinked_run_directory_is_not_followed() {
    let fixture = Fixture::new();
    fs::remove_dir(fixture.home.join("run/k")).unwrap();
    fs::remove_dir(fixture.home.join("run")).unwrap();
    let external = fixture._root.path().join("external");
    fs::create_dir(&external).unwrap();
    std::os::unix::fs::symlink(&external, fixture.home.join("run")).unwrap();
    let before = fixture.bytes();
    assert!(set_enabled(&fixture.home, "sample", false).is_err());
    assert_eq!(fixture.bytes(), before);
    assert_eq!(fs::read_dir(external).unwrap().count(), 0);
}
