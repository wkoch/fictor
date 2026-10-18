use fictor::{
    config::{Config, DEFAULT_CONFIG},
    home,
    store::Store,
};
use rusqlite::Connection;
use std::{fs, path::PathBuf, process::Command};
use tempfile::tempdir;

#[tokio::test]
async fn init_is_idempotent_and_preserves_configuration() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("fictor");
    fictor::initialize(&home).await.unwrap();
    let custom = DEFAULT_CONFIG.replace("idle_timeout_min = 30", "idle_timeout_min = 7");
    fs::write(home.join("config.toml"), &custom).unwrap();
    fictor::initialize(&home).await.unwrap();
    assert_eq!(
        fs::read_to_string(home.join("config.toml")).unwrap(),
        custom
    );
    let db = Connection::open(home.join("fictor.db")).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM sessions WHERE id='sys' AND kind='system'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        db.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        5
    );
    assert_eq!(
        db.pragma_query_value(None, "journal_mode", |r| r.get::<_, String>(0))
            .unwrap(),
        "wal"
    );
    for relative in [
        "blobs",
        "extensions/store",
        "extensions/quarantine",
        "extensions/data",
        "run/k",
        "logs/ext",
    ] {
        assert!(home.join(relative).is_dir());
    }
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&home, &home.join("run")] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        for name in ["config.toml", "fictor.db"] {
            assert_eq!(
                fs::metadata(home.join(name)).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}

#[test]
fn home_resolution_uses_xdg_and_linux_defaults() {
    let user = Some(PathBuf::from("/users/test"));
    assert_eq!(
        home::resolve_with(None, user.clone(), None).unwrap(),
        PathBuf::from("/users/test/.local/share/fictor")
    );
    assert_eq!(
        home::resolve_with(None, user.clone(), Some("/data".into())).unwrap(),
        PathBuf::from("/data/fictor")
    );
    assert_eq!(
        home::resolve_with(None, user.clone(), Some("relative".into())).unwrap(),
        PathBuf::from("/users/test/.local/share/fictor")
    );
    assert_eq!(
        home::resolve_with(Some("/override".into()), None, None).unwrap(),
        PathBuf::from("/override")
    );
    assert!(home::resolve_with(None, None, None).is_err());
    assert_eq!(
        home::resolve_with(None, None, Some("/xdg".into())).unwrap(),
        PathBuf::from("/xdg/fictor")
    );
    assert!(home::resolve_with(Some("".into()), user, None).is_err());
}

#[test]
fn config_rejects_exposed_listener_and_invalid_modes_without_echoing_input() {
    for address in [
        "0.0.0.0:7350",
        "192.168.1.2:7350",
        "[::1]:7350",
        "127.0.0.1:0",
        "127.0.0.1:7351",
    ] {
        assert!(Config::parse(&DEFAULT_CONFIG.replace("127.0.0.1:7350", address)).is_err());
    }
    let malformed = DEFAULT_CONFIG.replace(
        "default_mode = \"default\"",
        "default_mode = \"secret-test-value\"",
    );
    let error = Config::parse(&malformed).err().unwrap().to_string();
    assert!(!error.contains("secret-test-value"));
    let config = Config::parse(DEFAULT_CONFIG).unwrap();
    assert_eq!(
        config.ext["harness"]["default_model"].as_str(),
        Some("main")
    );
}

#[tokio::test]
async fn migrations_match_spec_and_protect_events() {
    assert_eq!(
        include_str!("../migrations/0001_init.sql"),
        include_str!("../../spec/schemas/0001_init.sql")
    );
    assert_eq!(
        include_str!("../migrations/0002_flow_budget.sql"),
        include_str!("../../spec/schemas/0002_flow_budget.sql")
    );
    assert_eq!(
        include_str!("../migrations/0003_proposal_receipts.sql"),
        include_str!("../../spec/schemas/0003_proposal_receipts.sql")
    );
    assert_eq!(
        include_str!("../migrations/0004_promotion_journal.sql"),
        include_str!("../../spec/schemas/0004_promotion_journal.sql")
    );
    assert_eq!(
        include_str!("../migrations/0005_crash_recovery.sql"),
        include_str!("../../spec/schemas/0005_crash_recovery.sql")
    );
    let dir = tempdir().unwrap();
    fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    fictor::initialize(dir.path()).await.unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    store.write(|db| {
        assert_eq!(db.pragma_query_value(None, "foreign_keys", |r| r.get::<_, i64>(0))?, 1);
        assert_eq!(db.pragma_query_value(None, "busy_timeout", |r| r.get::<_, i64>(0))?, 5000);
        assert_eq!(db.pragma_query_value(None, "synchronous", |r| r.get::<_, i64>(0))?, 2);
        db.execute("INSERT INTO events (id, session_id, kind, actor, payload, trust, sensitivity, text, created_at) VALUES ('test', 'sys', 'test', 'core', '{}', 'trusted', 'public', 'bootstrap', 0)", [])?;
        assert!(db.execute("UPDATE events SET text='changed' WHERE id='test'", []).is_err());
        assert!(db.execute("DELETE FROM events WHERE id='test'", []).is_err());
        assert_eq!(db.query_row("SELECT count(*) FROM events_fts WHERE events_fts MATCH 'bootstrap'", [], |r| r.get::<_, i64>(0))?, 1);
        Ok(())
    }).await.unwrap();
    store.shutdown().await.unwrap();
}

#[test]
fn cli_receipt_failures_report_durable_id_and_safe_reason() {
    let root = tempdir().unwrap();
    let home = root.path().join("core");
    let real = root.path().join("user");
    let source = root.path().join("private-source");
    fs::create_dir(&real).unwrap();
    fs::create_dir(&source).unwrap();
    fs::write(source.join("private.txt"), b"never-include-this-content").unwrap();
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_fictor"));
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &real)
            .env("FICTOR_HOME", &home);
        command
    };
    assert!(command().arg("init").output().unwrap().status.success());
    let config = home.join("config.toml");
    let text = fs::read_to_string(&config)
        .unwrap()
        .replace("backend = \"keyring\"", "backend = \"file\"");
    fs::write(config, text).unwrap();
    let output = command()
        .args(["ext", "check"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let db = Connection::open(home.join("fictor.db")).unwrap();
    let id: String = db
        .query_row(
            "SELECT id FROM proposals WHERE state='failed' AND ext_id IS NULL AND version IS NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains(&id));
    assert!(error.contains("manifest:missing"));
    assert!(!error.contains(source.to_str().unwrap()));
    assert!(!error.contains("never-include-this-content"));
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM events WHERE kind IN ('ext.proposed','ext.failed')",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        2
    );
    drop(db);
    assert!(command().arg("init").output().unwrap().status.success());
    let db = Connection::open(home.join("fictor.db")).unwrap();
    assert_eq!(
        db.query_row("SELECT id FROM proposals WHERE state='failed'", [], |row| {
            row.get::<_, String>(0)
        })
        .unwrap(),
        id
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM events WHERE kind='ext.failed'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
}

#[test]
fn cli_terminal_persistence_error_reports_id_without_claiming_audited_failure() {
    let root = tempdir().unwrap();
    let home = root.path().join("core");
    let real = root.path().join("user");
    let source = root.path().join("source");
    fs::create_dir(&real).unwrap();
    fs::create_dir(&source).unwrap();
    fs::write(source.join("copy.txt"), b"retain after failed commit").unwrap();
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_fictor"));
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &real)
            .env("FICTOR_HOME", &home);
        command
    };
    assert!(command().arg("init").output().unwrap().status.success());
    let config = home.join("config.toml");
    let text = fs::read_to_string(&config)
        .unwrap()
        .replace("backend = \"keyring\"", "backend = \"file\"");
    fs::write(config, text).unwrap();
    let db = Connection::open(home.join("fictor.db")).unwrap();
    db.execute_batch("CREATE TRIGGER refuse_failure BEFORE INSERT ON events WHEN new.kind='ext.failed' BEGIN SELECT RAISE(ABORT,'injected failure'); END;").unwrap();
    drop(db);
    let output = command()
        .args(["ext", "check"])
        .arg(source)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let db = Connection::open(home.join("fictor.db")).unwrap();
    let id: String = db
        .query_row(
            "SELECT id FROM proposals WHERE state='received'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains(&id));
    assert!(error.contains("transição não confirmada"));
    assert!(!error.contains("manifest:missing"));
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM events WHERE kind='ext.failed'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert!(
        home.join("extensions/quarantine")
            .join(format!(".receipt-{id}"))
            .join("copy.txt")
            .exists()
    );
}

#[tokio::test]
async fn future_schema_is_refused() {
    let dir = tempdir().unwrap();
    let db = Connection::open(dir.path().join("fictor.db")).unwrap();
    db.pragma_update(None, "user_version", 999).unwrap();
    drop(db);
    fs::create_dir(dir.path().join("blobs")).unwrap();
    let future_capture = dir.path().join("blobs/.model-capture-future");
    fs::write(&future_capture, b"future-core-data").unwrap();
    assert!(matches!(
        Store::open(dir.path()).await,
        Err(fictor::store::StoreError::NewerSchema(999))
    ));
    assert_eq!(fs::read(future_capture).unwrap(), b"future-core-data");
}

#[test]
fn cli_init_and_unsupported_install_are_honest() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("data");
    let output = Command::new(env!("CARGO_BIN_EXE_fictor"))
        .env("FICTOR_HOME", &home)
        .args(["init", "--first-party", "."])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!home.exists());
    let output = Command::new(env!("CARGO_BIN_EXE_fictor"))
        .env("FICTOR_HOME", &home)
        .arg("init")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(home.join("fictor.db").exists());
}

#[test]
fn doctor_reports_development_runtime_status_without_modifying_config() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("data");
    home::prepare(&home).unwrap();
    Config::create_if_missing(&home).unwrap();
    let original = fs::read(home.join("config.toml")).unwrap();
    let report = fictor::doctor::inspect_local(&home);
    assert!(
        report
            .iter()
            .any(|check| check.name == "node" && check.detail.contains("M0.9"))
    );
    assert!(report.iter().any(|check| check.name == "keyring/segredos"));
    assert_eq!(fs::read(home.join("config.toml")).unwrap(), original);
}

#[test]
fn runtime_sources_match_the_spec_and_reject_legacy_executable_overrides() {
    use fictor::config::RuntimeSource;
    let config = Config::parse(DEFAULT_CONFIG).unwrap();
    assert_eq!(
        config.runtimes["node"],
        RuntimeSource::Nodejs {
            channel: "lts".into()
        }
    );
    assert!(matches!(
        config.runtimes["uv"],
        RuntimeSource::GithubRelease { .. }
    ));
    for replacement in [
        "source = \"nodejs\"\nchannel = \"current\"",
        "source = \"nodejs\"\nchannel = \"lts\"\nbin = \"/tmp/node\"",
        "source = \"unknown\"\nchannel = \"lts\"",
    ] {
        assert!(
            Config::parse(
                &DEFAULT_CONFIG.replace("source = \"nodejs\"\nchannel = \"lts\"", replacement)
            )
            .is_err()
        );
    }
    assert!(Config::parse(&DEFAULT_CONFIG.replace(
        "[runtimes.node]                  # fonte; instalação/ativação gerenciada entra no M0.9\nsource = \"nodejs\"\nchannel = \"lts\"",
        "[runtimes]\nnode = \"/tmp/node\""
    )).is_err());
    assert!(
        Config::parse(&format!(
            "{DEFAULT_CONFIG}\n[sandbox.toolchains]\nmounts = [\"~/.rustup\"]\n"
        ))
        .is_err()
    );
}

#[test]
fn secrets_cli_never_accepts_or_echoes_secret_values_in_arguments() {
    let result = Command::new(env!("CARGO_BIN_EXE_fictor"))
        .args(["secrets", "set", "provider", "fake-sensitive-argv-value"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!String::from_utf8_lossy(&result.stdout).contains("fake-sensitive-argv-value"));
    assert!(!String::from_utf8_lossy(&result.stderr).contains("fake-sensitive-argv-value"));
    let help = Command::new(env!("CARGO_BIN_EXE_fictor"))
        .args(["secrets", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("list"));
}

#[tokio::test]
async fn init_refuses_symlinked_private_directories() {
    use std::os::unix::fs::symlink;
    let root = tempdir().unwrap();
    let home = root.path().join("data");
    let elsewhere = root.path().join("elsewhere");
    fs::create_dir(&home).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::create_dir(&elsewhere).unwrap();
    symlink(&elsewhere, home.join("extensions")).unwrap();
    assert!(fictor::initialize(&home).await.is_err());
    assert!(!home.join("fictor.db").exists());
    assert!(fs::read_dir(&elsewhere).unwrap().next().is_none());
}

#[test]
fn extension_config_reload_is_bound_to_the_authenticated_extension_table() {
    let dir = tempfile::tempdir().unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[ext.first]\nvalue = 1\n[ext.second]\nprivate = 'sibling-config'\n",
    )
    .unwrap();
    let first = Config::extension(dir.path(), "first").unwrap();
    assert_eq!(first["value"].as_integer(), Some(1));
    assert!(!first.contains_key("private"));
    std::fs::write(&path, "[ext.first]\nvalue = 2\n").unwrap();
    assert_eq!(
        Config::extension(dir.path(), "first").unwrap()["value"].as_integer(),
        Some(2)
    );
    assert!(Config::extension(dir.path(), "second").unwrap().is_empty());
    std::fs::write(&path, "[ext.first]\nvalue = invalid-sensitive-input\n").unwrap();
    let error = Config::extension(dir.path(), "first").unwrap_err();
    assert!(!format!("{error:?}: {error}").contains("invalid-sensitive-input"));
}
