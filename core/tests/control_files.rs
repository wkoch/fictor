use fictor::{
    config::{Config, ConfigError, DEFAULT_CONFIG},
    control_files::{ControlFiles, Failure},
    home,
};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::Path,
    process::Command,
};

fn fixture() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    // A fixture explicitly creates a new private home; production never repairs
    // an existing permissive directory or control source.
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    home::prepare(home.path()).unwrap();
    Config::create_if_missing(home.path()).unwrap();
    home
}

fn failure(error: ConfigError) -> Failure {
    match error {
        ConfigError::Control(error) => error.failure(),
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn boot_validates_both_controls_and_accepts_all_admitted_modes() {
    let home = fixture();
    for mode in [0o400, 0o600, 0o644, 0o404] {
        fs::set_permissions(
            home.path().join("config.toml"),
            fs::Permissions::from_mode(mode),
        )
        .unwrap();
        let instructions = home.path().join("AGENTS.md");
        if instructions.exists() {
            fs::remove_file(&instructions).unwrap();
        }
        fs::write(&instructions, "global instructions").unwrap();
        fs::set_permissions(&instructions, fs::Permissions::from_mode(mode)).unwrap();
        Config::load(home.path()).unwrap();
    }
    fs::set_permissions(
        home.path().join("AGENTS.md"),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    assert_eq!(
        failure(Config::load(home.path()).err().unwrap()),
        Failure::Unsafe
    );
    fs::remove_file(home.path().join("AGENTS.md")).unwrap();
    fs::write(home.path().join("AGENTS.md"), [0xff]).unwrap();
    assert_eq!(
        failure(Config::load(home.path()).err().unwrap()),
        Failure::Invalid
    );
    fs::remove_file(home.path().join("AGENTS.md")).unwrap();
    fs::remove_file(home.path().join("config.toml")).unwrap();
    assert_eq!(
        failure(Config::load(home.path()).err().unwrap()),
        Failure::Unreadable
    );
}

#[test]
fn init_and_doctor_leave_unsafe_links_and_their_targets_untouched() {
    let home = fixture();
    let external = tempfile::tempdir().unwrap();
    let target = external.path().join("workspace-source");
    fs::write(&target, DEFAULT_CONFIG).unwrap();
    let target_metadata = fs::metadata(&target).unwrap();
    for name in ["config.toml", "AGENTS.md"] {
        let path = home.path().join(name);
        if path.exists() {
            fs::remove_file(&path).unwrap();
        }
        for hard in [false, true] {
            if hard {
                fs::hard_link(&target, &path).unwrap();
            } else {
                symlink(&target, &path).unwrap();
            }
            assert_eq!(
                failure(Config::create_if_missing(home.path()).err().unwrap()),
                Failure::Unsafe
            );
            for command in ["init", "doctor"] {
                let output = Command::new(env!("CARGO_BIN_EXE_fictor"))
                    .arg(command)
                    .env("FICTOR_HOME", home.path())
                    .output()
                    .unwrap();
                assert!(!output.status.success());
                let diagnostic = format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(diagnostic.contains(name));
                assert!(diagnostic.contains("control_file:unsafe"));
                assert!(!diagnostic.contains(target.to_str().unwrap()));
            }
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert_eq!(metadata.file_type().is_symlink(), !hard);
            assert_eq!(fs::read_to_string(&target).unwrap(), DEFAULT_CONFIG);
            assert_eq!(
                fs::metadata(&target).unwrap().mode(),
                target_metadata.mode()
            );
            assert_eq!(fs::metadata(&target).unwrap().uid(), target_metadata.uid());
            fs::remove_file(&path).unwrap();
        }
        Config::create_if_missing(home.path()).unwrap();
    }
}

#[test]
fn init_accepts_a_home_alias_but_never_repairs_unsafe_home_permissions() {
    let home = fixture();
    let aliases = tempfile::tempdir().unwrap();
    let alias = aliases.path().join("home-alias");
    symlink(home.path(), &alias).unwrap();
    home::prepare(&alias).unwrap();
    Config::create_if_missing(&alias).unwrap();
    let controls = ControlFiles::open(&alias).unwrap();
    let other = fixture();
    fs::remove_file(&alias).unwrap();
    symlink(other.path(), &alias).unwrap();
    assert_eq!(controls.home(), home.path().canonicalize().unwrap());
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(home::prepare(home.path()).is_err());
    assert_eq!(fs::metadata(home.path()).unwrap().mode() & 0o7777, 0o755);
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn opaque_extension_strings_are_not_opened_or_reinterpreted() {
    let home = fixture();
    let path = home.path().join("config.toml");
    fs::write(&path, format!("{DEFAULT_CONFIG}\n[ext.client]\npath = '/unavailable/private-file'\nurl = 'https://not-contacted.invalid/control'\n")).unwrap();
    let section = Config::extension(home.path(), "client").unwrap();
    assert_eq!(section["path"].as_str(), Some("/unavailable/private-file"));
    assert_eq!(
        section["url"].as_str(),
        Some("https://not-contacted.invalid/control")
    );
    fs::write(&path, "[broken TOML content").unwrap();
    let error = Config::extension(home.path(), "client").unwrap_err();
    assert_eq!(failure(error), Failure::Invalid);
    assert!(
        !Config::load(Path::new("/this-home-does-not-exist"))
            .err()
            .unwrap()
            .to_string()
            .contains("/this-home")
    );
}
