use fictor::sandbox::{ProxyEndpoint, SandboxContext, SandboxPlan, SandboxProfile, Tier};
use std::{
    collections::BTreeMap,
    os::unix::{fs::symlink, net::UnixListener},
    path::PathBuf,
    process::Command,
};

struct Fixture {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    _proxy: UnixListener,
}
impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        for path in [
            "core/extensions/store/test/0.1-hash",
            "core/extensions/data/test",
            "core/run/k",
            "user/.ssh",
            "instance",
            "workspace",
            "outside",
        ] {
            std::fs::create_dir_all(root.join(path)).unwrap();
        }
        for (path, data) in [
            (
                "core/extensions/store/test/0.1-hash/code.txt",
                "promoted code",
            ),
            ("core/config.toml", "core private config"),
            ("user/.ssh/id_rsa", "fake-private-key"),
            ("user/.gitconfig", "read-only-config"),
            ("workspace/input.txt", "workspace input"),
            ("outside/secret.txt", "outside private"),
        ] {
            std::fs::write(root.join(path), data).unwrap();
        }
        let proxy = UnixListener::bind(root.join("core/run/proxy.sock")).unwrap();
        Self {
            _temporary: temporary,
            root,
            _proxy: proxy,
        }
    }
    fn context(&self) -> SandboxContext {
        let runtime = std::env::current_exe().unwrap().canonicalize().unwrap();
        SandboxContext {
            fictor_home: self.root.join("core"),
            real_home: self.root.join("user"),
            bundle_root: self.root.join("core/extensions/store/test/0.1-hash"),
            ext_data: self.root.join("core/extensions/data/test"),
            tmp_dir: self.root.join("instance"),
            runtime_root: runtime.parent().unwrap().into(),
            runtime,
            fictor_exe: PathBuf::from(env!("CARGO_BIN_EXE_fictor"))
                .canonicalize()
                .unwrap(),
            home_ro_files: vec![self.root.join("user/.gitconfig")],
            allow_store_read: false,
        }
    }
    fn profile(&self) -> SandboxProfile {
        SandboxProfile {
            read_paths: vec![],
            write_paths: vec![self.root.join("workspace")],
            spawn: false,
            kernel_socket: None,
            proxy: ProxyEndpoint::Unix(self.root.join("core/run/proxy.sock")),
            env: BTreeMap::new(),
            cwd: self.root.join("workspace"),
            tier: Tier::Os,
        }
    }
}

#[test]
fn ordinary_profile_keeps_the_explicit_private_mount_exceptions() {
    let fixture = Fixture::new();
    let _plan = SandboxPlan::new(fixture.profile(), fixture.context(), vec![]).unwrap();
}

#[test]
fn profile_validation_rejects_root_home_core_and_writable_code() {
    let fixture = Fixture::new();
    for path in [
        "/".into(),
        fixture.root.join("user"),
        fixture.root.join("core"),
        fixture.root.join("core/config.toml"),
        fixture.root.join("core/run"),
        fixture.root.clone(),
    ] {
        let mut profile = fixture.profile();
        profile.read_paths.push(path);
        assert!(SandboxPlan::new(profile, fixture.context(), vec![]).is_err());
    }
    for path in [
        fixture.root.join("core/extensions/store/test/0.1-hash"),
        std::env::current_exe().unwrap().parent().unwrap().into(),
        fixture.root.join("user/.gitconfig"),
    ] {
        let mut profile = fixture.profile();
        profile.write_paths.push(path);
        assert!(SandboxPlan::new(profile, fixture.context(), vec![]).is_err());
    }
    let mut context = fixture.context();
    context.bundle_root = fixture.root.join("outside");
    assert!(SandboxPlan::new(fixture.profile(), context, vec![]).is_err());
    let mut profile = fixture.profile();
    profile.proxy = ProxyEndpoint::Unix(fixture.root.join("core/config.toml"));
    assert!(SandboxPlan::new(profile, fixture.context(), vec![]).is_err());
}

#[test]
fn grant_symlink_escape_is_rejected() {
    let fixture = Fixture::new();
    symlink(
        fixture.root.join("outside"),
        fixture.root.join("workspace/escape"),
    )
    .unwrap();
    let mut profile = fixture.profile();
    profile
        .read_paths
        .push(fixture.root.join("workspace/escape/secret.txt"));
    assert!(SandboxPlan::new(profile, fixture.context(), vec![]).is_err());
}

#[test]
fn implicit_roots_cannot_reveal_store_symlinks_or_make_core_binary_writable() {
    let fixture = Fixture::new();
    let mut context = fixture.context();
    let fake_binary = fixture.root.join("instance/fictor");
    std::fs::write(&fake_binary, "binary").unwrap();
    context.fictor_exe = fake_binary;
    assert!(SandboxPlan::new(fixture.profile(), context, vec![]).is_err());

    let quarantine = fixture.root.join("core/extensions/quarantine/proposal");
    std::fs::create_dir_all(&quarantine).unwrap();
    std::fs::rename(
        fixture.root.join("core/extensions/store"),
        fixture.root.join("core/extensions/store-old"),
    )
    .unwrap();
    symlink(
        fixture.root.join("user"),
        fixture.root.join("core/extensions/store"),
    )
    .unwrap();
    let mut context = fixture.context();
    context.bundle_root = quarantine;
    context.allow_store_read = true;
    assert!(SandboxPlan::new(fixture.profile(), context, vec![]).is_err());
}

#[test]
fn gpg_agent_directory_is_denied_without_relying_on_legacy_environment() {
    let fixture = Fixture::new();
    let directory = fixture.root.join("user/.gnupg");
    std::fs::create_dir(&directory).unwrap();
    let mut profile = fixture.profile();
    profile.read_paths.push(directory);
    assert!(SandboxPlan::new(profile, fixture.context(), vec![]).is_err());
}

#[test]
fn sandbox_init_is_hidden_and_refuses_host_execution() {
    let binary = env!("CARGO_BIN_EXE_fictor");
    let help = Command::new(binary).arg("--help").output().unwrap();
    assert!(!String::from_utf8_lossy(&help.stdout).contains("__sandbox-init"));
    let output = Command::new(binary)
        .env_remove("HOME")
        .env_remove("FICTOR_HOME")
        .args([
            "__sandbox-init",
            "--mount-proof",
            "{}",
            "--",
            "/usr/bin/true",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("HOME não definido"));
}

mod receipt_mount_cleanup {
    use fictor::{
        installer::{
            lease::InstallerLease,
            recovery::{self, DiagnosticCode},
        },
        store::{NewProposal, ProposalState as State, Store},
    };
    use serde_json::json;
    use std::{
        fs,
        path::{Path, PathBuf},
        process::Command,
        sync::Arc,
    };
    async fn fixture() -> (tempfile::TempDir, Arc<Store>) {
        let home = tempfile::Builder::new()
            .prefix("fx-mount-")
            .tempdir_in("/tmp")
            .unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fictor::home::prepare(home.path()).unwrap();
        let store = Arc::new(Store::open(home.path()).await.unwrap());
        (home, store)
    }
    async fn begin(store: &Store) -> String {
        store
            .begin_attempt(NewProposal {
                source: json!({"kind":"local"}),
                tainted: false,
            })
            .await
            .unwrap()
            .id
    }
    fn receipt(home: &Path, id: &str) -> PathBuf {
        home.join("extensions/quarantine")
            .join(format!(".receipt-{id}"))
    }
    async fn recover(
        home: &Path,
        store: Arc<Store>,
    ) -> Result<recovery::RecoveryReport, recovery::RecoveryError> {
        let lease = Arc::new(InstallerLease::acquire(home).unwrap());
        recovery::recover(home, store, lease).await
    }
    #[test]
    fn cleanup_stops_at_bind_mounts_even_on_the_same_filesystem() {
        let status = Command::new("/usr/bin/unshare")
            .args([
                "--user",
                "--map-root-user",
                "--mount",
                "--propagation",
                "private",
            ])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "receipt_mount_cleanup::bind_mount_subprocess",
                "--nocapture",
            ])
            .env("FICTOR_TEST_RECOVERY_MOUNT", "1")
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[tokio::test]
    async fn bind_mount_subprocess() {
        if std::env::var_os("FICTOR_TEST_RECOVERY_MOUNT").is_none() {
            return;
        }
        let (home, store) = fixture().await;
        let id = begin(&store).await;
        let temporary = receipt(home.path(), &id);
        let mountpoint = temporary.join("mounted");
        fs::create_dir_all(&mountpoint).unwrap();
        let external = tempfile::tempdir().unwrap();
        fs::write(external.path().join("keep"), "mounted external bytes").unwrap();
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let source = CString::new(external.path().as_os_str().as_bytes()).unwrap();
        let destination = CString::new(mountpoint.as_os_str().as_bytes()).unwrap();
        // SAFETY: this opt-in subprocess owns a private mount/user namespace and
        // both NUL-terminated paths point to its disposable fixture directories.
        assert_eq!(
            unsafe {
                libc::mount(
                    source.as_ptr(),
                    destination.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            },
            0
        );
        let report = recover(home.path(), store.clone()).await.unwrap();
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.code == DiagnosticCode::CleanupFailed)
        );
        assert_eq!(store.proposal(id).await.unwrap().state, State::Failed);
        assert_eq!(
            fs::read_to_string(external.path().join("keep")).unwrap(),
            "mounted external bytes"
        );
        // SAFETY: destination identifies exactly the private bind mount above.
        assert_eq!(
            unsafe { libc::umount2(destination.as_ptr(), libc::MNT_DETACH) },
            0
        );
        assert!(
            recover(home.path(), store)
                .await
                .unwrap()
                .diagnostics
                .is_empty()
        );
        assert!(!temporary.exists());
    }
}

mod private_mount_aliases {
    use super::*;
    use std::{ffi::CString, fs, os::unix::ffi::OsStrExt, path::Path};

    #[test]
    fn grants_reject_private_bind_aliases_and_submounts_without_masking_them() {
        for scenario in [
            "home",
            "ancestor",
            "file",
            "submount",
            "data-submount",
            "system-base",
            "home-mount",
            "own-data-filesystem",
        ] {
            let output = Command::new("/usr/bin/unshare")
                .args([
                    "--user",
                    "--map-root-user",
                    "--mount",
                    "--propagation",
                    "private",
                ])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "private_mount_aliases::mount_namespace_subprocess",
                    "--nocapture",
                ])
                .env("FICTOR_TEST_PRIVATE_MOUNT", scenario)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{scenario}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    fn bind(source: &Path, destination: &Path) {
        let source = CString::new(source.as_os_str().as_bytes()).unwrap();
        let destination = CString::new(destination.as_os_str().as_bytes()).unwrap();
        // SAFETY: this opt-in subprocess owns its mount/user namespace. Both
        // paths are live fixture objects; the mount never changes the host tree.
        assert_eq!(
            unsafe {
                libc::mount(
                    source.as_ptr(),
                    destination.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            },
            0,
            "{}",
            std::io::Error::last_os_error()
        );
    }

    #[test]
    fn mount_namespace_subprocess() {
        let Some(scenario) = std::env::var_os("FICTOR_TEST_PRIVATE_MOUNT") else {
            return;
        };
        let fixture = Fixture::new();
        let home = fixture.root.join("core");
        let workspace = fixture.root.join("workspace");
        let mut context = fixture.context();
        let mut profile = fixture.profile();
        let scenario = scenario.to_str().unwrap();
        match scenario {
            "home" | "ancestor" => {
                let alias = fixture.root.join("outside/alias");
                fs::create_dir(&alias).unwrap();
                bind(
                    if scenario == "home" {
                        &home
                    } else {
                        &fixture.root
                    },
                    &alias,
                );
                profile.read_paths.push(alias);
            }
            "file" => {
                bind(&home.join("config.toml"), &workspace.join("input.txt"));
                profile.read_paths.push(workspace.join("input.txt"));
            }
            "submount" => {
                let alias = workspace.join("nested");
                fs::create_dir(&alias).unwrap();
                bind(&home, &alias);
            }
            "data-submount" => {
                let alias = context.ext_data.join("nested");
                fs::create_dir(&alias).unwrap();
                bind(&home, &alias);
            }
            "system-base" => bind(&home, Path::new("/etc/ssl")),
            "home-mount" => {
                let alias = fixture.root.join("outside/core-mount");
                fs::create_dir(&alias).unwrap();
                bind(&home, &alias);
                context.fictor_home = alias.clone();
                context.bundle_root = alias.join("extensions/store/test/0.1-hash");
                context.ext_data = alias.join("extensions/data/test");
                context.allow_store_read = true;
                profile.proxy = ProxyEndpoint::Unix(alias.join("run/proxy.sock"));
            }
            "own-data-filesystem" => {
                let destination = CString::new(context.ext_data.as_os_str().as_bytes()).unwrap();
                // SAFETY: a fresh tmpfs is mounted only on this private fixture
                // in the subprocess namespace, without changing host mounts.
                assert_eq!(
                    unsafe {
                        libc::mount(
                            c"tmpfs".as_ptr(),
                            destination.as_ptr(),
                            c"tmpfs".as_ptr(),
                            0,
                            std::ptr::null(),
                        )
                    },
                    0,
                    "{}",
                    std::io::Error::last_os_error()
                );
                profile.write_paths.push(context.ext_data.clone());
            }
            _ => panic!("unknown test scenario"),
        }
        let expected = matches!(scenario, "home-mount" | "own-data-filesystem");
        let result = SandboxPlan::new(profile, context, vec![]);
        assert_eq!(
            result.is_ok(),
            expected,
            "{scenario}: {}",
            result
                .err()
                .map(|error| error.to_string())
                .unwrap_or_default()
        );
        if scenario == "home" {
            // Protect the directory identity even before an optional control
            // exists: creating it must not make the same grant admissible.
            assert!(!home.join("AGENTS.md").exists());
            fs::write(home.join("AGENTS.md"), "new global instructions").unwrap();
            let mut profile = fixture.profile();
            profile.read_paths.push(fixture.root.join("outside/alias"));
            assert!(SandboxPlan::new(profile, fixture.context(), vec![]).is_err());
        }
    }
}

mod mounted_source_attestation {
    use super::*;
    use std::{
        ffi::{CString, OsString},
        fs,
        os::unix::ffi::OsStrExt,
        path::Path,
    };

    fn bind(source: &Path, target: &Path) {
        let source = CString::new(source.as_os_str().as_bytes()).unwrap();
        let target = CString::new(target.as_os_str().as_bytes()).unwrap();
        // SAFETY: the test runs in its own user/mount namespace and owns both
        // paths. The host mount tree is never changed.
        assert_eq!(
            unsafe {
                libc::mount(
                    source.as_ptr(),
                    target.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            },
            0,
            "{}",
            std::io::Error::last_os_error()
        );
    }

    #[test]
    fn late_source_and_submount_changes_abort_before_the_workload() {
        for scenario in [
            "safe",
            "source",
            "submount",
            "malformed",
            "missing",
            "oversized",
        ] {
            let output = Command::new("/usr/bin/unshare")
                .args([
                    "--user",
                    "--map-root-user",
                    "--mount",
                    "--propagation",
                    "private",
                ])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "mounted_source_attestation::namespace_subprocess",
                    "--nocapture",
                ])
                .env("FICTOR_TEST_MOUNT_ATTESTATION", scenario)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{scenario}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn namespace_subprocess() {
        let Some(scenario) = std::env::var_os("FICTOR_TEST_MOUNT_ATTESTATION") else {
            return;
        };
        let fixture = Fixture::new();
        let mut context = fixture.context();
        context.runtime = PathBuf::from("/usr/bin/sh").canonicalize().unwrap();
        context.runtime_root = "/usr".into();
        let canary = context.ext_data.join("attestation.canary");
        let mut profile = fixture.profile();
        profile
            .env
            .insert("ATTESTATION_CANARY".into(), canary.to_str().unwrap().into());
        let source = fixture.root.join("outside/grant");
        fs::create_dir(&source).unwrap();
        fs::create_dir(source.join("nested")).unwrap();
        if scenario == "safe" {
            let public = fixture.root.join("outside/public");
            fs::create_dir(&public).unwrap();
            bind(&public, &source.join("nested"));
            profile.read_paths.push(source.join("nested"));
        }
        profile.read_paths.push(source.clone());
        let plan = SandboxPlan::new(profile, context, vec!["-c".into(), "case \"$*\" in *--mount-proof*) exit 91;; esac; printf reached > \"$ATTESTATION_CANARY\"".into()]).unwrap();
        let command = plan.command().unwrap();
        // Freeze the validated Command before changing the path/topology. No
        // sleeps, scheduling assumptions or production hooks create this race.
        if scenario == "source" {
            fs::rename(&source, fixture.root.join("outside/original")).unwrap();
            symlink(fixture.root.join("core"), &source).unwrap();
        } else if scenario == "submount" {
            let before = fs::metadata(&source).unwrap();
            bind(&fixture.root.join("core"), &source.join("nested"));
            use std::os::unix::fs::MetadataExt;
            assert_eq!(fs::metadata(&source).unwrap().ino(), before.ino());
            assert_eq!(fs::metadata(&source).unwrap().dev(), before.dev());
        }
        let mut args: Vec<OsString> = command.get_args().map(Into::into).collect();
        let proof = args.iter().position(|arg| arg == "--mount-proof").unwrap();
        if scenario == "missing" {
            args.drain(proof..proof + 2);
        } else if scenario == "malformed" {
            args[proof + 1] = "{}".into();
        } else if scenario == "oversized" {
            args[proof + 1] = " ".repeat(64 * 1024 + 1).into();
        }
        let output = Command::new(command.get_program())
            .args(args)
            .env_clear()
            .output()
            .unwrap();
        if scenario == "safe" {
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(fs::read(&canary).unwrap(), b"reached");
        } else {
            assert!(!output.status.success());
            assert!(
                !canary.exists(),
                "untrusted workload ran with an invalid proof"
            );
            if scenario != "missing" {
                assert!(
                    String::from_utf8_lossy(&output.stderr).contains("atestação"),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        // Retain the plan's O_PATH inode anchors until the process has exited.
        drop(plan);
    }
}
