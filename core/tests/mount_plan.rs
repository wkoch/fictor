//! ADR-044 destination/equivalence integration in a fresh private mount/PID
//! namespace. All imported data and sentinels are fake and created on tmpfs.
use fictor::sandbox::{ProxyEndpoint, SandboxContext, SandboxPlan, SandboxProfile, Tier};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    os::unix::{
        fs::{PermissionsExt, symlink},
        net::UnixListener,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

struct Fixture {
    _root: tempfile::TempDir,
    root: PathBuf,
    _proxy: UnixListener,
}
impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::Builder::new()
            .prefix("adr044-plan-")
            .tempdir()
            .unwrap();
        let root = temporary.path().to_path_buf();
        for path in [
            "core/extensions/store/tool/key",
            "core/extensions/data/tool/child",
            "core/run",
            "user",
            "instance/work",
            "workspace/sub",
        ] {
            fs::create_dir_all(root.join(path)).unwrap();
        }
        fs::set_permissions(root.join("core"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join("core/config.toml"), "fake hidden control").unwrap();
        fs::write(root.join("core/extensions/store/tool/key/input"), "bundle").unwrap();
        fs::write(
            root.join("core/extensions/data/tool/child/input"),
            "own-data",
        )
        .unwrap();
        fs::write(root.join("workspace/input"), "workspace").unwrap();
        fs::write(root.join("instance/host-sentinel"), "not imported").unwrap();
        fs::write(
            root.join("instance/work/host-sentinel"),
            "not imported either",
        )
        .unwrap();
        let proxy = UnixListener::bind(root.join("core/run/proxy.sock")).unwrap();
        Self {
            _root: temporary,
            root,
            _proxy: proxy,
        }
    }
    fn context(&self) -> SandboxContext {
        SandboxContext {
            fictor_home: self.root.join("core"),
            real_home: self.root.join("user"),
            bundle_root: self.root.join("core/extensions/store/tool/key"),
            ext_data: self.root.join("core/extensions/data/tool"),
            tmp_dir: self.root.join("instance"),
            runtime: "/usr/bin/sh".into(),
            runtime_root: "/usr".into(),
            fictor_exe: env!("CARGO_BIN_EXE_fictor").into(),
            home_ro_files: vec![],
            allow_store_read: true,
        }
    }
    fn profile(&self) -> SandboxProfile {
        SandboxProfile {
            read_paths: vec![self.root.join("workspace")],
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

fn count_bind(arguments: &[std::ffi::OsString], source: &Path) -> usize {
    arguments
        .windows(3)
        .filter(|parts| {
            matches!(
                parts[0].to_str(),
                Some("--bind" | "--ro-bind" | "--ro-bind-try")
            ) && parts[1] == source.as_os_str()
        })
        .count()
}

#[test]
fn destination_reservations_equivalence_and_private_tmp_hold_in_real_sandboxes() {
    for case in [
        "equivalent",
        "proc",
        "dev",
        "usr-write",
        "etc-ancestor",
        "resource-ancestor",
        "tmp-container",
        "tmp-home",
        "tmp-template-home",
        "tmp-template-home-child",
        "tmp-conflict",
        "routing-node",
        "run-alias",
        "tmp-helper-parent",
        "tmp-helper-alias",
        "bootstrap-valid",
        "bootstrap-original-inplace",
        "bootstrap-original-replaced",
        "bootstrap-copy-inplace",
        "bootstrap-copy-replaced",
        "bootstrap-system-base",
    ] {
        let output = Command::new("/usr/bin/unshare")
            .args([
                "--user",
                "--map-root-user",
                "--mount",
                "--propagation",
                "private",
                "--pid",
                "--fork",
                "--mount-proc",
                "--",
            ])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", "mount_plan_child", "--nocapture"])
            .env("FICTOR_TEST_MOUNT_PLAN_CASE", case)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "case={case}\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn mount_plan_child() {
    let Ok(case) = std::env::var("FICTOR_TEST_MOUNT_PLAN_CASE") else {
        return;
    };
    // Replace only this helper's private /tmp, before creating any fixture.
    // The helper's procfs belongs to its own new PID namespace as well.
    let mounted = Command::new("/usr/bin/mount")
        .args(["-t", "tmpfs", "tmpfs", "/tmp"])
        .status()
        .unwrap();
    assert!(mounted.success());
    let fixture = Fixture::new();
    let mut context = fixture.context();
    let mut profile = fixture.profile();
    let marker = fixture.root.join("workspace/workload-started");
    if case.starts_with("bootstrap-") {
        // A fake bootstrap is deliberately executable and writes a canary before
        // doing any init attestation. A rejection after its first instruction is
        // too late; the unchanged control proves the marker can be reached.
        let directory = fixture.root.join("trusted-bin");
        fs::create_dir(&directory).unwrap();
        let original = directory.join("init");
        let bytes = format!("#!/usr/bin/sh\nprintf executed > '{}'\n", marker.display());
        fs::write(&original, &bytes).unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
        context.fictor_exe = original.clone();
        let plan = SandboxPlan::new(profile, context, vec!["-c".into(), "exit 0".into()]).unwrap();
        let mut command = plan.command().unwrap();
        let args = command.get_args().collect::<Vec<_>>();
        let copy = args
            .windows(3)
            .find(|parts| parts[0] == "--ro-bind" && parts[2] == "/fx/fictor")
            .map(|parts| PathBuf::from(parts[1]))
            .unwrap();
        match case.as_str() {
            "bootstrap-valid" => {}
            "bootstrap-original-inplace" => {
                fs::write(&original, format!("{bytes}# altered\n")).unwrap()
            }
            "bootstrap-original-replaced" => {
                fs::rename(&original, directory.join("old-init")).unwrap();
                fs::write(&original, &bytes).unwrap();
                fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
            }
            "bootstrap-copy-inplace" => {
                fs::set_permissions(&copy, fs::Permissions::from_mode(0o700)).unwrap();
                fs::write(&copy, format!("{bytes}# altered\n")).unwrap();
                fs::set_permissions(&copy, fs::Permissions::from_mode(0o500)).unwrap();
            }
            "bootstrap-copy-replaced" => {
                fs::rename(&copy, copy.with_extension("old")).unwrap();
                fs::write(&copy, &bytes).unwrap();
                fs::set_permissions(&copy, fs::Permissions::from_mode(0o500)).unwrap();
            }
            "bootstrap-system-base" => {
                // The pending first exec resolves this path. Only this helper's
                // private namespace is changed; the real host binary is intact.
                assert!(
                    Command::new("/usr/bin/mount")
                        .arg("--bind")
                        .arg(&original)
                        .arg("/usr/bin/bwrap")
                        .status()
                        .unwrap()
                        .success()
                );
            }
            _ => unreachable!(),
        }
        let result = command.stdin(Stdio::null()).output();
        if case == "bootstrap-valid" {
            let output = result.unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(fs::read(&marker).unwrap(), b"executed");
        } else {
            assert_eq!(
                result.unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
            assert!(
                !marker.exists(),
                "bootstrap executed before checking {case}"
            );
        }
        return;
    }
    if case != "equivalent" {
        match case.as_str() {
            "proc" => profile.read_paths.push("/proc".into()),
            "dev" => profile.read_paths.push("/dev".into()),
            "usr-write" => profile.write_paths.push("/usr/bin".into()),
            "etc-ancestor" => profile.read_paths.push("/etc".into()),
            "resource-ancestor" => profile
                .read_paths
                .push(fixture.root.join("core/extensions/data")),
            "tmp-container" => profile.read_paths.push("/tmp".into()),
            "tmp-home" => {
                fs::create_dir("/tmp/home").unwrap();
                profile.read_paths.push("/tmp/home".into());
            }
            "tmp-template-home" | "tmp-template-home-child" => {
                let path = context.tmp_dir.join(if case == "tmp-template-home" {
                    "home"
                } else {
                    "home/child"
                });
                fs::create_dir_all(&path).unwrap();
                profile.read_paths.push(path);
            }
            "tmp-conflict" => {
                fs::create_dir("/tmp/work").unwrap();
                profile
                    .write_paths
                    .extend([context.tmp_dir.join("work"), "/tmp/work".into()]);
            }
            "routing-node" => {
                // The Atomic routing contract applies when this alias exists.
                if !fs::read_link("/home")
                    .ok()
                    .is_some_and(|target| matches!(target.to_str(), Some("var/home" | "/var/home")))
                {
                    return;
                }
                profile.read_paths.push("/home".into());
            }
            "run-alias" => {
                assert!(
                    Command::new("/usr/bin/mount")
                        .args(["-t", "tmpfs", "tmpfs", "/run"])
                        .status()
                        .unwrap()
                        .success()
                );
                fs::write("/run/fake-public-data", "test data, no secret").unwrap();
                let alias = fixture.root.join("timezone-lookalike");
                symlink("/run/fake-public-data", &alias).unwrap();
                profile.read_paths.push(alias);
            }
            "tmp-helper-parent" | "tmp-helper-alias" => {
                let parent = fixture.root.join("helper-parent");
                context.tmp_dir = parent.join("instance");
                fs::create_dir_all(context.tmp_dir.join("home")).unwrap();
                fs::write(
                    context.tmp_dir.join("home/host-sentinel"),
                    "fake private preparation data",
                )
                .unwrap();
                if case == "tmp-helper-parent" {
                    profile.read_paths.push(parent);
                } else {
                    let alias = fixture.root.join("helper-alias");
                    fs::create_dir(&alias).unwrap();
                    assert!(
                        Command::new("/usr/bin/mount")
                            .arg("--bind")
                            .arg(&context.tmp_dir)
                            .arg(&alias)
                            .status()
                            .unwrap()
                            .success()
                    );
                    profile.read_paths.push(alias);
                }
            }
            _ => panic!("unknown test case"),
        }
        let result = SandboxPlan::new(
            profile,
            context,
            vec!["-c".into(), format!("touch {}", marker.display()).into()],
        );
        assert!(
            result.is_err(),
            "reserved case unexpectedly admitted: {case}"
        );
        assert!(!marker.exists());
        return;
    }
    fs::create_dir("/tmp/project").unwrap();
    fs::write("/tmp/project/input", "ordinary tmp child").unwrap();
    fs::write("/tmp/host-sentinel", "whole host tmp must stay hidden").unwrap();
    profile.read_paths.extend([
        "/usr/bin".into(),
        context.bundle_root.clone(),
        context.ext_data.join("child"),
        context.fictor_home.join("extensions/store"),
        "/tmp/project".into(),
    ]);
    profile
        .write_paths
        .extend([context.ext_data.clone(), context.tmp_dir.join("work")]);
    let script = format!(
        "set -eu; test \"$(cat '{}/input')\" = workspace; test \"$(cat '{}/input')\" = bundle; test \"$(cat '{}/child/input')\" = own-data; test \"$(cat /tmp/project/input)\" = 'ordinary tmp child'; test -d /tmp/work; test ! -e /tmp/host-sentinel; test ! -e /tmp/work/host-sentinel; test ! -e '{}/config.toml'; printf success > '{}'",
        fixture.root.join("workspace").display(),
        context.bundle_root.display(),
        context.ext_data.display(),
        context.fictor_home.display(),
        marker.display(),
    );
    let plan = SandboxPlan::new(profile, context, vec!["-c".into(), script.into()]).unwrap();
    let arguments = plan.linux_arguments().unwrap();
    assert_eq!(count_bind(&arguments, &fixture.root.join("workspace")), 1);
    assert_eq!(
        count_bind(&arguments, &fixture.root.join("core/extensions/data/tool")),
        1
    );
    assert_eq!(
        count_bind(
            &arguments,
            &fixture.root.join("core/extensions/store/tool/key")
        ),
        0
    );
    assert_eq!(count_bind(&arguments, Path::new("/usr/bin")), 0);
    assert_eq!(count_bind(&arguments, &fixture.root.join("instance")), 0);
    assert!(
        arguments
            .windows(2)
            .any(|parts| parts == [OsStr::new("--tmpfs"), OsStr::new("/tmp")])
    );
    let output = plan
        .command()
        .unwrap()
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(marker).unwrap(), "success");
}
