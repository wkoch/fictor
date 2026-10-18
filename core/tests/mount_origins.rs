//! ADR-044 source admission. The child has its own PID/mount namespaces and
//! procfs: no test imports or reads another host process's proc entries.
use fictor::sandbox::{ProxyEndpoint, SandboxContext, SandboxPlan, SandboxProfile, Tier};
use std::{
    collections::BTreeMap,
    fs,
    os::{
        fd::AsRawFd,
        unix::{fs::symlink, net::UnixListener},
    },
    path::{Path, PathBuf},
    process::Command,
};

struct Fixture {
    _root: tempfile::TempDir,
    root: PathBuf,
    _proxy: UnixListener,
}
impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        for name in [
            "core/extensions/store/probe/0.1-hash",
            "core/extensions/data/probe",
            "core/run",
            "user",
            "instance",
            "workspace",
            "lower",
            "upper",
            "work",
        ] {
            fs::create_dir_all(root.join(name)).unwrap();
        }
        fs::write(root.join("workspace/input"), "only fake test input").unwrap();
        let proxy = UnixListener::bind(root.join("core/run/proxy.sock")).unwrap();
        Self {
            _root: temporary,
            root,
            _proxy: proxy,
        }
    }
    fn profile(&self) -> SandboxProfile {
        SandboxProfile {
            read_paths: vec![self.root.join("workspace")],
            write_paths: vec![],
            spawn: false,
            kernel_socket: None,
            proxy: ProxyEndpoint::Unix(self.root.join("core/run/proxy.sock")),
            env: BTreeMap::new(),
            cwd: self.root.join("workspace"),
            tier: Tier::Os,
        }
    }
    fn context(&self) -> SandboxContext {
        SandboxContext {
            fictor_home: self.root.join("core"),
            real_home: self.root.join("user"),
            bundle_root: self.root.join("core/extensions/store/probe/0.1-hash"),
            ext_data: self.root.join("core/extensions/data/probe"),
            tmp_dir: self.root.join("instance"),
            runtime: "/usr/bin/true".into(),
            runtime_root: "/usr".into(),
            fictor_exe: env!("CARGO_BIN_EXE_fictor").into(),
            home_ro_files: vec![],
            allow_store_read: false,
        }
    }
    fn plan(&self) -> Result<SandboxPlan, fictor::sandbox::SandboxError> {
        SandboxPlan::new(self.profile(), self.context(), vec![])
    }
}

fn mount(arguments: &[&std::ffi::OsStr]) {
    let output = Command::new("/usr/bin/mount")
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "mount failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn overlay(fixture: &Fixture, target: &Path) {
    let options = format!(
        "userxattr,lowerdir={},upperdir={},workdir={}",
        fixture.root.join("lower").display(),
        fixture.root.join("upper").display(),
        fixture.root.join("work").display()
    );
    mount(&[
        "-t".as_ref(),
        "overlay".as_ref(),
        "overlay".as_ref(),
        "-o".as_ref(),
        options.as_ref(),
        target.as_os_str(),
    ]);
}

#[test]
fn ordinary_mount_types_and_original_magic_links_are_checked_before_import() {
    for case in [
        "tmpfs",
        "magic",
        "proc-file",
        "proc-submount",
        "overlay",
        "overlay-submount",
        "base-overlay-submount",
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
            .args(["--exact", "source_namespace_child", "--nocapture"])
            .env("FICTOR_TEST_MOUNT_ORIGIN", case)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "case {case}:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn source_namespace_child() {
    let Ok(case) = std::env::var("FICTOR_TEST_MOUNT_ORIGIN") else {
        return;
    };
    let fixture = Fixture::new();
    // This positive control distinguishes source-policy failures from a broken
    // ordinary profile, Toolbx base, or isolated /proc used by the helper.
    let _ordinary = fixture.plan().unwrap();
    let workspace = fixture.root.join("workspace");
    match case.as_str() {
        "tmpfs" => {
            mount(&[
                "-t".as_ref(),
                "tmpfs".as_ref(),
                "tmpfs".as_ref(),
                workspace.as_os_str(),
            ]);
            let _allowed = fixture.plan().unwrap();
            return;
        }
        "magic" => {
            let file = fs::File::open(workspace.join("input")).unwrap();
            let magic = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
            assert_eq!(fs::canonicalize(&magic).unwrap(), workspace.join("input"));
            for source in [magic.clone(), fixture.root.join("ordinary-link")] {
                if source != magic {
                    symlink(&magic, &source).unwrap();
                }
                let mut profile = fixture.profile();
                profile.read_paths.push(source);
                assert!(SandboxPlan::new(profile, fixture.context(), vec![]).is_err());
            }
            // An ordinary symlink without a kernel magic link is still usable
            // for a core resource; it is not the reason for the failure above.
            let bundle_alias = fixture.root.join("bundle-link");
            symlink(
                fixture.root.join("core/extensions/store/probe/0.1-hash"),
                &bundle_alias,
            )
            .unwrap();
            let mut context = fixture.context();
            context.bundle_root = bundle_alias;
            let _allowed = SandboxPlan::new(fixture.profile(), context, vec![]).unwrap();
            return;
        }
        "proc-file" => {
            mount(&[
                "--bind".as_ref(),
                "/proc/self/status".as_ref(),
                workspace.join("input").as_os_str(),
            ]);
        }
        "proc-submount" => {
            let target = workspace.join("kernel");
            fs::create_dir(&target).unwrap();
            mount(&[
                "-t".as_ref(),
                "proc".as_ref(),
                "proc".as_ref(),
                target.as_os_str(),
            ]);
        }
        "overlay" => overlay(&fixture, &workspace),
        "overlay-submount" => {
            let target = workspace.join("nested");
            fs::create_dir(&target).unwrap();
            overlay(&fixture, &target);
        }
        "base-overlay-submount" => overlay(&fixture, Path::new("/usr/share/zoneinfo")),
        _ => panic!("unknown fixture case"),
    }
    let error = match fixture.plan() {
        Err(error) => error,
        Ok(_) => panic!("forbidden source was imported: {case}"),
    };
    let expected = if case.starts_with("proc") {
        "proc"
    } else {
        "overlay"
    };
    assert!(
        error.to_string().contains(expected),
        "expected observed filesystem {expected}: {error}"
    );
}
