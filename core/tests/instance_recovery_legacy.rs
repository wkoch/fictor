//! Legacy diagnostics only. The real /tmp is never enumerated or modified by
//! this test: its helper first creates a private mount/PID namespace and tmpfs.
use fictor::{instance_recovery, store::Store};
use std::{
    ffi::CString,
    fs,
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, PermissionsExt, symlink},
    },
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

#[tokio::test]
async fn legacy_resources_are_diagnosed_without_contents_or_invented_ownership() {
    let mut command = tokio::process::Command::new("/usr/bin/unshare");
    command
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--propagation",
            "private",
            "--pid",
            "--fork",
            "--kill-child=KILL",
            "--mount-proc",
            "--",
        ])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "legacy_namespace_child", "--nocapture"])
        .env("FICTOR_TEST_LEGACY_NAMESPACE", "1")
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(15), command.output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn fifo(path: &Path) {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: the owned test pathname is a live NUL-terminated C string.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
}

#[tokio::test]
async fn legacy_namespace_child() {
    if std::env::var_os("FICTOR_TEST_LEGACY_NAMESPACE").is_none() {
        return;
    }
    assert!(
        Command::new("/usr/bin/mount")
            .args(["-t", "tmpfs", "tmpfs", "/tmp"])
            .status()
            .unwrap()
            .success()
    );
    let root = tempfile::Builder::new()
        .prefix("adr038-legacy-")
        .tempdir_in("/tmp")
        .unwrap();
    let home = root.path().join("core");
    fictor::initialize(&home).await.unwrap();
    let store = Arc::new(Store::open(&home).await.unwrap());
    assert!(!home.join("run/instances").exists());
    // A prefix lookalike and a nested candidate are not old top-level resources.
    fs::create_dir("/tmp/fictorial").unwrap();
    fs::create_dir_all("/tmp/ordinary/nested/fictor-unrelated").unwrap();
    let empty = instance_recovery::recover(store.clone()).await.unwrap();
    assert!(!empty.legacy.pid_files && !empty.legacy.temporaries && !empty.legacy.scan_unavailable);

    let secret = root.path().join("fake-secret-target");
    fs::write(&secret, b"fake-secret-canary-never-log").unwrap();
    let pid = home.join("run/untrusted-\u{1b}-name.pid");
    // If anyone interprets or signals this number heuristically, the helper
    // dies. It is the exact test process, never an unrelated host PID.
    let pid_text = std::process::id().to_string();
    let temporary = Path::new("/tmp/fictor-\u{1b}fake-secret");
    let absent = root.path().join("fake-secret-absent");
    let head = store.session("sys".into()).await.unwrap().head_id;
    // One candidate at a time: no earlier ordinary entry can hide a mistaken
    // symlink traversal or a blocking FIFO open in the diagnostic scanner.
    for kind in ["dangling-link", "fifo", "old-tree"] {
        match kind {
            "dangling-link" => {
                symlink(&absent, &pid).unwrap();
                symlink(&absent, temporary).unwrap();
            }
            "fifo" => {
                fifo(&pid);
                fifo(temporary);
            }
            _ => {
                fs::write(&pid, &pid_text).unwrap();
                fs::create_dir_all(temporary.join("nested")).unwrap();
                fs::set_permissions(temporary, fs::Permissions::from_mode(0o700)).unwrap();
                fs::write(temporary.join("nested/canary"), b"retain every byte").unwrap();
            }
        }
        for _ in 0..2 {
            let report = instance_recovery::recover(store.clone()).await.unwrap();
            assert!(
                report.legacy.pid_files && report.legacy.temporaries,
                "{kind}"
            );
            assert!(!report.legacy.scan_unavailable);
            assert!(report.removed.is_empty() && report.diagnostics.is_empty());
            let diagnostic = format!("{:?}", report.legacy);
            assert!(
                !diagnostic.contains("secret")
                    && !diagnostic.contains('/')
                    && !diagnostic.contains('\u{1b}')
            );
            assert_eq!(store.session("sys".into()).await.unwrap().head_id, head);
            assert_eq!(fs::read(&secret).unwrap(), b"fake-secret-canary-never-log");
            match kind {
                "dangling-link" => {
                    assert_eq!(fs::read_link(&pid).unwrap(), absent);
                    assert_eq!(fs::read_link(temporary).unwrap(), absent);
                    assert!(!absent.exists());
                }
                "fifo" => {
                    assert!(fs::symlink_metadata(&pid).unwrap().file_type().is_fifo());
                    assert!(
                        fs::symlink_metadata(temporary)
                            .unwrap()
                            .file_type()
                            .is_fifo()
                    );
                }
                _ => {
                    assert_eq!(fs::read_to_string(&pid).unwrap(), pid_text);
                    assert_eq!(
                        fs::read(temporary.join("nested/canary")).unwrap(),
                        b"retain every byte"
                    );
                }
            }
            assert!(!home.join("run/instances").exists());
        }
        // Only the fixture removes its exact fake entries, between cases.
        fs::remove_file(&pid).unwrap();
        if kind == "old-tree" {
            fs::remove_dir_all(temporary).unwrap();
        } else {
            fs::remove_file(temporary).unwrap();
        }
    }
}
