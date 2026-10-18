use fictor::{
    config::Config,
    installer::local::{LocalChecker, LocalError},
    proxy::{EgressProxy, nat64::Nat64Prefixes},
    secrets::{BackendKind, Redactor, SecretStore},
    store::{ProposalState, Store},
    supervisor::Supervisor,
};
use std::{fs, path::Path, sync::Arc};

async fn setup(home: &Path, real_home: &Path) -> (LocalChecker, Arc<Store>) {
    fictor::initialize(home).await.unwrap();
    let store = Arc::new(Store::open(home).await.unwrap());
    let supervisor = test_supervisor(home, real_home, store.clone(), "proxy.sock").await;
    (
        LocalChecker::new(
            home.to_path_buf(),
            Nat64Prefixes::default(),
            store.clone(),
            supervisor,
            Default::default(),
        ),
        store,
    )
}

async fn test_supervisor(
    home: &Path,
    real_home: &Path,
    store: Arc<Store>,
    proxy_name: &str,
) -> Arc<Supervisor> {
    let config = Arc::new(Config::load(home).unwrap());
    let secret = Arc::new(SecretStore::open(home, BackendKind::File, Redactor::default()).unwrap());
    let proxy = EgressProxy::bind_unix_with_nat64(
        home.join("run").join(proxy_name),
        store.clone(),
        vec![],
        Nat64Prefixes::default(),
    )
    .await
    .unwrap();
    let supervisor = Supervisor::new(
        home,
        real_home,
        config,
        secret,
        store.clone(),
        Arc::new(proxy),
    )
    .unwrap()
    .with_fictor_exe(std::path::PathBuf::from(env!("CARGO_BIN_EXE_fictor")))
    .unwrap();
    Arc::new(supervisor)
}
fn manifest(path: &Path, runtime: &str) {
    fs::create_dir_all(path).unwrap();
    fs::write(path.join("fictor.yaml"),format!("schema: 1\nid: fixture\nversion: 0.1.0\ndescription: Local fixture\nruntime:\n  kind: {runtime}\n{}",if runtime=="none"{"mcp: false\n"}else{"  entry: main.js\nscope: session\n"})).unwrap();
}
#[tokio::test]
async fn checked_local_bundle_stays_quarantined_and_persists_audited_checks() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("core");
    let real = root.path().join("user");
    fs::create_dir(&real).unwrap();
    let source = root.path().join("source");
    manifest(&source, "none");
    fs::create_dir(source.join("node_modules")).unwrap();
    fs::write(source.join("node_modules/untrusted.js"), b"ignored").unwrap();
    let (checker, store) = setup(&home, &real).await;
    let result = checker.check_local(&source).await.unwrap();
    assert_eq!(result.proposal.state, ProposalState::Checked);
    assert_eq!(
        result.ignored,
        vec![std::path::PathBuf::from("node_modules")]
    );
    assert!(result.catalog.tools().is_empty());
    assert!(
        home.join("extensions/quarantine")
            .join(&result.proposal.id)
            .join("fictor.yaml")
            .exists()
    );
    assert!(!home.join("extensions/lock.json").exists());
    assert!(
        fs::read_dir(home.join("extensions/store"))
            .unwrap()
            .next()
            .is_none()
    );
    let persisted = store.proposal(result.proposal.id.clone()).await.unwrap();
    assert_eq!(persisted.hash, result.proposal.hash);
    let path = store.event_path("sys".into(), None, None).await.unwrap();
    let kinds: Vec<_> = path.events.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(kinds, vec!["ext.proposed", "ext.checking", "ext.checked"]);
}
#[tokio::test]
async fn runtime_dependencies_are_not_silently_skipped() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("core");
    let real = root.path().join("user");
    fs::create_dir(&real).unwrap();
    let source = root.path().join("source");
    manifest(&source, "node");
    fs::write(
        source.join("package.json"),
        r#"{"dependencies":{"zod":"4.1.12"}}"#,
    )
    .unwrap();
    let (checker, store) = setup(&home, &real).await;
    let error = checker.check_local(&source).await.err().unwrap();
    let LocalError::Failed {
        proposal_id,
        reason,
    } = error
    else {
        panic!("unexpected error");
    };
    assert_eq!(reason, "dependency resolver unavailable");
    let proposal = store.proposal(proposal_id).await.unwrap();
    assert_eq!(proposal.state, ProposalState::Failed);
    assert_eq!(proposal.ext_id.as_deref(), Some("fixture"));
    assert_eq!(proposal.version.as_deref(), Some("0.1.0"));
    let checks = proposal.checks.unwrap();
    assert!(
        checks
            .iter()
            .any(|check| check.name == "manifest" && check.passed)
    );
    assert!(
        checks
            .iter()
            .any(|check| check.name == "dependencies" && !check.passed)
    );
    assert!(!home.join("extensions/lock.json").exists());
}

#[tokio::test]
async fn prepacked_node_skips_resolution_but_dependency_metadata_fails_closed() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("core");
    let real = root.path().join("user");
    fs::create_dir(&real).unwrap();
    let (checker, store) = setup(&home, &real).await;
    for (index, metadata, reason) in [
        (0, None, "sandbox smoke failed"),
        (
            1,
            Some(r#"{"type":"module","dependencies":{},"scripts":{"postinstall":"touch never"}}"#),
            "sandbox smoke failed",
        ),
        (
            2,
            Some(r#"{"optionalDependencies":{"package":"1.0.0"}}"#),
            "dependency resolver unavailable",
        ),
        (
            3,
            Some(r#"{"devDependencies":{"package":"1.0.0"}}"#),
            "dependency resolver unavailable",
        ),
        (
            4,
            Some(r#"{"dependencies":"malformed"}"#),
            "invalid package metadata",
        ),
        (5, Some("not json"), "invalid package metadata"),
    ] {
        let source = root.path().join(format!("source-{index}"));
        manifest(&source, "node");
        if let Some(metadata) = metadata {
            fs::write(source.join("package.json"), metadata).unwrap();
        }
        let LocalError::Failed {
            proposal_id,
            reason: actual,
        } = checker.check_local(&source).await.err().unwrap()
        else {
            panic!("unexpected error");
        };
        assert_eq!(actual, reason);
        let proposal = store.proposal(proposal_id).await.unwrap();
        assert_eq!(proposal.state, ProposalState::Failed);
        let checks = proposal.checks.unwrap();
        assert!(checks.iter().any(|check| check.name == "dependencies"
            && check.passed == (reason == "sandbox smoke failed")));
        assert!(!source.join("never").exists());
    }
}

#[tokio::test]
async fn mcp_default_classification_is_not_a_required_tool_but_named_declarations_are() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("core");
    let real = root.path().join("user");
    fs::create_dir(&real).unwrap();
    let (checker, store) = setup(&home, &real).await;
    for (index, named, expected) in [
        (0, "", ProposalState::Checked),
        (1, "  echo: {}\n", ProposalState::Checked),
        (2, "  missing: {}\n", ProposalState::Failed),
    ] {
        let source = root.path().join(format!("source-{index}"));
        fs::create_dir(&source).unwrap();
        fs::write(source.join("fictor.yaml"), format!("schema: 1\nid: fixture\nversion: 0.1.0\ndescription: MCP fixture\nscope: session\nruntime:\n  kind: node\n  entry: main.mjs\ntools:\n  default: {{effect: read, sensitivity: public, output_trust: trusted}}\n{named}")).unwrap();
        fs::write(
            source.join("main.mjs"),
            r#"import { createInterface } from 'node:readline';
for await (const line of createInterface({ input: process.stdin })) {
  const request = JSON.parse(line);
  if (!Object.hasOwn(request, 'id')) continue;
  let result;
  switch (request.method) {
    case 'initialize': result = {
      protocolVersion: request.params.protocolVersion,
      capabilities: { tools: {}, resources: {} },
      serverInfo: { name: 'local-fixture', version: '1.0.0' }
    }; break;
    case 'tools/list': result = { tools: [{
      name: 'echo', description: 'Fixture tool', inputSchema: { type: 'object' }
    }] }; break;
    case 'resources/list': result = { resources: [] }; break;
    default: result = {};
  }
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: request.id, result }) + '\n');
}
"#,
        )
        .unwrap();
        let proposal = match checker.check_local(&source).await {
            Ok(report) => {
                assert_eq!(report.catalog.tools().len(), 1);
                assert_eq!(report.catalog.tools()[0]["name"], "echo");
                report.proposal
            }
            Err(LocalError::Failed {
                proposal_id,
                reason,
            }) => {
                assert_eq!(reason, "declared MCP tools or resources absent");
                store.proposal(proposal_id).await.unwrap()
            }
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(proposal.state, expected);
        assert!(!home.join("extensions/lock.json").exists());
    }
}

#[tokio::test]
async fn global_process_fails_before_dependency_resolution_or_smoke() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("core");
    let real = root.path().join("user");
    fs::create_dir(&real).unwrap();
    let source = root.path().join("source");
    manifest(&source, "node");
    let path = source.join("fictor.yaml");
    let text = fs::read_to_string(&path)
        .unwrap()
        .replace("scope: session", "scope: global");
    fs::write(path, text).unwrap();
    let (checker, store) = setup(&home, &real).await;
    let error = checker.check_local(&source).await.err().unwrap();
    let LocalError::Failed {
        proposal_id,
        reason,
    } = error
    else {
        panic!("unexpected error");
    };
    assert_eq!(reason, "phase:global");
    let proposal = store.proposal(proposal_id).await.unwrap();
    assert_eq!(proposal.state, ProposalState::Failed);
    assert!(proposal.ext_id.is_none());
    assert!(proposal.version.is_none());
    assert!(
        proposal
            .checks
            .unwrap()
            .iter()
            .any(|check| check.name == "manifest" && !check.passed)
    );
    assert!(!home.join("extensions/lock.json").exists());
    assert!(!home.join("logs/ext/fixture.log").exists());
}
#[tokio::test]
async fn invalid_manifest_is_removed_without_execution() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("core");
    let real = root.path().join("user");
    fs::create_dir(&real).unwrap();
    let source = root.path().join("source");
    manifest(&source, "none");
    fs::write(source.join("fictor.yaml"), "schema: [secret-input\n").unwrap();
    let (checker, store) = setup(&home, &real).await;
    let error = checker.check_local(&source).await.err().unwrap();
    assert!(!error.to_string().contains("secret-input"));
    let LocalError::Failed {
        proposal_id,
        reason,
    } = error
    else {
        panic!("unexpected failure")
    };
    assert_eq!(reason, "manifest:invalid_yaml");
    let proposal = store.proposal(proposal_id).await.unwrap();
    assert_eq!(proposal.state, ProposalState::Failed);
    assert!(proposal.ext_id.is_none());
    assert!(proposal.version.is_none());
    assert!(proposal.manifest.is_none());
    assert!(
        fs::read_dir(home.join("extensions/quarantine"))
            .unwrap()
            .next()
            .is_none()
    );
}
#[tokio::test]
async fn receipt_rejects_5001_empty_files_before_parsing() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("core");
    let real = root.path().join("user");
    fs::create_dir(&real).unwrap();
    let source = root.path().join("source");
    fs::create_dir(&source).unwrap();
    for n in 0..5001 {
        fs::File::create(source.join(format!("{n:05}"))).unwrap();
    }
    let (checker, store) = setup(&home, &real).await;
    let LocalError::Failed {
        proposal_id,
        reason,
    } = checker.check_local(&source).await.err().unwrap()
    else {
        panic!("unexpected failure")
    };
    assert_eq!(reason, "limit:entries");
    let proposal = store.proposal(proposal_id).await.unwrap();
    assert_eq!(proposal.state, ProposalState::Failed);
    assert!(proposal.ext_id.is_none());
    assert!(proposal.version.is_none());
    assert!(!home.join("extensions/lock.json").exists());
}

#[tokio::test]
async fn cli_check_reports_hashes_and_never_activates_the_bundle() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("core");
    let real = root.path().join("user");
    fs::create_dir(&real).unwrap();
    fictor::initialize(&home).await.unwrap();
    let config_path = home.join("config.toml");
    let config = fs::read_to_string(&config_path)
        .unwrap()
        .replace("backend = \"keyring\"", "backend = \"file\"");
    fs::write(config_path, config).unwrap();
    let source = root.path().join("bundle with spaces");
    manifest(&source, "none");
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_fictor"))
        .args(["ext", "check"])
        .arg(&source)
        .env("FICTOR_HOME", &home)
        .env("HOME", &real)
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["state"], "checked");
    assert_eq!(report["activated"], false);
    assert!(
        report["bundle_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert!(!home.join("extensions/lock.json").exists());
}

#[tokio::test]
async fn review_preserves_requested_permissions_omitted_paths_and_ignored_receipt() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("core");
    let real = root.path().join("user");
    fs::create_dir(&real).unwrap();
    let source = root.path().join("source");
    manifest(&source, "binary");
    let path = source.join("fictor.yaml");
    let mut text = fs::read_to_string(&path).unwrap();
    text.push_str("permissions:\n  fs:\n    read: [\"${workspace}\", \"~/Documents/x\", \"/opt/private\"]\n    write: [\"${ext_data}\", \"~/Documents/output\"]\n");
    fs::write(path, text).unwrap();
    fs::create_dir(source.join("node_modules")).unwrap();
    fs::write(source.join("node_modules/ignored.js"), b"ignored").unwrap();
    // This test intentionally fails before smoke, proving the review metadata is
    // retained even when the requested executable cannot be started.
    let (checker, store) = setup(&home, &real).await;
    let LocalError::Failed {
        proposal_id,
        reason,
    } = checker.check_local(&source).await.err().unwrap()
    else {
        panic!("unexpected error");
    };
    assert_eq!(reason, "sandbox smoke failed");
    let proposal = store.proposal(proposal_id.clone()).await.unwrap();
    let checks = proposal.checks.unwrap();
    let summary: serde_json::Value = serde_json::from_str(
        checks
            .iter()
            .find(|check| check.name == "permissions")
            .unwrap()
            .detail
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        summary["requested"]["fs"]["read"],
        serde_json::json!(["${workspace}", "~/Documents/x", "/opt/private"])
    );
    assert_eq!(
        summary["omitted_fs"]["read"],
        serde_json::json!(["~/Documents/x", "/opt/private"])
    );
    assert_eq!(
        summary["omitted_fs"]["write"],
        serde_json::json!(["~/Documents/output"])
    );
    assert!(
        !checks
            .iter()
            .find(|check| check.name == "permissions")
            .unwrap()
            .blocking
    );
    let receipt: serde_json::Value = serde_json::from_str(
        checks
            .iter()
            .find(|check| check.name == "receipt")
            .unwrap()
            .detail
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["ignored"], serde_json::json!(["node_modules"]));
    assert!(
        home.join("extensions/quarantine")
            .join(&proposal_id)
            .join("fictor.yaml")
            .exists()
    );
    assert!(
        checks
            .iter()
            .any(|check| check.name == "smoke" && !check.passed)
    );
    assert!(!home.join("extensions/lock.json").exists());
}

#[tokio::test]
async fn cancellation_of_caller_does_not_strand_the_core_owned_check() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("core");
    let real = root.path().join("user");
    fs::create_dir(&real).unwrap();
    let source = root.path().join("source");
    manifest(&source, "none");
    // The worker must be observed during receipt, before it can become checked.
    fs::File::create(source.join("padding"))
        .unwrap()
        .set_len(40 * 1024 * 1024)
        .unwrap();
    let (checker, store) = setup(&home, &real).await;
    let caller = tokio::spawn(async move { checker.check_local(&source).await });
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if fs::read_dir(home.join("extensions/quarantine"))
                .unwrap()
                .any(|entry| {
                    entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".receipt-")
                })
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    caller.abort();
    let Err(error) = caller.await else {
        panic!("caller unexpectedly completed")
    };
    assert!(error.is_cancelled());
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let events = store
                .event_path("sys".into(), None, None)
                .await
                .unwrap()
                .events;
            if let Some(event) = events.iter().find(|event| event.kind == "ext.checked") {
                let proposal = store
                    .proposal(event.payload["proposal_id"].as_str().unwrap().into())
                    .await
                    .unwrap();
                assert_eq!(proposal.state, ProposalState::Checked);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(!home.join("extensions/lock.json").exists());
}

#[tokio::test]
async fn preidentity_refusals_are_durable_sanitized_and_remove_only_received_bytes() {
    use std::os::unix::{ffi::OsStringExt, fs::symlink};
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("core");
    let real = root.path().join("user");
    fs::create_dir(&real).unwrap();
    let (checker, store) = setup(&home, &real).await;
    let outside = root.path().join("private-secret-content");
    fs::write(&outside, "outside remains intact").unwrap();
    let mut ids = Vec::new();
    for (index, name, reason) in [
        (0, "receipt", "receipt:symlink"),
        (1, "receipt", "receipt:special_file"),
        (2, "receipt", "receipt:invalid_path"),
        (3, "receipt", "receipt:invalid_path"),
        (4, "manifest", "manifest:missing"),
        (5, "manifest", "manifest:invalid_yaml"),
        (6, "manifest", "manifest:invalid"),
        (7, "receipt", "receipt:io"),
    ] {
        let source = root.path().join(format!("private-source-{index}"));
        manifest(&source, "none");
        match index {
            0 => symlink(&outside, source.join("link")).unwrap(),
            1 => {
                let name =
                    std::ffi::CString::new(source.join("fifo").as_os_str().as_encoded_bytes())
                        .unwrap();
                // SAFETY: name is NUL-terminated and mode contains ordinary file permission bits.
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
            2 => fs::write(source.join("private-invalid\nname"), "unchanged").unwrap(),
            3 => fs::write(
                source.join(std::ffi::OsString::from_vec(vec![b'x', 0xff])),
                "unchanged",
            )
            .unwrap(),
            4 => fs::remove_file(source.join("fictor.yaml")).unwrap(),
            5 => fs::write(
                source.join("fictor.yaml"),
                "schema: [private-yaml-content\n",
            )
            .unwrap(),
            6 => fs::write(
                source.join("fictor.yaml"),
                "schema: 1\nid: invalid_underscore\nversion: 1.0.0\n",
            )
            .unwrap(),
            7 => fs::remove_dir_all(&source).unwrap(),
            _ => unreachable!(),
        }
        let error = checker.check_local(&source).await.err().unwrap();
        assert!(!error.to_string().contains("private-"));
        let LocalError::Failed {
            proposal_id,
            reason: actual,
        } = error
        else {
            panic!("unexpected failure")
        };
        assert_eq!(actual, reason);
        let proposal = store.proposal(proposal_id.clone()).await.unwrap();
        assert_eq!(proposal.state, ProposalState::Failed);
        assert!(proposal.ext_id.is_none() && proposal.version.is_none());
        assert!(
            proposal.manifest.is_none() && proposal.hash.is_none() && proposal.update_of.is_none()
        );
        let failure = proposal.checks.as_ref().unwrap().last().unwrap();
        assert_eq!(failure.name, name);
        assert_eq!(failure.detail.as_deref(), Some(reason));
        assert!(!failure.passed && failure.blocking);
        let encoded = serde_json::to_string(&proposal).unwrap();
        assert!(!encoded.contains("private-"));
        let events = store
            .event_path("sys".into(), None, None)
            .await
            .unwrap()
            .events;
        let attempt: Vec<_> = events
            .iter()
            .filter(|event| event.payload["proposal_id"] == proposal_id)
            .collect();
        assert_eq!(attempt.len(), 2);
        assert_eq!(attempt[0].kind, "ext.proposed");
        assert_eq!(attempt[1].kind, "ext.failed");
        assert_eq!(
            attempt[1].parent_id.as_deref(),
            Some(attempt[0].id.as_str())
        );
        for event in &attempt {
            assert!(event.payload["ext_id"].is_null() && event.payload["version"].is_null());
            assert!(event.payload.get("key").is_none());
        }
        assert_eq!(attempt[1].payload["reason"], reason);
        assert!(
            !home
                .join("extensions/quarantine")
                .join(format!(".receipt-{proposal_id}"))
                .exists()
        );
        assert!(
            !home
                .join("extensions/quarantine")
                .join(&proposal_id)
                .exists()
        );
        if index != 7 {
            assert!(source.exists());
        }
        assert_eq!(
            fs::read_to_string(&outside).unwrap(),
            "outside remains intact"
        );
        ids.push(proposal_id);
    }
    drop(checker);
    // Dropping the supervisor stops its disposable proxy tasks, which release
    // their Store references before the writer can be joined for the restart.
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while Arc::strong_count(&store) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    Arc::try_unwrap(store)
        .ok()
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    let reopened = Store::open(&home).await.unwrap();
    for id in ids {
        let proposal = reopened.proposal(id).await.unwrap();
        assert_eq!(proposal.state, ProposalState::Failed);
        assert!(proposal.ext_id.is_none() && proposal.version.is_none());
    }
}

#[tokio::test]
async fn failed_initial_commit_never_opens_the_source() {
    use std::{io::Read, os::fd::FromRawFd};
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("core");
    let real = root.path().join("user");
    fs::create_dir(&real).unwrap();
    let source = root.path().join("source");
    manifest(&source, "none");
    let (checker, store) = setup(&home, &real).await;
    let db = rusqlite::Connection::open(home.join("fictor.db")).unwrap();
    db.execute_batch("CREATE TRIGGER deny_initial_receipt BEFORE INSERT ON events WHEN NEW.kind='ext.proposed' BEGIN SELECT RAISE(ABORT,'test refusal'); END;").unwrap();
    // SAFETY: inotify_init1 takes only valid flags and returns a new owned fd.
    let descriptor = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    assert!(descriptor >= 0);
    // SAFETY: descriptor was just allocated and has not been wrapped previously.
    let mut watch = unsafe { fs::File::from_raw_fd(descriptor) };
    let path = std::ffi::CString::new(source.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: path is NUL-terminated; descriptor remains live for the test.
    assert!(
        unsafe {
            libc::inotify_add_watch(descriptor, path.as_ptr(), libc::IN_OPEN | libc::IN_ACCESS)
        } >= 0
    );
    assert!(matches!(
        checker.check_local(&source).await,
        Err(LocalError::Store(_))
    ));
    let mut events = [0; 4096];
    assert!(
        matches!(watch.read(&mut events), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    assert!(
        store
            .event_path("sys".into(), None, None)
            .await
            .unwrap()
            .events
            .is_empty()
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM proposals", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert!(
        fs::read_dir(home.join("extensions/quarantine"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[tokio::test]
async fn failed_terminal_commit_retains_the_receipt_and_reports_its_id() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("core");
    let real = root.path().join("user");
    fs::create_dir(&real).unwrap();
    let source = root.path().join("source");
    manifest(&source, "none");
    fs::write(
        source.join("fictor.yaml"),
        "schema: [private-yaml-content\n",
    )
    .unwrap();
    let (checker, store) = setup(&home, &real).await;
    let db = rusqlite::Connection::open(home.join("fictor.db")).unwrap();
    db.execute_batch("CREATE TRIGGER deny_terminal_receipt BEFORE INSERT ON events WHEN NEW.kind='ext.failed' BEGIN SELECT RAISE(ABORT,'test refusal'); END;").unwrap();
    let error = checker.check_local(&source).await.err().unwrap();
    assert!(!error.to_string().contains("private-yaml-content"));
    let LocalError::Persistence { proposal_id } = error else {
        panic!("unexpected failure")
    };
    let proposal = store.proposal(proposal_id.clone()).await.unwrap();
    assert_eq!(proposal.state, ProposalState::Received);
    assert!(proposal.ext_id.is_none() && proposal.version.is_none());
    assert!(
        home.join("extensions/quarantine")
            .join(format!(".receipt-{proposal_id}"))
            .join("fictor.yaml")
            .exists()
    );
    assert_eq!(
        store
            .event_path("sys".into(), None, None)
            .await
            .unwrap()
            .events
            .len(),
        1
    );
}

#[tokio::test]
async fn another_checker_cannot_recover_or_admit_while_the_first_owns_the_lease() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("core");
    let real = root.path().join("user");
    fs::create_dir(&real).unwrap();
    let source = root.path().join("source");
    manifest(&source, "none");
    let (first, store) = setup(&home, &real).await;
    let checked = first.check_local(&source).await.unwrap().proposal;
    let second = LocalChecker::new(
        home.clone(),
        Nat64Prefixes::default(),
        store.clone(),
        test_supervisor(&home, &real, store.clone(), "proxy2.sock").await,
        Default::default(),
    );
    assert!(matches!(
        second.check_local(&source).await,
        Err(LocalError::Admission)
    ));
    assert_eq!(
        store.proposal(checked.id).await.unwrap().state,
        ProposalState::Checked
    );
    assert_eq!(
        store
            .event_path("sys".into(), None, None)
            .await
            .unwrap()
            .events
            .len(),
        3
    );
    drop(first);
    assert_eq!(
        second.check_local(&source).await.unwrap().proposal.state,
        ProposalState::Checked
    );
}
