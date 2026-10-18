use fictor::{
    config::Config,
    installer::{
        BundleError,
        local::{LocalChecker, LocalError},
    },
    proxy::{EgressProxy, nat64::Nat64Prefixes},
    secrets::{BackendKind, Redactor, SecretStore},
    store::{ProposalState, Store},
    supervisor::Supervisor,
};
use std::{fs, path::Path, sync::Arc};

async fn setup(home: &Path, real_home: &Path) -> (LocalChecker, Arc<Store>) {
    fictor::initialize(home).await.unwrap();
    let config = Arc::new(Config::load(home).unwrap());
    let store = Arc::new(Store::open(home).await.unwrap());
    let secret = Arc::new(SecretStore::open(home, BackendKind::File, Redactor::default()).unwrap());
    let proxy = EgressProxy::bind_unix_with_nat64(
        home.join("run/proxy.sock"),
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
    (
        LocalChecker::new(
            home.to_path_buf(),
            Nat64Prefixes::default(),
            store.clone(),
            Arc::new(supervisor),
            Default::default(),
        ),
        store,
    )
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
    assert!(!proposal.checks.unwrap()[0].passed);
    assert!(!home.join("extensions/lock.json").exists());
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
    assert!(!proposal.checks.unwrap()[0].passed);
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
    fs::write(source.join("fictor.yaml"), "!!not-supported secret-input").unwrap();
    let (checker, _store) = setup(&home, &real).await;
    let error = checker.check_local(&source).await.err().unwrap();
    assert!(matches!(error, LocalError::Manifest(_)));
    assert!(!error.to_string().contains("secret-input"));
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
    let (checker, _store) = setup(&home, &real).await;
    assert!(matches!(
        checker.check_local(&source).await,
        Err(LocalError::Bundle(BundleError::Limit("entries")))
    ));
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
