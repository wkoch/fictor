use fictor::{
    admin::{AdminMutationError, AdminMutationHandler, MutationReason},
    config::Config,
    installer::{
        local::LocalChecker,
        lock::Lock,
        online::{InstallService, InstallStatus},
        overrides::Overrides,
    },
    proxy::{EgressProxy, nat64::Nat64Prefixes},
    secrets::{BackendKind, Redactor, SecretStore},
    store::{ProposalState, Store},
    supervisor::Supervisor,
};
use serde_json::{Value, json};
use std::{fs, path::PathBuf, sync::Arc, time::Duration};

struct Fixture {
    _root: tempfile::TempDir,
    home: PathBuf,
    store: Arc<Store>,
    checker: LocalChecker,
    service: InstallService,
    _proxy: Arc<EgressProxy>,
}
impl Fixture {
    async fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("fx-on-")
            .tempdir_in("/tmp")
            .unwrap();
        let home = root.path().join("core");
        fictor::initialize(&home).await.unwrap();
        let store = Arc::new(Store::open(&home).await.unwrap());
        let mut config = Config::load(&home).unwrap();
        config.providers.clear();
        config.sandbox.home_ro_files.clear();
        let config = Arc::new(config);
        let secrets = Arc::new(
            SecretStore::open_with_lease(
                store.owner().clone(),
                BackendKind::File,
                Redactor::default(),
            )
            .unwrap(),
        );
        let proxy = Arc::new(
            EgressProxy::bind_unix_with_nat64(
                home.join("run/proxy.sock"),
                store.clone(),
                vec![],
                Nat64Prefixes::default(),
            )
            .await
            .unwrap(),
        );
        let supervisor = Arc::new(
            Supervisor::new(
                &home,
                root.path(),
                config,
                secrets,
                store.clone(),
                proxy.clone(),
            )
            .unwrap(),
        );
        let checker = LocalChecker::new(
            home.clone(),
            Nat64Prefixes::default(),
            store.clone(),
            supervisor,
            Default::default(),
        );
        let service = InstallService::new(store.clone(), checker.clone())
            .await
            .unwrap();
        Self {
            _root: root,
            home,
            store,
            checker,
            service,
            _proxy: proxy,
        }
    }
    async fn checked(&self, version: &str) -> (String, InstallStatus) {
        let source = self._root.path().join(format!("source-{version}"));
        fs::create_dir(&source).unwrap();
        fs::write(source.join("fictor.yaml"), json!({"schema":1,"id":"local-review","version":version,"description":"Local review fixture","runtime":{"kind":"none"},"scope":"global","mcp":false}).to_string()).unwrap();
        let id = self
            .service
            .prepare(source.to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(
            self.store.proposal(id.clone()).await.unwrap().source,
            json!({"kind":"local"})
        );
        let status = self.wait(&id, ProposalState::Checked).await;
        assert!(
            InstallStatus::parse(serde_json::to_value(&status).unwrap(), &id).is_ok(),
            "the complete status emitted by the service must round-trip through the strict client parser"
        );
        fs::remove_dir_all(source).unwrap();
        (id, status)
    }
    async fn wait(&self, id: &str, target: ProposalState) -> InstallStatus {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let status = match self.service.status(id.into(), None).await {
                    Err(error)
                        if error.reason == MutationReason::Busy
                            && error.effect == fictor::admin::Effect::None =>
                    {
                        tokio::task::yield_now().await;
                        continue;
                    }
                    result => result.unwrap(),
                };
                if status.state == target {
                    return status;
                }
                assert!(!matches!(
                    status.state,
                    ProposalState::Failed | ProposalState::Rejected
                ));
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap()
    }
    async fn approve(&self, id: &str, status: &InstallStatus) {
        assert_eq!(
            status.review.as_ref().unwrap().hash().unwrap(),
            status.review_hash.clone().unwrap()
        );
        self.service
            .decision(
                id.into(),
                status.nonce.clone().unwrap(),
                status.review_hash.clone().unwrap(),
                true,
                Overrides::default(),
            )
            .await
            .unwrap();
    }
}
fn reason(error: AdminMutationError) -> MutationReason {
    error.reason
}

#[tokio::test]
async fn online_review_binds_nonce_and_promotion_without_reopening_the_origin() {
    let f = Fixture::new().await;
    let (id, checked) = f.checked("1.0.0").await;
    assert!(checked.review.as_ref().unwrap().base.is_none());
    let before = f.store.session("sys".into()).await.unwrap().head_id;
    assert_eq!(
        reason(
            f.service
                .decision(
                    id.clone(),
                    "a".repeat(64),
                    checked.review_hash.clone().unwrap(),
                    true,
                    Overrides::default()
                )
                .await
                .unwrap_err()
        ),
        MutationReason::InvalidNonce
    );
    assert_eq!(f.store.session("sys".into()).await.unwrap().head_id, before);
    f.approve(&id, &checked).await;
    assert_eq!(
        reason(
            f.service
                .decision(
                    id.clone(),
                    checked.nonce.unwrap(),
                    checked.review_hash.unwrap(),
                    true,
                    Overrides::default()
                )
                .await
                .unwrap_err()
        ),
        MutationReason::InvalidState
    );
    let admission = f.service.promote(id.clone()).await.unwrap();
    let promoted = f.wait(&id, ProposalState::Promoted).await;
    assert!(promoted.nonce.is_none());
    assert_eq!(promoted.promotion.as_ref().unwrap().state, "committed");
    assert_eq!(
        promoted.promotion.as_ref().unwrap().operation_id,
        admission["operation_id"]
    );
    assert_eq!(f.service.promote(id).await.unwrap(), admission);
    assert!(
        Lock::load_required(&f.home)
            .unwrap()
            .extensions
            .contains_key("local-review")
    );
}

#[tokio::test]
async fn rejecting_the_presented_review_can_use_its_old_base_but_restart_cannot_invent_it() {
    let f = Fixture::new().await;
    let (first, status) = f.checked("1.0.0").await;
    f.approve(&first, &status).await;
    f.service.promote(first.clone()).await.unwrap();
    f.wait(&first, ProposalState::Promoted).await;
    let (id, checked) = f.checked("2.0.0").await;
    let path = f.home.join("extensions/lock.json");
    let mut lock: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    lock["extensions"]["local-review"]["enabled"] = false.into();
    fs::write(path, lock.to_string()).unwrap();
    assert_eq!(
        reason(
            f.service
                .decision(
                    id.clone(),
                    checked.nonce.clone().unwrap(),
                    checked.review_hash.clone().unwrap(),
                    true,
                    Overrides::default()
                )
                .await
                .unwrap_err()
        ),
        MutationReason::StaleBase
    );
    let restarted = InstallService::new(f.store.clone(), f.checker.clone())
        .await
        .unwrap();
    assert_eq!(
        reason(
            restarted
                .decision(
                    id.clone(),
                    checked.nonce.clone().unwrap(),
                    checked.review_hash.clone().unwrap(),
                    false,
                    Overrides::default()
                )
                .await
                .unwrap_err()
        ),
        MutationReason::StaleBase
    );
    assert_eq!(
        f.service
            .decision(
                id,
                checked.nonce.unwrap(),
                checked.review_hash.unwrap(),
                false,
                Overrides::default()
            )
            .await
            .unwrap(),
        ProposalState::Rejected
    );
}

#[tokio::test]
async fn a_review_that_does_not_fit_is_never_presented_or_authorized() {
    let f = Fixture::new().await;
    let (id, _) = f.checked("1.0.0").await;
    let proposal = f.store.proposal(id.clone()).await.unwrap();
    let mut checks = serde_json::to_value(proposal.checks.unwrap()).unwrap();
    checks.as_array_mut().unwrap().push(json!({"name":"diagnostic","passed":true,"blocking":false,"detail":"x".repeat(fictor::kernel::MAX_MESSAGE_BYTES)}));
    let key = id.clone();
    f.store
        .write(move |db| {
            db.execute(
                "UPDATE proposals SET checks=?1 WHERE id=?2",
                [checks.to_string(), key],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        reason(f.service.status(id.clone(), None).await.err().unwrap()),
        MutationReason::TooLarge
    );
    assert_eq!(
        f.store.proposal(id).await.unwrap().state,
        ProposalState::Checked
    );
}

#[derive(Clone)]
struct CliService {
    inner: InstallService,
    source: PathBuf,
    malformed_review: bool,
    publication_script: bool,
    publication_observation: Arc<std::sync::atomic::AtomicUsize>,
    calls: Arc<std::sync::Mutex<Vec<String>>>,
    proposal: Arc<std::sync::Mutex<Option<String>>>,
}
impl fictor::admin::AdminMutationHandler for CliService {
    fn call_mutation<'a>(
        &'a self,
        method: &'a str,
        params: &'a Value,
    ) -> fictor::admin::AdminMutationFuture<'a> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(method.into());
            let mut value = self.inner.call_mutation(method, params).await?;
            if method == "ext.install.prepare" {
                *self.proposal.lock().unwrap() = value["proposal_id"].as_str().map(str::to_owned);
            }
            if method == "ext.install.status" && value["state"] == "checked" {
                // The remaining client flow must consume the receipt and review,
                // even when the original local directory has ceased to exist.
                if self.source.exists() {
                    fs::remove_dir_all(&self.source).unwrap();
                }
                if self.malformed_review {
                    value["review"]["manifest"]["description"] = json!("tampered after hashing");
                }
            }
            if method == "ext.install.status"
                && self.publication_script
                && value["state"] == "promoted"
            {
                match self
                    .publication_observation
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                {
                    0 => {
                        value["state"] = json!("approved");
                        value["promotion"]["state"] = json!("prepared");
                    }
                    1 => return Err(AdminMutationError::none(MutationReason::Busy)),
                    _ => {}
                }
            }
            Ok(value)
        })
    }
}
fn cli_source(fixture: &Fixture, name: &str, description: &str) -> PathBuf {
    let source = fixture._root.path().join(name);
    fs::create_dir(&source).unwrap();
    fs::write(source.join("fictor.yaml"), json!({"schema":1,"id":"local-review","version":"1.0.0","description":description,"runtime":{"kind":"none"},"scope":"global","mcp":false}).to_string()).unwrap();
    source
}
async fn cli_output(
    home: &std::path::Path,
    arguments: &[&std::ffi::OsStr],
    stdin: bool,
) -> std::process::Output {
    use std::os::unix::process::CommandExt;
    use tokio::io::AsyncWriteExt;
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_fictor"));
    command
        .env("FICTOR_HOME", home)
        .args(["ext", "install"])
        .args(arguments)
        .stdin(if stdin {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // Deliberately remove the inherited controlling TTY even when cargo itself
    // was started interactively. Redirected stdin must never grant consent.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut child = tokio::process::Command::from(command)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    if stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"sim\n")
            .await
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(12), child.wait_with_output())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_yes_displays_safe_complete_review_installs_and_resume_never_reopens_source() {
    let f = Fixture::new().await;
    let source = cli_source(&f, "cli-source", "declared\u{1b}[31mcontrol\u{202e}bidi");
    let service = Arc::new(CliService {
        inner: f.service.clone(),
        source: source.clone(),
        malformed_review: false,
        publication_script: true,
        publication_observation: Arc::default(),
        calls: Arc::default(),
        proposal: Arc::default(),
    });
    let server = fictor::admin::AdminServer::builder(f.store.owner().clone())
        .with_installer(service.clone())
        .bind()
        .await
        .unwrap();
    let output = cli_output(
        &f.home,
        &[source.as_os_str(), std::ffi::OsStr::new("--yes")],
        false,
    )
    .await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.stdout.contains(&0x1b));
    let text = String::from_utf8(output.stdout).unwrap();
    for field in [
        "manifest",
        "base",
        "differences",
        "tools",
        "packages",
        "checks",
        "omitted_fs",
        "overrides",
    ] {
        assert!(text.contains(field), "missing review field {field}");
    }
    assert!(text.contains("\\u001b[31m") && text.contains("\\u{202e}"));
    assert!(!text.contains('\u{202e}'));
    assert!(!source.exists());
    assert!(
        service
            .publication_observation
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 3
    );
    let id = service.proposal.lock().unwrap().clone().unwrap();
    let proposal = f.store.proposal(id.clone()).await.unwrap();
    assert_eq!(proposal.state, ProposalState::Promoted);
    assert_eq!(proposal.decided_by.as_deref(), Some("user"));
    assert_eq!(
        f.service
            .status(id.clone(), None)
            .await
            .unwrap()
            .promotion
            .unwrap()
            .state,
        "committed"
    );
    let resumed = cli_output(
        &f.home,
        &[std::ffi::OsStr::new("--resume"), std::ffi::OsStr::new(&id)],
        false,
    )
    .await;
    assert!(
        resumed.status.success(),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    let calls = service.calls.lock().unwrap().clone();
    for method in [
        "ext.install.prepare",
        "ext.install.decision",
        "ext.install.promote",
    ] {
        assert_eq!(
            calls.iter().filter(|call| call.as_str() == method).count(),
            1,
            "{calls:?}"
        );
    }
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_yes_rejects_a_tampered_review_before_decision_and_stdin_cannot_confirm_resume() {
    let f = Fixture::new().await;
    let source = cli_source(&f, "cli-tampered", "valid declared description");
    let service = Arc::new(CliService {
        inner: f.service.clone(),
        source: source.clone(),
        malformed_review: true,
        publication_script: false,
        publication_observation: Arc::default(),
        calls: Arc::default(),
        proposal: Arc::default(),
    });
    let server = fictor::admin::AdminServer::builder(f.store.owner().clone())
        .with_installer(service.clone())
        .bind()
        .await
        .unwrap();
    let output = cli_output(
        &f.home,
        &[source.as_os_str(), std::ffi::OsStr::new("--yes")],
        false,
    )
    .await;
    assert!(!output.status.success());
    let id = service.proposal.lock().unwrap().clone().unwrap();
    assert_eq!(
        f.store.proposal(id.clone()).await.unwrap().state,
        ProposalState::Checked
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("--resume"));
    assert!(
        !service
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|method| method == "ext.install.decision" || method == "ext.install.promote")
    );
    server.shutdown().await.unwrap();
    let server = fictor::admin::AdminServer::builder(f.store.owner().clone())
        .with_installer(Arc::new(f.service.clone()))
        .bind()
        .await
        .unwrap();
    let resumed = cli_output(
        &f.home,
        &[std::ffi::OsStr::new("--resume"), std::ffi::OsStr::new(&id)],
        true,
    )
    .await;
    assert!(!resumed.status.success());
    assert!(String::from_utf8_lossy(&resumed.stderr).contains("TTY"));
    assert_eq!(
        f.store.proposal(id.clone()).await.unwrap().state,
        ProposalState::Checked
    );
    let status = f.service.status(id.clone(), None).await.unwrap();
    f.approve(&id, &status).await;
    let approved = cli_output(
        &f.home,
        &[std::ffi::OsStr::new("--resume"), std::ffi::OsStr::new(&id)],
        true,
    )
    .await;
    assert!(!approved.status.success());
    assert_eq!(
        f.store.proposal(id.clone()).await.unwrap().state,
        ProposalState::Approved
    );
    assert!(
        f.service
            .status(id, None)
            .await
            .unwrap()
            .promotion
            .is_none()
    );
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_lost_prepare_or_decision_reply_never_retries_or_promotes() {
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    for lost in ["ext.install.prepare", "ext.install.decision"] {
        let f = Fixture::new().await;
        let source = cli_source(&f, "cli-lost", "lost response fixture");
        let path = f.home.join("run/admin.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let service = f.service.clone();
        let mut task = tokio::spawn(async move {
            let mut calls = Vec::new();
            let mut proposal = None;
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                let request: Value = serde_json::from_str(&line).unwrap();
                let method = request["method"].as_str().unwrap();
                calls.push(method.to_owned());
                let result = service
                    .call_mutation(method, &request["params"])
                    .await
                    .unwrap();
                if method == "ext.install.prepare" {
                    proposal = result["proposal_id"].as_str().map(str::to_owned);
                }
                if method == lost {
                    drop(stream);
                    return (proposal.unwrap(), calls);
                }
                let mut response = serde_json::to_vec(
                    &json!({"jsonrpc":"2.0","id":request["id"],"result":result}),
                )
                .unwrap();
                response.push(b'\n');
                stream.get_mut().write_all(&response).await.unwrap();
                stream.get_mut().shutdown().await.unwrap();
            }
        });
        let output = cli_output(
            &f.home,
            &[source.as_os_str(), std::ffi::OsStr::new("--yes")],
            false,
        )
        .await;
        assert!(!output.status.success());
        let result = tokio::time::timeout(Duration::from_secs(2), &mut task).await;
        if result.is_err() {
            task.abort();
            let _ = task.await;
            panic!(
                "client stopped before the lost-response boundary: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let (id, calls) = result.unwrap().unwrap();
        assert_eq!(
            calls
                .iter()
                .filter(|method| method.as_str() == lost)
                .count(),
            1
        );
        assert!(!calls.iter().any(|method| method == "ext.install.promote"));
        let error = String::from_utf8(output.stderr).unwrap();
        if lost == "ext.install.prepare" {
            assert!(error.contains("ID da proposta desconhecido"));
            f.wait(&id, ProposalState::Checked).await;
        } else {
            assert!(error.contains(&id) && error.contains("--resume"));
            assert_eq!(
                f.store.proposal(id.clone()).await.unwrap().state,
                ProposalState::Approved
            );
        }
        assert!(
            f.service
                .status(id, None)
                .await
                .unwrap()
                .promotion
                .is_none()
        );
    }
}

struct ObservedPromotion {
    service: InstallService,
    state: &'static str,
    operation: String,
    calls: Arc<std::sync::Mutex<Vec<String>>>,
    second_status: Arc<tokio::sync::Notify>,
}
impl AdminMutationHandler for ObservedPromotion {
    fn call_mutation<'a>(
        &'a self,
        method: &'a str,
        params: &'a Value,
    ) -> fictor::admin::AdminMutationFuture<'a> {
        Box::pin(async move {
            let count = {
                let mut calls = self.calls.lock().unwrap();
                calls.push(method.into());
                calls.len()
            };
            if method != "ext.install.status" {
                return Err(AdminMutationError::none(MutationReason::InvalidState));
            }
            let mut response = self.service.call_mutation(method, params).await?;
            response["promotion"] = json!({"operation_id":self.operation,"state":self.state});
            if count >= 2 {
                self.second_status.notify_one();
            }
            Ok(response)
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_resume_only_observes_prepared_and_aborted_requires_current_tty_consent() {
    use std::os::unix::process::CommandExt;
    for state in ["prepared", "aborted"] {
        let f = Fixture::new().await;
        let (id, status) = f.checked("1.0.0").await;
        f.approve(&id, &status).await;
        let service = Arc::new(ObservedPromotion {
            service: f.service.clone(),
            state,
            operation: ulid::Ulid::generate().to_string(),
            calls: Arc::default(),
            second_status: Arc::default(),
        });
        let server = fictor::admin::AdminServer::builder(f.store.owner().clone())
            .with_installer(service.clone())
            .bind()
            .await
            .unwrap();
        let output = if state == "prepared" {
            let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_fictor"));
            command
                .env("FICTOR_HOME", &f.home)
                .args(["ext", "install", "--resume", &id])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            // SAFETY: only setsid and an errno read occur between fork and exec.
            unsafe {
                command.pre_exec(|| {
                    if libc::setsid() < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                });
            }
            let child = tokio::process::Command::from(command)
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            tokio::time::timeout(Duration::from_secs(5), service.second_status.notified())
                .await
                .unwrap();
            // Signal only the exact child created by this test, never a process
            // discovered from the host or from an unauthenticated PID file.
            let pid = i32::try_from(child.id().unwrap()).unwrap();
            assert_eq!(unsafe { libc::kill(pid, libc::SIGINT) }, 0);
            let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
                .await
                .unwrap()
                .unwrap();
            assert!(String::from_utf8_lossy(&output.stderr).contains("interrompida"));
            output
        } else {
            let output = cli_output(
                &f.home,
                &[std::ffi::OsStr::new("--resume"), std::ffi::OsStr::new(&id)],
                true,
            )
            .await;
            assert!(String::from_utf8_lossy(&output.stderr).contains("TTY"));
            output
        };
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(&id));
        assert!(
            service
                .calls
                .lock()
                .unwrap()
                .iter()
                .all(|method| method == "ext.install.status")
        );
        assert_eq!(
            f.store.proposal(id.clone()).await.unwrap().state,
            ProposalState::Approved
        );
        assert!(
            f.service
                .status(id, None)
                .await
                .unwrap()
                .promotion
                .is_none()
        );
        server.shutdown().await.unwrap();
    }
}
