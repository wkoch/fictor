//! Trusted launch, process ownership and lazy crash admission. The installer
//! supplies a validated bundle and explicit identity; no call is replayed here.
use crate::{
    config::Config,
    crash_recovery::{
        CrashClock, CrashObservation, CrashStderr, LinuxCrashClock, RecoveryKey, RecoveryStatus,
    },
    gateway::{AuditIdentity, CatalogInvalidation, McpConnection, PinnedCatalog},
    installer::{
        bundle::{self, BundleBudget, BundleProfile},
        manifest::{KernelScope, Manifest, Role, RuntimeKind, Scope},
    },
    kernel::{KernelError, KernelIdentity, KernelServer, LogFuture, LogRecord, LogSink},
    proxy::{EgressProxy, ProxyIdentity, ProxyToken, nat64::Nat64Prefixes},
    sandbox::{ProxyEndpoint, SandboxContext, SandboxPlan, SandboxProfile, Tier},
    secrets::{RedactionStream, Redactor, SecretStore},
    store::{AppendEvent, Provenance, Store},
};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        process::ExitStatusExt,
    },
    path::{Component, Path, PathBuf},
    process::{ExitStatus, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    process::{Child, ChildStderr, ChildStdin, ChildStdout},
    sync::{oneshot, watch},
};

const LOG_LIMIT: u64 = 10 * 1024 * 1024;

pub struct SmokeReport {
    pub catalog: PinnedCatalog,
    pub resources: Vec<rmcp::model::Resource>,
}

#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    #[error("manifest ou identidade de instância inválido")]
    Invalid,
    #[error("runtime não disponível nesta fase ou instalação")]
    Unsupported,
    #[error("caminho do supervisor inválido ou inseguro")]
    Path,
    #[error("segredo declarado indisponível")]
    Secret,
    #[error("sandbox indisponível ou perfil recusado")]
    Sandbox,
    #[error("proxy ou kernel indisponível")]
    Transport,
    #[error("não foi possível executar ou acompanhar a extensão")]
    Process,
    #[error("auditoria da extensão indisponível")]
    Audit,
    #[error("conexão MCP indisponível")]
    Mcp,
    #[error("extensão em backoff por {retry_after_ms} ms")]
    Backoff { retry_after_ms: i64 },
    #[error("extensão bloqueada por crash loop")]
    CrashLoop,
    #[error("promoção pendente impede admissão da extensão")]
    PromotionPending,
}

pub struct Supervisor {
    home: PathBuf,
    home_anchor: File,
    real_home: PathBuf,
    source_home: Option<PathBuf>,
    config: Arc<Config>,
    secrets: Arc<SecretStore>,
    store: Arc<Store>,
    proxy: Arc<EgressProxy>,
    nat64: Nat64Prefixes,
    fictor_exe: PathBuf,
    active: Arc<Mutex<BTreeSet<String>>>,
    logs: Mutex<BTreeMap<String, Arc<Mutex<RotatingLog>>>>,
    crash_clock: Arc<dyn CrashClock>,
    pending_crashes: Arc<Mutex<BTreeMap<RecoveryKey, CrashObservation>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessExit {
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub crashed: bool,
}

/// Dropping this handle kills the sandbox. Its detached owner confirms namespace
/// exit by reaping bubblewrap before releasing sockets or temporary paths.
pub struct ManagedInstance {
    pub instance_id: String,
    pid: u32,
    group: Arc<Mutex<Option<u32>>>,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    connection: Option<McpConnection>,
    pinned_hash: Option<String>,
    catalog_invalidation: CatalogInvalidation,
    audit: AuditIdentity,
    workspace: Option<PathBuf>,
    stop: watch::Sender<bool>,
    exit: watch::Receiver<Option<Result<ProcessExit, ()>>>,
}

struct LaunchRequest<'a> {
    manifest: &'a Manifest,
    bundle: &'a Path,
    key: &'a str,
    session_id: Option<&'a str>,
    workspace: Option<&'a Path>,
    smoke: bool,
    smoke_home: Option<tempfile::TempDir>,
    owner: Option<Arc<dyn Send + Sync>>,
}

impl Supervisor {
    pub fn new(
        home: impl AsRef<Path>,
        real_home: impl AsRef<Path>,
        config: Arc<Config>,
        secrets: Arc<SecretStore>,
        store: Arc<Store>,
        proxy: Arc<EgressProxy>,
    ) -> Result<Self, SupervisorError> {
        let home = canonical_directory(home.as_ref())?;
        // Pins identity only; exclusive ownership is the separate ADR-038 lease.
        let home_anchor =
            crate::sandbox::mounts::pin_home(&home).map_err(|_| SupervisorError::Sandbox)?;
        let real_home = canonical_directory(real_home.as_ref())?;
        let nat64 = Nat64Prefixes::new(&config.egress.nat64_prefixes)
            .map_err(|_| SupervisorError::Invalid)?;
        let fictor_exe = std::env::current_exe().map_err(|_| SupervisorError::Path)?;
        Ok(Self {
            home,
            home_anchor,
            real_home,
            source_home: None,
            config,
            secrets,
            store,
            proxy,
            nat64,
            fictor_exe,
            active: Arc::default(),
            logs: Mutex::default(),
            crash_clock: Arc::new(LinuxCrashClock),
            pending_crashes: Arc::default(),
        })
    }

    /// Trusted injection for deterministic recovery tests; extensions cannot
    /// select the host clock or request resets through the Kernel Protocol.
    pub fn with_crash_clock(mut self, clock: Arc<dyn CrashClock>) -> Self {
        self.crash_clock = clock;
        self
    }

    async fn require_recovery(&self, key: &RecoveryKey) -> Result<(), SupervisorError> {
        let pending = self
            .pending_crashes
            .lock()
            .map_err(|_| SupervisorError::Audit)?
            .get(key)
            .cloned();
        if let Some(observation) = pending {
            self.store
                .record_crash(observation.clone(), self.crash_clock.clone())
                .await
                .map_err(|_| SupervisorError::Audit)?;
            let mut pending = self
                .pending_crashes
                .lock()
                .map_err(|_| SupervisorError::Audit)?;
            if pending
                .get(key)
                .is_some_and(|current| current.instance_id == observation.instance_id)
            {
                pending.remove(key);
            }
        }
        match self
            .store
            .crash_availability(key.clone(), self.crash_clock.clone())
            .await
            .map_err(|_| SupervisorError::Audit)?
        {
            RecoveryStatus::Ready => Ok(()),
            RecoveryStatus::Backoff { retry_after_ms } => {
                Err(SupervisorError::Backoff { retry_after_ms })
            }
            RecoveryStatus::CrashLoop => Err(SupervisorError::CrashLoop),
        }
    }

    /// A trusted host executable override, principally for integration-test
    /// launchers on Linux where current_exe is the test harness, not __sandbox-init.
    pub fn with_fictor_exe(mut self, executable: PathBuf) -> Result<Self, SupervisorError> {
        self.fictor_exe =
            crate::sandbox::mounts::canonicalize(&executable).map_err(|_| SupervisorError::Path)?;
        if !self.fictor_exe.is_file() {
            return Err(SupervisorError::Path);
        }
        Ok(self)
    }

    pub async fn spawn(
        &self,
        manifest: &Manifest,
        bundle: &Path,
        key: &str,
        session_id: Option<&str>,
        workspace: Option<&Path>,
    ) -> Result<ManagedInstance, SupervisorError> {
        self.launch(LaunchRequest {
            manifest,
            bundle,
            key,
            session_id,
            workspace,
            smoke: false,
            smoke_home: None,
            owner: None,
        })
        .await
    }

    /// Consume the single ADR-037 snapshot; no permissions merge occurs here.
    pub async fn spawn_effective(
        &self,
        effective: &crate::installer::overrides::EffectiveManifest,
        bundle: &Path,
        key: &str,
        session_id: Option<&str>,
        workspace: Option<&Path>,
    ) -> Result<ManagedInstance, SupervisorError> {
        self.spawn(effective.manifest(), bundle, key, session_id, workspace)
            .await
    }

    /// Retain trusted caller resources through namespace confirmation, including
    /// startup failure or cancellation. This changes no grants or child inputs.
    pub async fn spawn_with_owner(
        &self,
        manifest: &Manifest,
        bundle: &Path,
        key: &str,
        session_id: Option<&str>,
        workspace: Option<&Path>,
        owner: Arc<dyn Send + Sync>,
    ) -> Result<ManagedInstance, SupervisorError> {
        self.launch(LaunchRequest {
            manifest,
            bundle,
            key,
            session_id,
            workspace,
            smoke: false,
            smoke_home: None,
            owner: Some(owner),
        })
        .await
    }

    /// Run MCP discovery entirely inside disposable core state. No production
    /// database, config, mutable extension data or real credential is exposed.
    pub async fn smoke(
        &self,
        manifest: &Manifest,
        bundle: &Path,
        key: &str,
    ) -> Result<SmokeReport, SupervisorError> {
        manifest
            .validate_with_nat64(&self.nat64)
            .map_err(|_| SupervisorError::Invalid)?;
        let provider_secrets = self
            .config
            .providers
            .values()
            .filter_map(|p| p.secret.clone())
            .collect();
        manifest
            .validate_provider_secrets(&provider_secrets)
            .map_err(|_| SupervisorError::Invalid)?;
        if manifest.runtime.kind == RuntimeKind::None {
            if manifest.mcp_enabled() || manifest.role == Role::Harness {
                return Err(SupervisorError::Unsupported);
            }
            return Ok(SmokeReport {
                catalog: PinnedCatalog::new(vec![]).map_err(|_| SupervisorError::Mcp)?,
                resources: vec![],
            });
        }
        // ADR-025: no global process is admitted before the Phase 1 watermark.
        if manifest.scope == Scope::Global {
            return Err(SupervisorError::Unsupported);
        }
        // ADR-028: verification has disposable template roots only. Keep the
        // reviewed manifest intact; explicit real-host grants apply after install.
        let mut smoke_manifest = manifest.clone();
        smoke_manifest
            .permissions
            .fs
            .read
            .retain(|p| p.starts_with("${"));
        smoke_manifest
            .permissions
            .fs
            .write
            .retain(|p| p.starts_with("${"));
        let manifest = &smoke_manifest;
        let disposable = tempfile::Builder::new()
            .prefix("fx-")
            .tempdir_in("/tmp")
            .map_err(|_| SupervisorError::Path)?;
        let home = disposable.path().join("core");
        crate::home::prepare(&home).map_err(|_| SupervisorError::Path)?;
        let mut config = Config::create_if_missing(&home).map_err(|_| SupervisorError::Path)?;
        config.runtimes = self.config.runtimes.clone();
        config.egress.nat64_prefixes = self.config.egress.nat64_prefixes.clone();
        config.providers.clear();
        config.sandbox.home_ro_files.clear();
        let store = Arc::new(
            Store::open(&home)
                .await
                .map_err(|_| SupervisorError::Audit)?,
        );
        let secrets = Arc::new(
            SecretStore::open_with_lease(
                store.owner().clone(),
                crate::secrets::BackendKind::File,
                self.secrets.redactor(),
            )
            .map_err(|_| SupervisorError::Secret)?,
        );
        let proxy = EgressProxy::bind_unix_with_nat64(
            home.join("run/proxy.sock"),
            store.clone(),
            vec![],
            self.nat64.clone(),
        )
        .await;
        let proxy = Arc::new(proxy.map_err(|_| SupervisorError::Transport)?);
        let destination = home.join("extensions/quarantine/bundle");
        let source = bundle.to_path_buf();
        let target = destination.clone();
        tokio::task::spawn_blocking(move || {
            bundle::copy_local(
                &source,
                &target,
                &BundleBudget::start(BundleProfile::PostDependencies),
            )
        })
        .await
        .map_err(|_| SupervisorError::Path)?
        .map_err(|_| SupervisorError::Path)?;
        let mut isolated = Self::new(
            &home,
            &self.real_home,
            Arc::new(config),
            secrets,
            store,
            proxy,
        )?
        .with_fictor_exe(self.fictor_exe.clone())?;
        isolated.source_home = Some(self.home.clone());
        let mut managed = isolated
            .launch(LaunchRequest {
                manifest,
                bundle: &destination,
                key,
                session_id: None,
                workspace: None,
                smoke: true,
                smoke_home: Some(disposable),
                owner: None,
            })
            .await?;
        let result = if manifest.mcp_enabled() {
            tokio::time::timeout(Duration::from_secs(15), async {
                let connection = managed.connect_mcp(None).await?;
                let catalog = connection.catalog().clone();
                let resources = connection
                    .resources()
                    .await
                    .map_err(|_| SupervisorError::Mcp)?;
                Ok(SmokeReport { catalog, resources })
            })
            .await
            .map_err(|_| SupervisorError::Mcp)
            .and_then(|result| result)
        } else {
            // A non-MCP executable may finish normally during startup.
            match tokio::time::timeout(Duration::from_millis(100), managed.wait()).await {
                Ok(Ok(exit)) if exit.code != Some(0) => Err(SupervisorError::Process),
                Ok(Err(error)) => Err(error),
                _ => Ok(SmokeReport {
                    catalog: PinnedCatalog::new(vec![]).map_err(|_| SupervisorError::Mcp)?,
                    resources: vec![],
                }),
            }
        };
        let stopped = managed.shutdown().await;
        result.and_then(|report| stopped.map(|_| report))
    }

    async fn launch(&self, request: LaunchRequest<'_>) -> Result<ManagedInstance, SupervisorError> {
        let LaunchRequest {
            manifest,
            bundle,
            key,
            session_id,
            workspace,
            smoke,
            smoke_home,
            owner,
        } = request;
        manifest
            .validate_with_nat64(&self.nat64)
            .map_err(|_| SupervisorError::Invalid)?;
        let provider_secrets = self
            .config
            .providers
            .values()
            .filter_map(|p| p.secret.clone())
            .collect();
        manifest
            .validate_provider_secrets(&provider_secrets)
            .map_err(|_| SupervisorError::Invalid)?;
        // ADR-025: global processes require the Phase 1 watermark.
        if manifest.scope == Scope::Global {
            return Err(SupervisorError::Unsupported);
        }
        if matches!(
            manifest.runtime.kind,
            RuntimeKind::None | RuntimeKind::Remote
        ) {
            return Err(SupervisorError::Unsupported);
        }
        if key.is_empty() || key.chars().any(char::is_control) {
            return Err(SupervisorError::Invalid);
        }
        let id = ulid::Ulid::generate().to_string();
        let logical = if smoke {
            format!("smoke:{id}")
        } else {
            match manifest.scope {
                Scope::Global if session_id.is_none() && workspace.is_none() => manifest.id.clone(),
                Scope::Session if session_id.is_some() && workspace.is_some() => {
                    let session = session_id.ok_or(SupervisorError::Invalid)?;
                    if session.len() != 26 || session.parse::<ulid::Ulid>().is_err() {
                        return Err(SupervisorError::Invalid);
                    }
                    format!("{}@{session}", manifest.id)
                }
                _ => return Err(SupervisorError::Invalid),
            }
        };
        // A smoke Supervisor owns a separate disposable Store/home; its gate
        // cannot deadlock the original installer's admission section.
        let mut admission = Some(self.store.owner().installer_gate().lock_owned().await);
        let recovery = RecoveryKey {
            ext_id: manifest.id.clone(),
            key: key.into(),
            session_id: session_id.map(str::to_owned),
        };
        if !smoke
            && self
                .store
                .pending_promotion()
                .await
                .map_err(|_| SupervisorError::Audit)?
                .is_some()
        {
            return Err(SupervisorError::PromotionPending);
        }
        let reservation = Reservation::new(self.active.clone(), logical)?;
        let bundle = canonical_directory(bundle)?;
        let quarantine = self.home.join("extensions/quarantine");
        let store_root = self.home.join("extensions/store");
        let parent = if smoke { &quarantine } else { &store_root };
        if bundle == *parent || !bundle.starts_with(parent) {
            return Err(SupervisorError::Path);
        }
        if !smoke
            && (Path::new(key).components().count() != 1
                || !matches!(
                    Path::new(key).components().next(),
                    Some(Component::Normal(_))
                )
                || bundle != store_root.join(&manifest.id).join(key))
        {
            return Err(SupervisorError::Path);
        }
        let temporary = create_temporary(&id)?;
        let tmp = crate::sandbox::mounts::canonicalize(temporary.path())
            .map_err(|_| SupervisorError::Path)?;
        ensure_directory(&tmp, &tmp.join("home"))?;
        let mut session = if smoke && manifest.scope == Scope::Session {
            Some(ulid::Ulid::generate().to_string())
        } else {
            session_id.map(str::to_owned)
        };
        let workspace = if smoke && manifest.scope == Scope::Session {
            let path = tmp.join("workspace");
            ensure_directory(&tmp, &path)?;
            Some(path)
        } else {
            workspace.map(canonical_directory).transpose()?
        };
        if let Some(workspace) = &workspace
            && (workspace.parent().is_none()
                || workspace == &self.real_home
                || overlaps(workspace, &self.home))
        {
            return Err(SupervisorError::Path);
        }
        if let Some(workspace) = &workspace {
            crate::sandbox::mounts::check_workspace(&self.home, &self.home_anchor, workspace)
                .map_err(|_| SupervisorError::Sandbox)?;
        }
        if smoke && manifest.scope == Scope::Session {
            let created = self
                .store
                .create_session(crate::store::NewSession {
                    title: "Isolated smoke".into(),
                    workspace: workspace.clone().ok_or(SupervisorError::Invalid)?,
                    workspace_trust: crate::store::Trust::Untrusted,
                    harness: manifest.id.clone(),
                    mode: crate::config::Mode::Plan,
                    model: None,
                })
                .await
                .map_err(|_| SupervisorError::Audit)?;
            session = Some(created.id);
        }
        if let Some(session) = &session {
            let stored =
                self.store
                    .session(session.clone())
                    .await
                    .map_err(|error| match error {
                        crate::store::StoreError::NotFound => SupervisorError::Invalid,
                        _ => SupervisorError::Audit,
                    })?;
            // The session, rather than a caller-supplied path, owns the
            // workspace identity. Check even MCP-only processes without kernel.
            if stored.archived
                || stored.kind == "system"
                || stored.workspace.as_deref().map(Path::new) != workspace.as_deref()
            {
                return Err(SupervisorError::Invalid);
            }
        }
        if !smoke {
            self.require_recovery(&recovery).await?;
        }
        let data_base = self.home.join("extensions/data");
        let data = if smoke {
            data_base.join(&manifest.id).join("smoke").join(&id)
        } else if let Some(session) = &session {
            data_base.join(&manifest.id).join("sessions").join(session)
        } else {
            data_base.join(&manifest.id)
        };
        ensure_directory(&self.home, &data)?;
        let smoke_data = smoke.then(|| RemoveDirectory(data.clone()));
        let paths = Paths {
            bundle: &bundle,
            data: &data,
            tmp: &tmp,
            store: &store_root,
            workspace: workspace.as_deref(),
            home: &self.real_home,
        };
        let read = manifest
            .permissions
            .fs
            .read
            .iter()
            .map(|p| expand_path(p, &paths))
            .collect::<Result<Vec<_>, _>>()?;
        let write = manifest
            .permissions
            .fs
            .write
            .iter()
            .map(|p| expand_path(p, &paths))
            .collect::<Result<Vec<_>, _>>()?;
        let mut environment = manifest.permissions.env.clone();
        let redactor = self.secrets.redactor();
        if smoke {
            for binding in &manifest.permissions.secrets {
                let value = format!("fictor_honey_{}", ulid::Ulid::generate());
                redactor
                    .register(&value)
                    .map_err(|_| SupervisorError::Secret)?;
                environment.insert(binding.env.clone(), value);
            }
        } else {
            let secrets = self.secrets.clone();
            let bindings = manifest.permissions.secrets.clone();
            let values = tokio::task::spawn_blocking(move || {
                bindings
                    .into_iter()
                    .map(|binding| {
                        secrets
                            .get(&binding.name)
                            .map(|value| (binding.env, value.expose().to_owned()))
                            .map_err(|_| SupervisorError::Secret)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .await
            .map_err(|_| SupervisorError::Secret)??;
            environment.extend(values);
        }
        let identity = ProxyIdentity {
            instance_id: id.clone(),
            ext_id: manifest.id.clone(),
            session_id: if smoke { None } else { session.clone() },
        };
        let patterns = if smoke {
            &[][..]
        } else {
            &manifest.permissions.net.allow
        };
        let models = if smoke {
            &[][..]
        } else {
            &manifest.permissions.models
        };
        let token = self
            .proxy
            .register_with_models(identity, patterns, models)
            .map_err(|_| SupervisorError::Transport)?;
        let registration = Registration {
            proxy: self.proxy.clone(),
            token,
        };
        redactor
            .register(registration.token.expose())
            .map_err(|_| SupervisorError::Secret)?;
        // The standard Basic encoding is also an authentication credential.
        let basic = registration.token.basic_header();
        redactor
            .register(&basic)
            .map_err(|_| SupervisorError::Secret)?;
        if let Some(encoded) = basic.strip_prefix("Basic ") {
            redactor
                .register(encoded)
                .map_err(|_| SupervisorError::Secret)?;
        }
        let endpoint = proxy_endpoint(&self.proxy)?;
        let proxy_port = 3128;
        let proxy_url = format!(
            "http://fx:{}@127.0.0.1:{proxy_port}",
            registration.token.expose()
        );
        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            environment.insert(name.into(), proxy_url.clone());
        }
        environment.insert("FICTOR_EXT_ID".into(), manifest.id.clone());
        environment.insert("FICTOR_INSTANCE_ID".into(), id.clone());
        if let Some(session) = &session {
            environment.insert("FICTOR_SESSION_ID".into(), session.clone());
            environment.insert(
                "FICTOR_WORKSPACE".into(),
                utf8(workspace.as_deref().ok_or(SupervisorError::Invalid)?)?,
            );
        }
        if !models.is_empty() {
            environment.insert(
                "FICTOR_MODELS_URL".into(),
                "http://models.fictor.internal/p".into(),
            );
        }
        let log = self.log(&manifest.id)?;
        // Smoke launches use a completely separate home and Store.
        let mut kernel = if !manifest.kernel.is_empty() {
            let scopes = manifest
                .kernel
                .iter()
                .map(|s| {
                    serde_json::to_value(s)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_owned))
                        .ok_or(SupervisorError::Invalid)
                })
                .collect::<Result<BTreeSet<_>, _>>()?;
            let kernel = KernelServer::bind_with_log(
                &self.home,
                KernelIdentity {
                    ext_id: manifest.id.clone(),
                    instance_id: id.clone(),
                    session_id: session.clone(),
                    is_harness: manifest.role == Role::Harness,
                    scopes,
                },
                self.store.clone(),
                self.config.providers.keys().cloned().collect(),
                Some(Arc::new(ExtensionLog {
                    log: log.clone(),
                    redactor: redactor.clone(),
                })),
            )
            .await
            .map_err(|_| SupervisorError::Transport)?;
            redactor
                .register(kernel.token())
                .map_err(|_| SupervisorError::Secret)?;
            environment.insert("FICTOR_KERNEL_TOKEN".into(), kernel.token().to_owned());
            Some(kernel)
        } else {
            None
        };
        let kernel_socket = kernel.as_ref().map(|k| k.socket_path().to_path_buf());
        // I11: model-facing processes receive private input through the kernel,
        // never via implicit real-home mounts that bypass provenance tracking.
        let mediated =
            manifest.role == Role::Harness || manifest.kernel.contains(&KernelScope::Tools);
        let home_ro_files = if !smoke && session.is_some() && !mediated {
            self.config
                .sandbox
                .home_ro_files
                .iter()
                .map(|path| expand_home_file(path, &self.real_home))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };
        let mut runtime_read = read.clone();
        runtime_read.extend(home_ro_files.iter().cloned());
        if manifest.role == Role::Harness {
            runtime_read.push(store_root.clone());
        }
        let (runtime, runtime_root, arguments) = runtime_command(
            manifest,
            &paths,
            RuntimeGrants {
                read: &runtime_read,
                write: &write,
            },
            &mut environment,
        )?;
        // Changing FICTOR_HOME for smoke must not turn a configured runtime
        // installation under the production core into a readable directory.
        if self
            .source_home
            .as_ref()
            .is_some_and(|source| overlaps(&runtime_root, source))
        {
            return Err(SupervisorError::Sandbox);
        }
        let plan = SandboxPlan::new_anchored(
            SandboxProfile {
                read_paths: read,
                write_paths: write,
                spawn: manifest.permissions.spawn,
                kernel_socket,
                proxy: endpoint,
                env: environment,
                cwd: bundle.clone(),
                tier: Tier::Os,
            },
            SandboxContext {
                fictor_home: self.home.clone(),
                real_home: self.real_home.clone(),
                bundle_root: bundle,
                ext_data: data,
                tmp_dir: tmp,
                runtime,
                runtime_root,
                fictor_exe: self.fictor_exe.clone(),
                home_ro_files,
                allow_store_read: manifest.role == Role::Harness,
            },
            arguments,
            &self.home_anchor,
        )
        .map_err(|_| SupervisorError::Sandbox)?;
        let mut command =
            tokio::process::Command::from(plan.command().map_err(|_| SupervisorError::Sandbox)?);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let stream = redactor.stream().map_err(|_| SupervisorError::Secret)?;
        // Reserve the path before a process exists. After spawn every failure
        // belongs to the detached owner; no `?` may release live instance paths.
        let pid_path = self.home.join("run").join(format!("{id}.pid"));
        let (pid_file, mut pid_record) = prepare_pid(&pid_path)?;
        let mut child = command.spawn().map_err(|_| SupervisorError::Process)?;
        let pid = child.id().unwrap_or(0);
        let mut startup_error = if pid == 0 {
            Some(SupervisorError::Process)
        } else {
            record_pid(&mut pid_record, pid).err()
        };
        drop(pid_record);
        let group = Arc::new(Mutex::new(Some(pid)));
        let guard = GroupGuard {
            pid,
            group: group.clone(),
        };
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        if stdin.is_none() || stdout.is_none() || stderr.is_none() {
            startup_error.get_or_insert(SupervisorError::Process);
        }
        let (stop, stop_receiver) = watch::channel(false);
        let catalog_invalidation = CatalogInvalidation::new(stop.clone());
        let (exit_sender, exit) = watch::channel(None);
        let (ready, started) = oneshot::channel();
        let audit = AuditIdentity {
            store: self.store.clone(),
            ext_id: manifest.id.clone(),
            key: key.into(),
            instance_id: id.clone(),
        };
        let managed = ManagedInstance {
            instance_id: id.clone(),
            pid,
            group,
            stdin,
            stdout,
            connection: None,
            pinned_hash: None,
            catalog_invalidation: catalog_invalidation.clone(),
            audit: audit.clone(),
            workspace,
            stop,
            exit,
        };
        let crash_clock = self.crash_clock.clone();
        let pending_crashes = self.pending_crashes.clone();
        tokio::spawn(async move {
            // Mount source descriptors stay pinned until reap, including the
            // interval before __sandbox-init verifies its post-mount proof.
            let _ownership = (temporary, smoke_data, pid_file, smoke_home, owner, plan);
            let mut reservation = Some(reservation);
            let stderr = tokio::spawn(async move {
                match stderr {
                    Some(stderr) => drain_stderr(stderr, log, stream).await,
                    None => Err(SupervisorError::Process),
                }
            });
            if startup_error.is_none() {
                startup_error = audit_event(&audit, "ext.started", json!({"ext_id":audit.ext_id,"instance_id":id,"key":audit.key,"pid":pid,"smoke":smoke}), vec![]).await.err();
            }
            let success = startup_error.is_none();
            let failed_ready = if success {
                // The detached owner holds admission across caller cancellation
                // after fork, but not throughout the process's active lifetime.
                admission.take();
                let _ = ready.send(Ok(()));
                None
            } else {
                Some(ready)
            };
            let outcome = supervise(
                &mut child,
                stop_receiver,
                success,
                CleanupContext {
                    kernel: &mut kernel,
                    guard: &guard,
                    registration: &registration,
                    audit: &audit,
                    reservation: &mut reservation,
                    catalog_invalidation: &catalog_invalidation,
                },
            )
            .await;
            drop(registration); // Revoke before potentially waiting on inherited pipes.
            if let Some(kernel) = &kernel {
                kernel.revoke();
            }
            let tail = stderr.await;
            let stderr_failed = !matches!(&tail, Ok(Ok(_)));
            let tail = tail
                .ok()
                .and_then(Result::ok)
                .unwrap_or_else(|| b"[stderr capture unavailable]\n".to_vec());
            let kernel_failed = if let Some(kernel) = &mut kernel {
                kernel.shutdown().await.is_err()
            } else {
                false
            };
            // Re-read after namespace/transport shutdown: invalidation can race
            // a manual stop. This task owns both the audit and instance paths.
            let catalog_failed = if catalog_invalidation.is_invalidated() {
                audit_event(
                    &audit,
                    "ext.tools_changed",
                    json!({"ext_id":audit.ext_id,"key":audit.key,"instance_id":id}),
                    vec![],
                )
                .await
                .is_err()
            } else {
                false
            };
            let process_failed = outcome.is_err();
            let outcome = outcome.unwrap_or(ProcessExit {
                code: None,
                signal: None,
                crashed: false, // A monitor failure is not an observed crash.
            });
            let mut references = Vec::new();
            let mut payload = json!({"ext_id":audit.ext_id,"instance_id":id,"key":audit.key,"code":outcome.code,"signal":outcome.signal,"smoke":smoke});
            let mut blob_failed = false;
            if outcome.crashed {
                match audit.store.put_blob(tail).await {
                    Ok(hash) => {
                        payload["stderr_blob"] = hash.clone().into();
                        references.push(hash);
                    }
                    Err(_) => {
                        blob_failed = true;
                        payload["stderr_unavailable"] = true.into();
                    }
                }
            }
            if stderr_failed {
                payload["stderr_unavailable"] = true.into();
            }
            if process_failed {
                payload["process_error"] = true.into();
            }
            let audited = if outcome.crashed && !smoke {
                let observation = CrashObservation {
                    recovery,
                    instance_id: id.clone(),
                    code: outcome.code,
                    signal: outcome.signal,
                    stderr: CrashStderr {
                        blob: references.first().cloned(),
                        unavailable: stderr_failed || blob_failed,
                    },
                };
                let result = audit
                    .store
                    .record_crash(observation.clone(), crash_clock)
                    .await
                    .map(|_| ())
                    .map_err(|_| SupervisorError::Audit);
                if result.is_err()
                    && let Ok(mut pending) = pending_crashes.lock()
                {
                    // Keep this before releasing the active reservation. A new
                    // demand can retry only this audit, never the failed call.
                    pending.insert(observation.recovery.clone(), observation);
                }
                result
            } else {
                audit_event(
                    &audit,
                    if outcome.crashed {
                        "ext.crashed"
                    } else {
                        "ext.stopped"
                    },
                    payload,
                    references,
                )
                .await
            };
            let final_result = if audited.is_ok()
                && !stderr_failed
                && !kernel_failed
                && !process_failed
                && !blob_failed
                && !catalog_failed
            {
                Ok(outcome)
            } else {
                Err(())
            };
            // Observers of completion also observe PID and temporary-path cleanup.
            drop(kernel);
            drop(reservation);
            drop(guard);
            drop(_ownership);
            admission.take();
            exit_sender.send_replace(Some(final_result));
            if let Some(ready) = failed_ready {
                // An error hands control back only after bwrap has been reaped
                // and every internal/external resource has completed cleanup.
                let _ = ready.send(Err(startup_error.unwrap_or(SupervisorError::Audit)));
            }
        });
        match started.await {
            Ok(Ok(())) => Ok(managed),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(SupervisorError::Process),
        }
    }

    fn log(&self, id: &str) -> Result<Arc<Mutex<RotatingLog>>, SupervisorError> {
        let mut logs = self.logs.lock().map_err(|_| SupervisorError::Process)?;
        if let Some(log) = logs.get(id) {
            return Ok(log.clone());
        }
        let root = self.home.join("logs/ext");
        ensure_directory(&self.home, &root)?;
        let log = Arc::new(Mutex::new(
            RotatingLog::open(root.join(format!("{id}.log")))
                .map_err(|_| SupervisorError::Process)?,
        ));
        logs.insert(id.into(), log.clone());
        Ok(log)
    }
}

impl ManagedInstance {
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn connection(&self) -> Option<&McpConnection> {
        self.connection.as_ref()
    }
    pub async fn connect_mcp(
        &mut self,
        pin: Option<PinnedCatalog>,
    ) -> Result<&McpConnection, SupervisorError> {
        let pinned_hash = pin.as_ref().map(|pin| pin.hash().to_owned());
        if self.connection.is_some() && pinned_hash.is_some() && pinned_hash != self.pinned_hash {
            // Discovery cannot be upgraded into a pinned connection, nor can a
            // live connection switch its approved catalog without a new spawn.
            self.catalog_invalidation.invalidate();
            let _ = self.shutdown().await;
            return Err(SupervisorError::Mcp);
        }
        if self.connection.is_none() {
            // Once pipes leave the handle, a cancelled handshake cannot be
            // retried. Its Drop must hand shutdown to the existing process owner.
            let mut handshake = HandshakeGuard(Some(self.stop.clone()));
            let stdout = self.stdout.take().ok_or(SupervisorError::Mcp)?;
            let stdin = self.stdin.take().ok_or(SupervisorError::Mcp)?;
            let connection = McpConnection::connect_monitored(
                stdout,
                stdin,
                self.workspace.as_deref(),
                pin,
                self.audit.clone(),
                Some(self.catalog_invalidation.clone()),
            )
            .await;
            match connection {
                Ok(connection) => {
                    self.connection = Some(connection);
                    self.pinned_hash = pinned_hash;
                    handshake.0.take();
                }
                Err(_) => {
                    let _ = self.shutdown().await;
                    return Err(SupervisorError::Mcp);
                }
            }
        }
        self.connection.as_ref().ok_or(SupervisorError::Mcp)
    }
    pub async fn wait(&mut self) -> Result<ProcessExit, SupervisorError> {
        loop {
            if let Some(exit) = *self.exit.borrow() {
                return exit.map_err(|_| SupervisorError::Audit);
            }
            self.exit
                .changed()
                .await
                .map_err(|_| SupervisorError::Process)?;
        }
    }
    pub async fn shutdown(&mut self) -> Result<ProcessExit, SupervisorError> {
        self.shutdown_with_timeout(Duration::from_secs(10)).await
    }
    async fn shutdown_with_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<ProcessExit, SupervisorError> {
        self.stdin.take();
        self.stop.send_replace(true);
        let connection = self.connection.take();
        // A daemonized descendant may retain a pipe. Return a bounded failure,
        // while the detached owner retains guards/paths until cleanup is complete.
        tokio::time::timeout(timeout, async {
            if let Some(connection) = connection {
                let _ = tokio::time::timeout(Duration::from_secs(1), connection.shutdown()).await;
            }
            self.wait().await
        })
        .await
        .map_err(|_| SupervisorError::Process)?
    }
}

struct HandshakeGuard(Option<watch::Sender<bool>>);
impl Drop for HandshakeGuard {
    fn drop(&mut self) {
        if let Some(stop) = self.0.take() {
            stop.send_replace(true);
        }
    }
}
impl Drop for ManagedInstance {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        if let Ok(group) = self.group.lock()
            && let Some(pid) = *group
        {
            signal_group(pid, libc::SIGKILL);
        }
    }
}

struct CleanupContext<'a> {
    kernel: &'a mut Option<KernelServer>,
    guard: &'a GroupGuard,
    registration: &'a Registration,
    audit: &'a AuditIdentity,
    reservation: &'a mut Option<Reservation>,
    catalog_invalidation: &'a CatalogInvalidation,
}

async fn supervise(
    child: &mut Child,
    mut stop: watch::Receiver<bool>,
    started: bool,
    cleanup: CleanupContext<'_>,
) -> Result<ProcessExit, SupervisorError> {
    let CleanupContext {
        kernel,
        guard,
        registration,
        audit,
        reservation,
        catalog_invalidation,
    } = cleanup;
    let (status, mut crashed) = if !started {
        let _ = registration.proxy.revoke(&registration.token);
        if let Some(kernel) = &kernel {
            kernel.revoke();
        }
        let _ = child.start_kill();
        signal_group(guard.pid, libc::SIGKILL);
        let status = match tokio::time::timeout(Duration::from_secs(10), child.wait()).await {
            Ok(status) => status,
            Err(_) => {
                let _ = audit_event(
                    audit,
                    "ext.cleanup_failed",
                    json!({
                        "ext_id":audit.ext_id,"instance_id":audit.instance_id,"key":audit.key
                    }),
                    vec![],
                )
                .await;
                reservation.take();
                child.wait().await
            }
        };
        (status, false)
    } else {
        tokio::select! { biased;
            _ = stop.changed() => {
                // Graceful notice closes traffic while retaining the socket and
                // token registration until revocation after the grace period.
                if let Some(kernel) = kernel { kernel.notify_shutdown(); }
                let completed = {
                    let shutdown = async {
                        match tokio::time::timeout(Duration::from_secs(3), child.wait()).await {
                            Ok(status) => status,
                            Err(_) => {
                                let _ = registration.proxy.revoke(&registration.token);
                                if let Some(kernel) = &kernel { kernel.revoke(); }
                                signal_group(guard.pid, libc::SIGTERM);
                                match tokio::time::timeout(Duration::from_secs(2), child.wait()).await {
                                    Ok(status) => status,
                                    Err(_) => { signal_group(guard.pid, libc::SIGKILL); child.wait().await }
                                }
                            }
                        }
                    };
                    tokio::pin!(shutdown);
                    let terminal_catalog = async {
                        while !catalog_invalidation.is_invalidated() {
                            if stop.changed().await.is_err() {
                                std::future::pending::<()>().await;
                            }
                        }
                        // A failed security pin revokes access immediately, even
                        // when it races the grace period of a manual shutdown.
                        let _ = registration.proxy.revoke(&registration.token);
                        if let Some(kernel) = &kernel { kernel.revoke(); }
                    };
                    let shutdown = async {
                        tokio::select! {
                            status = &mut shutdown => status,
                            _ = terminal_catalog => shutdown.await,
                        }
                    };
                    tokio::time::timeout(Duration::from_secs(10), shutdown).await
                };
                let status = match completed {
                    Ok(status) => status,
                    Err(_) => {
                        let _ = registration.proxy.revoke(&registration.token);
                        if let Some(kernel) = &kernel { kernel.revoke(); }
                        signal_group(guard.pid, libc::SIGKILL);
                        let _ = audit_event(audit, "ext.cleanup_failed", json!({
                            "ext_id": audit.ext_id, "instance_id": audit.instance_id,
                            "key": audit.key
                        }), vec![]).await;
                        // A new identity may start, while this owner retains all
                        // resources belonging to the unconfirmed namespace.
                        reservation.take();
                        child.wait().await
                    }
                };
                (status, false)
            },
            status = child.wait() => (status, true),
        }
    };
    let _ = registration.proxy.revoke(&registration.token);
    if let Some(kernel) = kernel {
        kernel.revoke();
    }
    let mut status = status;
    if status.is_err() {
        // No exit was observed before the core requested cleanup. Do not infer
        // another crash from cleanup_failed or from a forced termination.
        crashed = false;
        signal_group(guard.pid, libc::SIGKILL);
        let _ = audit_event(
            audit,
            "ext.cleanup_failed",
            json!({
                "ext_id": audit.ext_id, "instance_id": audit.instance_id,
                "key": audit.key
            }),
            vec![],
        )
        .await;
        reservation.take();
    }
    // A failed wait is not confirmation. Keep the owner and all its resources
    // alive until the OS actually reports bubblewrap's exit.
    let status = loop {
        match status {
            Ok(status) => break status,
            Err(_) => {
                tokio::time::sleep(Duration::from_secs(1)).await;
                status = child.wait().await;
            }
        }
    };
    // ADR-029: bubblewrap exit confirms the PID namespace is empty, including
    // double-forked/setsid descendants. A host process group is not the tree.
    if let Ok(mut group) = guard.group.lock() {
        *group = None;
    }
    // The now-empty numeric group must never be signalled again, including Drop
    // of a caller handle whose stderr/audit completion is still pending.
    Ok(exit(status, crashed))
}
fn exit(status: ExitStatus, crashed: bool) -> ProcessExit {
    ProcessExit {
        code: status.code(),
        signal: status.signal(),
        crashed,
    }
}
struct GroupGuard {
    pid: u32,
    group: Arc<Mutex<Option<u32>>>,
}
impl Drop for GroupGuard {
    fn drop(&mut self) {
        if let Ok(mut group) = self.group.lock()
            && let Some(pid) = group.take()
        {
            signal_group(pid, libc::SIGKILL);
        }
    }
}
fn signal_group(pid: u32, signal: i32) {
    if pid == 0 {
        return;
    }
    if let Ok(pid) = i32::try_from(pid) {
        unsafe {
            libc::kill(-pid, signal);
        }
    }
}
struct Registration {
    proxy: Arc<EgressProxy>,
    token: ProxyToken,
}
impl Drop for Registration {
    fn drop(&mut self) {
        let _ = self.proxy.revoke(&self.token);
    }
}
struct Reservation {
    active: Arc<Mutex<BTreeSet<String>>>,
    key: String,
}
impl Reservation {
    fn new(active: Arc<Mutex<BTreeSet<String>>>, key: String) -> Result<Self, SupervisorError> {
        if !active
            .lock()
            .map_err(|_| SupervisorError::Process)?
            .insert(key.clone())
        {
            return Err(SupervisorError::Process);
        }
        Ok(Self { active, key })
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active.lock() {
            active.remove(&self.key);
        }
    }
}
struct RemoveDirectory(PathBuf);
impl Drop for RemoveDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct PidFile(PathBuf);
impl Drop for PidFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn prepare_pid(path: &Path) -> Result<(PidFile, File), SupervisorError> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| SupervisorError::Path)?;
    Ok((PidFile(path.into()), file))
}
fn record_pid(file: &mut File, pid: u32) -> Result<(), SupervisorError> {
    writeln!(file, "{pid}")
        .and_then(|_| file.sync_all())
        .map_err(|_| SupervisorError::Path)?;
    Ok(())
}
async fn audit_event(
    audit: &AuditIdentity,
    kind: &str,
    payload: serde_json::Value,
    blob_refs: Vec<String>,
) -> Result<(), SupervisorError> {
    audit
        .store
        .append(AppendEvent {
            session_id: "sys".into(),
            parent_id: None,
            kind: kind.into(),
            actor: "core".into(),
            payload,
            blob_refs,
            provenance: Provenance::core(),
        })
        .await
        .map(|_| ())
        .map_err(|_| SupervisorError::Audit)
}

struct Paths<'a> {
    bundle: &'a Path,
    data: &'a Path,
    tmp: &'a Path,
    store: &'a Path,
    workspace: Option<&'a Path>,
    home: &'a Path,
}
fn expand_path(value: &str, paths: &Paths<'_>) -> Result<PathBuf, SupervisorError> {
    if value.contains('\\')
        || value.chars().any(char::is_control)
        || value.split('/').any(|part| part == "..")
    {
        return Err(SupervisorError::Path);
    }
    let (root, suffix) = if let Some(value) = value.strip_prefix("${") {
        let (name, suffix) = value.split_once('}').ok_or(SupervisorError::Path)?;
        let root = match name {
            "ext_root" => paths.bundle,
            "ext_data" => paths.data,
            "tmp" => paths.tmp,
            "store" => paths.store,
            "workspace" => paths.workspace.ok_or(SupervisorError::Path)?,
            _ => return Err(SupervisorError::Path),
        };
        (root, suffix.strip_prefix('/').unwrap_or(suffix))
    } else if let Some(suffix) = value.strip_prefix("~/") {
        (paths.home, suffix)
    } else {
        return crate::sandbox::mounts::canonicalize(Path::new(value))
            .map_err(|_| SupervisorError::Path);
    };
    let candidate = root.join(suffix);
    let canonical =
        crate::sandbox::mounts::canonicalize(&candidate).map_err(|_| SupervisorError::Path)?;
    if !canonical.starts_with(root) {
        return Err(SupervisorError::Path);
    }
    Ok(canonical)
}
fn canonical_directory(path: &Path) -> Result<PathBuf, SupervisorError> {
    if !path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
        return Err(SupervisorError::Path);
    }
    let path = crate::sandbox::mounts::canonicalize(path).map_err(|_| SupervisorError::Path)?;
    if !path.is_dir() {
        return Err(SupervisorError::Path);
    }
    Ok(path)
}
fn ensure_directory(root: &Path, path: &Path) -> Result<(), SupervisorError> {
    let suffix = path.strip_prefix(root).map_err(|_| SupervisorError::Path)?;
    let mut current = root.to_path_buf();
    for component in suffix.components() {
        let Component::Normal(component) = component else {
            return Err(SupervisorError::Path);
        };
        current.push(component);
        crate::home::private_dir(&current).map_err(|_| SupervisorError::Path)?;
        let metadata = fs::symlink_metadata(&current).map_err(|_| SupervisorError::Path)?;
        if metadata.uid() != unsafe { libc::geteuid() }
            || !metadata.is_dir()
            || metadata.file_type().is_symlink()
        {
            return Err(SupervisorError::Path);
        }
    }
    Ok(())
}
fn create_temporary(id: &str) -> Result<tempfile::TempDir, SupervisorError> {
    let base = crate::sandbox::mounts::canonicalize(&std::env::temp_dir())
        .map_err(|_| SupervisorError::Path)?;
    let root = base.join("fictor");
    ensure_directory(&base, &root)?;
    tempfile::Builder::new()
        .prefix(id)
        .tempdir_in(root)
        .map_err(|_| SupervisorError::Path)
}
fn expand_home_file(value: &str, home: &Path) -> Result<PathBuf, SupervisorError> {
    let value = value
        .strip_prefix("~/")
        .map(|v| home.join(v))
        .unwrap_or_else(|| PathBuf::from(value));
    let canonical =
        crate::sandbox::mounts::canonicalize(&value).map_err(|_| SupervisorError::Path)?;
    if !canonical.starts_with(home) || !canonical.is_file() {
        return Err(SupervisorError::Path);
    }
    Ok(canonical)
}
fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}
fn utf8(path: &Path) -> Result<String, SupervisorError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or(SupervisorError::Path)
}
fn proxy_endpoint(proxy: &EgressProxy) -> Result<ProxyEndpoint, SupervisorError> {
    proxy
        .unix_path()
        .map(|p| ProxyEndpoint::Unix(p.into()))
        .ok_or(SupervisorError::Transport)
}

struct RuntimeGrants<'a> {
    read: &'a [PathBuf],
    write: &'a [PathBuf],
}
fn runtime_command(
    manifest: &Manifest,
    paths: &Paths<'_>,
    grants: RuntimeGrants<'_>,
    environment: &mut BTreeMap<String, String>,
) -> Result<(PathBuf, PathBuf, Vec<OsString>), SupervisorError> {
    let RuntimeGrants { read, write } = grants;
    let entry = crate::sandbox::mounts::canonicalize(
        &paths.bundle.join(
            manifest
                .runtime
                .entry
                .as_deref()
                .ok_or(SupervisorError::Unsupported)?,
        ),
    )
    .map_err(|_| SupervisorError::Path)?;
    if !entry.starts_with(paths.bundle) || !entry.is_file() {
        return Err(SupervisorError::Path);
    }
    let (runtime, root, mut args) = if manifest.runtime.kind == RuntimeKind::Binary {
        (entry.clone(), paths.bundle.to_path_buf(), Vec::new())
    } else {
        // M0.5 development bootstrap only. The managed/checksummed runtime
        // resolver belongs to M0.9; never use caller PATH or a config executable.
        if !Path::new("/run/.toolboxenv").is_file() {
            return Err(SupervisorError::Unsupported);
        }
        let runtime =
            crate::sandbox::mounts::canonicalize(Path::new(match manifest.runtime.kind {
                RuntimeKind::Node => "/usr/bin/node",
                RuntimeKind::Python => "/usr/bin/python3",
                _ => return Err(SupervisorError::Unsupported),
            }))
            .map_err(|_| SupervisorError::Unsupported)?;
        if !executable(&runtime) {
            return Err(SupervisorError::Unsupported);
        }
        let parent = runtime.parent().ok_or(SupervisorError::Path)?;
        let root = if parent.file_name().is_some_and(|v| v == "bin") {
            parent.parent().ok_or(SupervisorError::Path)?
        } else {
            parent
        }
        .to_path_buf();
        let mut args = Vec::new();
        if manifest.runtime.kind == RuntimeKind::Node {
            args = node_permissions(paths, &root, read, write, manifest.permissions.spawn)?;
            environment.insert("NODE_USE_ENV_PROXY".into(), "1".into());
        }
        if manifest.runtime.kind == RuntimeKind::Python {
            environment.insert("PYTHONPATH".into(), utf8(&paths.bundle.join(".pydeps"))?);
        }
        args.push("--".into());
        args.push(entry.into_os_string());
        (runtime, root, args)
    };
    args.extend(manifest.runtime.args.iter().map(OsString::from));
    Ok((runtime, root, args))
}

fn node_permissions(
    paths: &Paths<'_>,
    runtime_root: &Path,
    read: &[PathBuf],
    write: &[PathBuf],
    spawn: bool,
) -> Result<Vec<OsString>, SupervisorError> {
    // Node 24 LTS Permission Model (v24.x/api/permissions.html). Network
    // isolation is supplied by the namespace/proxy; --allow-net starts in v25.
    let mut args = vec![OsString::from("--permission")];
    for path in [paths.bundle, runtime_root, paths.data, paths.tmp]
        .into_iter()
        .chain(read.iter().map(PathBuf::as_path))
        .chain(write.iter().map(PathBuf::as_path))
    {
        node_path_permission(&mut args, "read", path)?;
    }
    for path in [paths.data, paths.tmp]
        .into_iter()
        .chain(write.iter().map(PathBuf::as_path))
    {
        node_path_permission(&mut args, "write", path)?;
    }
    if spawn {
        args.extend(["--allow-child-process", "--allow-worker"].map(OsString::from));
    }
    Ok(args)
}

fn node_path_permission(
    args: &mut Vec<OsString>,
    access: &str,
    path: &Path,
) -> Result<(), SupervisorError> {
    let path = utf8(path)?;
    // A literal host directory containing '*' must not become a Node wildcard.
    if path.contains('*') {
        return Err(SupervisorError::Path);
    }
    args.push(format!("--allow-fs-{access}={path}").into());
    Ok(())
}
fn executable(path: &Path) -> bool {
    fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

struct ExtensionLog {
    log: Arc<Mutex<RotatingLog>>,
    redactor: Redactor,
}
impl LogSink for ExtensionLog {
    fn write(&self, record: LogRecord) -> LogFuture {
        let log = self.log.clone();
        let redactor = self.redactor.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                // Ordinary diagnostic text in the same file as stderr. Debug
                // escaping keeps messages on one line and matches the escaped
                // secret representations already registered by Redactor.
                let line = match record.fields {
                    Some(fields) => format!(
                        "[{}] {:?} {:?}\n",
                        record.level.as_str(),
                        record.message,
                        fields
                    ),
                    None => format!("[{}] {:?}\n", record.level.as_str(), record.message),
                };
                // Snapshot at delivery: secrets added after process startup
                // must also be masked in subsequent structured notifications.
                let mut stream = redactor.stream().map_err(|_| KernelError::Log)?;
                let mut bytes = stream.push(line.as_bytes());
                bytes.extend(stream.finish());
                log.lock()
                    .map_err(|_| KernelError::Log)?
                    .write(&bytes)
                    .map_err(|_| KernelError::Log)
            })
            .await
            .map_err(|_| KernelError::Task)?
        })
    }
}

struct RotatingLog {
    path: PathBuf,
    file: File,
    size: u64,
}
impl RotatingLog {
    fn open(path: PathBuf) -> io::Result<Self> {
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)?;
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.permissions().mode() & 0o077 != 0
        {
            return Err(io::Error::other("invalid log"));
        }
        Ok(Self {
            path,
            size: meta.len(),
            file,
        })
    }
    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        for chunk in bytes.chunks(LOG_LIMIT as usize) {
            if self.size + chunk.len() as u64 > LOG_LIMIT {
                let backup = self.path.with_extension("log.1");
                fs::rename(&self.path, backup)?;
                *self = Self::open(self.path.clone())?;
            }
            self.file.write_all(chunk)?;
            self.size += chunk.len() as u64;
        }
        Ok(())
    }
}
async fn drain_stderr(
    mut stderr: ChildStderr,
    log: Arc<Mutex<RotatingLog>>,
    mut redactor: RedactionStream,
) -> Result<Vec<u8>, SupervisorError> {
    let mut tail = VecDeque::new();
    let mut chunk = [0u8; 8192];
    loop {
        let length = stderr
            .read(&mut chunk)
            .await
            .map_err(|_| SupervisorError::Process)?;
        if length == 0 {
            break;
        }
        let redacted = redactor.push(&chunk[..length]);
        append_stderr(&log, &mut tail, redacted).await?;
    }
    append_stderr(&log, &mut tail, redactor.finish()).await?;
    let bytes: Vec<u8> = tail.into_iter().collect();
    let mut lines = VecDeque::new();
    for line in bytes.split_inclusive(|b| *b == b'\n') {
        if lines.len() == 50 {
            lines.pop_front();
        }
        lines.push_back(line);
    }
    Ok(lines.into_iter().flatten().copied().collect())
}
async fn append_stderr(
    log: &Arc<Mutex<RotatingLog>>,
    tail: &mut VecDeque<u8>,
    bytes: Vec<u8>,
) -> Result<(), SupervisorError> {
    // A bounded crash tail cannot be inflated by a single unterminated line.
    for byte in &bytes {
        if tail.len() == LOG_LIMIT as usize {
            tail.pop_front();
        }
        tail.push_back(*byte);
    }
    let log = log.clone();
    tokio::task::spawn_blocking(move || {
        log.lock()
            .map_err(|_| SupervisorError::Process)?
            .write(&bytes)
            .map_err(|_| SupervisorError::Process)
    })
    .await
    .map_err(|_| SupervisorError::Process)?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn permission_templates_and_home_files_reject_original_magic_links() {
        use std::os::{fd::AsRawFd, unix::fs::symlink};
        if std::env::var_os("FICTOR_TEST_SUPERVISOR_MAGIC").is_none() {
            let output = std::process::Command::new("/usr/bin/unshare")
                .args(["--user", "--map-root-user", "--mount", "--propagation", "private", "--pid", "--fork", "--mount-proc", "--"])
                .arg(std::env::current_exe().unwrap())
                .args(["--exact", "supervisor::tests::permission_templates_and_home_files_reject_original_magic_links", "--nocapture"])
                .env("FICTOR_TEST_SUPERVISOR_MAGIC", "1")
                .output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        // Only this helper's fake files and own PID namespace are observable.
        assert_eq!(unsafe { libc::getpid() }, 1);
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input");
        fs::write(&input, "fake test content").unwrap();
        let file = File::open(&input).unwrap();
        let magic = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
        let link = root.path().join("link");
        symlink(&magic, &link).unwrap();
        let paths = Paths {
            bundle: root.path(),
            data: root.path(),
            tmp: root.path(),
            store: root.path(),
            workspace: Some(root.path()),
            home: root.path(),
        };
        for value in [
            "${workspace}/link",
            "${ext_root}/link",
            "${ext_data}/link",
            "${store}/link",
            "${tmp}/link",
            "~/link",
            link.to_str().unwrap(),
            magic.to_str().unwrap(),
        ] {
            assert!(expand_path(value, &paths).is_err(), "{value}");
        }
        assert!(expand_home_file("~/link", root.path()).is_err());
        let directory = File::open(root.path()).unwrap();
        let directory_magic = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        assert!(canonical_directory(&directory_magic).is_err());
        assert_eq!(expand_home_file("~/input", root.path()).unwrap(), input);
        assert_eq!(expand_path("${workspace}/input", &paths).unwrap(), input);
    }
    #[test]
    fn failed_pid_write_retains_the_record_until_its_owner_releases_it() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("instance.pid");
        let (owner, record) = prepare_pid(&path).unwrap();
        drop(record);
        let mut read_only = File::open(&path).unwrap();
        assert!(matches!(
            record_pid(&mut read_only, 1234),
            Err(SupervisorError::Path)
        ));
        assert!(path.exists());
        drop(owner);
        assert!(!path.exists());
    }
    #[test]
    fn stderr_rotation_keeps_each_log_within_ten_mebibytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("extension.log");
        let mut log = RotatingLog::open(path.clone()).unwrap();
        log.write(&vec![b'a'; LOG_LIMIT as usize - 2]).unwrap();
        log.write(b"next").unwrap();
        assert_eq!(
            fs::metadata(path.with_extension("log.1")).unwrap().len(),
            LOG_LIMIT - 2
        );
        assert_eq!(fs::read(&path).unwrap(), b"next");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    #[tokio::test]
    async fn kernel_logs_share_rotation_and_mask_late_multiline_and_nested_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("extension.log");
        let log = Arc::new(Mutex::new(RotatingLog::open(path.clone()).unwrap()));
        log.lock()
            .unwrap()
            .write(&vec![b'a'; LOG_LIMIT as usize - 2])
            .unwrap();
        let redactor = Redactor::default();
        let sink = ExtensionLog {
            log,
            redactor: redactor.clone(),
        };
        // Registration after sink construction must still cover future records,
        // including Debug's control-character escapes in nested fields and keys.
        let secret = "fake-kernel-credential\n\u{1}\\é";
        redactor.register(secret).unwrap();
        let mut fields = serde_json::Map::new();
        fields.insert(secret.into(), json!({"nested":[secret]}));
        sink.write(LogRecord {
            level: crate::kernel::LogLevel::Warn,
            message: format!("before {secret} after"),
            fields: Some(fields),
        })
        .await
        .unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("[warn]"));
        assert!(text.contains("***"));
        assert!(!text.contains("fake-kernel-credential"));
        assert_eq!(text.lines().count(), 1);
        assert_eq!(
            fs::metadata(path.with_extension("log.1")).unwrap().len(),
            LOG_LIMIT - 2
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    #[test]
    fn node_permissions_keep_grants_separate_and_deny_undeclared_process_features() {
        let paths = Paths {
            bundle: Path::new("/bundle"),
            data: Path::new("/data"),
            tmp: Path::new("/temporary"),
            store: Path::new("/store"),
            workspace: None,
            home: Path::new("/home/user"),
        };
        let read = vec![PathBuf::from("/read,with,commas")];
        let write = vec![PathBuf::from("/work")];
        let args = node_permissions(&paths, Path::new("/runtime"), &read, &write, false).unwrap();
        assert!(args.contains(&OsString::from("--permission")));
        assert!(args.contains(&OsString::from("--allow-fs-read=/read,with,commas")));
        assert!(args.contains(&OsString::from("--allow-fs-read=/work")));
        assert!(args.contains(&OsString::from("--allow-fs-write=/work")));
        assert!(!args.iter().any(|a| a == "--allow-child-process"
            || a == "--allow-worker"
            || a == "--allow-addons"
            || a == "--allow-wasi"));
        let spawn = node_permissions(&paths, Path::new("/runtime"), &read, &write, true).unwrap();
        assert!(spawn.contains(&OsString::from("--allow-child-process")));
        assert!(spawn.contains(&OsString::from("--allow-worker")));
        assert!(
            node_permissions(
                &paths,
                Path::new("/runtime"),
                &[PathBuf::from("/literal*path")],
                &[],
                false
            )
            .is_err()
        );
    }
    #[tokio::test]
    async fn shutdown_deadline_returns_without_claiming_cleanup_completed() {
        let home = tempfile::tempdir().unwrap();
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
        crate::home::prepare(home.path()).unwrap();
        let store = Arc::new(Store::open(home.path()).await.unwrap());
        let (stop, stopped) = watch::channel(false);
        let (_owner, exit) = watch::channel(None);
        let mut instance = ManagedInstance {
            instance_id: "fake".into(),
            pid: 0,
            group: Arc::new(Mutex::new(None)),
            stdin: None,
            stdout: None,
            connection: None,
            pinned_hash: None,
            catalog_invalidation: CatalogInvalidation::new(stop.clone()),
            audit: AuditIdentity {
                store,
                ext_id: "fake".into(),
                key: "fake".into(),
                instance_id: "fake".into(),
            },
            workspace: None,
            stop,
            exit,
        };
        assert!(matches!(
            instance
                .shutdown_with_timeout(Duration::from_millis(10))
                .await,
            Err(SupervisorError::Process)
        ));
        assert!(*stopped.borrow());
        assert!(instance.exit.borrow().is_none());
    }
}
