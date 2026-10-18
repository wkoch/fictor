//! Stage 3: registry-only installation into disposable extension data. Neither
//! candidate code nor package lifecycle/build scripts are executed by this stage.
use super::{
    BundleBudget, BundleError, BundleProfile, Inspection, bundle,
    lease::InstallerLease,
    manifest::{Manifest, RuntimeKind},
};
use crate::{
    config::{Config, Mode},
    proxy::{EgressProxy, nat64::Nat64Prefixes},
    secrets::{BackendKind, Redactor, SecretStore},
    store::{NewSession, ResolvedPackage, Store, Trust},
    supervisor::Supervisor,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

const ID: &str = "dependency-resolver";
const KEY: &str = "0.1.0-000000000000";
const MAX_METADATA: u64 = 100 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum DependencyError {
    #[error("dependency metadata invalid")]
    Metadata,
    #[error("dependency lockfile missing")]
    MissingLock,
    #[error("dependency runtime unavailable")]
    Runtime,
    #[error("installer registry policy invalid")]
    RegistryPolicy,
    #[error("dependency installation failed")]
    Command,
    #[error("dependency verification unavailable")]
    Storage,
    #[error("dependency task unavailable")]
    Task,
    #[error("dependency cleanup unconfirmed")]
    Cleanup,
    #[error("dependency limit exceeded")]
    Bundle(BundleError),
}
impl DependencyError {
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Metadata => "invalid package metadata",
            Self::MissingLock => "dependency lockfile missing",
            Self::Runtime => "dependency runtime unavailable",
            Self::RegistryPolicy => "installer registry policy invalid",
            Self::Command => "dependency installation failed",
            Self::Storage => "dependency verification unavailable",
            Self::Task => "dependency task unavailable",
            Self::Cleanup => "dependency cleanup unconfirmed",
            Self::Bundle(error) => error.receipt_reason(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DependencyKind {
    Npm,
    Python,
}
impl DependencyKind {
    fn directory(self) -> &'static str {
        match self {
            Self::Npm => "node_modules",
            Self::Python => ".pydeps",
        }
    }
}

/// Metadata is inspected before invoking any package manager. Package managers
/// validate lock consistency and hashes; their diagnostics never become audit text.
pub fn plan(runtime: RuntimeKind, path: &Path) -> Result<Option<DependencyKind>, DependencyError> {
    match runtime {
        RuntimeKind::Binary | RuntimeKind::None => Ok(None),
        RuntimeKind::Node => {
            let Some(package) = optional_json(&path.join("package.json"))? else {
                return Ok(None);
            };
            let package = package.as_object().ok_or(DependencyError::Metadata)?;
            let mut required = false;
            for name in [
                "dependencies",
                "devDependencies",
                "optionalDependencies",
                "peerDependencies",
            ] {
                if let Some(value) = package.get(name) {
                    required |= !value
                        .as_object()
                        .ok_or(DependencyError::Metadata)?
                        .is_empty();
                }
            }
            for name in ["bundledDependencies", "bundleDependencies"] {
                if let Some(value) = package.get(name) {
                    required |= match value {
                        Value::Array(entries) => !entries.is_empty(),
                        Value::Bool(enabled) => *enabled,
                        _ => return Err(DependencyError::Metadata),
                    };
                }
            }
            if !required {
                return Ok(None);
            }
            let lock = optional_json(&path.join("package-lock.json"))?
                .ok_or(DependencyError::MissingLock)?;
            if !lock.is_object()
                || path
                    .join("npm-shrinkwrap.json")
                    .try_exists()
                    .map_err(|_| DependencyError::Metadata)?
            {
                // npm 11 gives shrinkwrap precedence; never silently use a second
                // lock instead of the package-lock required by the Fictor pipeline.
                return Err(DependencyError::Metadata);
            }
            Ok(Some(DependencyKind::Npm))
        }
        RuntimeKind::Python => {
            metadata(&path.join("requirements.lock"))?.ok_or(DependencyError::MissingLock)?;
            Ok(Some(DependencyKind::Python))
        }
        _ => Err(DependencyError::Runtime),
    }
}

pub struct DependencyReport {
    pub inspection: Inspection,
    pub packages: Vec<ResolvedPackage>,
}

#[derive(Clone)]
pub struct DependencyResolver {
    config: Arc<Config>,
    real_home: PathBuf,
    executable: PathBuf,
}
impl DependencyResolver {
    pub fn new(config: Arc<Config>, real_home: PathBuf, executable: PathBuf) -> Self {
        Self {
            config,
            real_home,
            executable,
        }
    }

    /// The detached owner also shields the disposable home from caller abort.
    pub async fn resolve(
        &self,
        kind: DependencyKind,
        path: &Path,
        lease: Arc<InstallerLease>,
    ) -> Result<DependencyReport, DependencyError> {
        let resolver = self.clone();
        let path = path.to_owned();
        tokio::spawn(async move {
            let deadline = Instant::now() + Duration::from_secs(600);
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                resolver.resolve_owned(kind, path, lease, deadline),
            )
            .await
            .map_err(|_| DependencyError::Bundle(BundleError::Limit("time")))?
        })
        .await
        .map_err(|_| DependencyError::Task)?
    }

    async fn resolve_owned(
        &self,
        kind: DependencyKind,
        path: PathBuf,
        lease: Arc<InstallerLease>,
        deadline: Instant,
    ) -> Result<DependencyReport, DependencyError> {
        // M0.5 development bootstrap. Downloading managed runtimes is M0.9.
        if !Path::new("/run/.toolboxenv").is_file() {
            return Err(DependencyError::Runtime);
        }
        let script = bootstrap(kind)?;
        let budget = Arc::new(BundleBudget::start(BundleProfile::PostDependencies));
        let resolver = self.clone();
        let setup_lease = lease.clone();
        // Store::open owns a blocking writer. A timeout must not remove its
        // disposable directory while setup or a queued initialization runs.
        let environment = tokio::spawn(async move {
            let _lease = setup_lease;
            Environment::new(&resolver, script).await
        })
        .await
        .map_err(|_| DependencyError::Task)??;
        let source = path.clone();
        let target = environment.candidate.clone();
        let copy_budget = budget.clone();
        let root_guard = environment.root.clone();
        let copy_lease = lease.clone();
        let original = tokio::task::spawn_blocking(move || {
            let _guards = (root_guard, copy_lease);
            bundle::copy_local(&source, &target, &copy_budget)
        })
        .await
        .map_err(|_| DependencyError::Task)?
        .map_err(DependencyError::Bundle)?;
        let mut process = environment
            .supervisor
            .spawn_with_owner(
                &environment.manifest,
                &environment.bootstrap,
                KEY,
                Some(&environment.session),
                Some(&environment.workspace),
                Arc::new((environment.root.clone(), lease.clone())),
            )
            .await
            .map_err(|_| DependencyError::Command)?;
        let outcome =
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), process.wait()).await;
        let successful = matches!(&outcome, Ok(Ok(exit)) if exit.code == Some(0));
        if process.shutdown().await.is_err() {
            // ADR-029: never remove sockets, data or the disposable core home
            // until the independent supervisor confirms namespace exit.
            tokio::spawn(async move {
                let _guards = (environment, lease);
                let _ = process.wait().await;
            });
            return Err(DependencyError::Cleanup);
        }
        if outcome.is_err() {
            return Err(DependencyError::Bundle(BundleError::Limit("time")));
        }
        if !successful {
            return Err(DependencyError::Command);
        }
        let candidate = environment.candidate.clone();
        let inspection_budget = budget.clone();
        let root_guard = environment.root.clone();
        let inspection_lease = lease.clone();
        let (resolved, packages) = tokio::task::spawn_blocking(move || {
            let _guards = (root_guard, inspection_lease);
            let resolved =
                bundle::inspect(&candidate, &inspection_budget).map_err(DependencyError::Bundle)?;
            let prefix = Path::new(kind.directory());
            // Package managers may only add the dependency tree. In particular,
            // candidate manifest, code and lock bytes cannot be rewritten here.
            let retained: Vec<_> = resolved
                .files
                .iter()
                .filter(|file| !file.path.starts_with(prefix))
                .collect();
            if retained.len() != original.files.len()
                || retained
                    .iter()
                    .zip(&original.files)
                    .any(|(after, before)| *after != before)
            {
                return Err(DependencyError::Metadata);
            }
            let packages = inventory(kind, &candidate, &resolved)?;
            Ok::<_, DependencyError>((resolved, packages))
        })
        .await
        .map_err(|_| DependencyError::Task)??;
        let source = environment.candidate.join(kind.directory());
        let target = path.join(kind.directory());
        let final_budget = budget.clone();
        let root_guard = environment.root.clone();
        tokio::task::spawn_blocking(move || {
            let _guards = (root_guard, lease);
            if source.try_exists().map_err(|_| DependencyError::Metadata)? {
                bundle::copy_local(&source, &target, &final_budget)
                    .map_err(DependencyError::Bundle)?;
            }
            let inspection =
                bundle::inspect(&path, &final_budget).map_err(DependencyError::Bundle)?;
            if inspection.bundle_hash != resolved.bundle_hash {
                return Err(DependencyError::Metadata);
            }
            Ok(DependencyReport {
                inspection,
                packages,
            })
        })
        .await
        .map_err(|_| DependencyError::Task)?
    }
}

struct Environment {
    root: Arc<tempfile::TempDir>,
    supervisor: Supervisor,
    manifest: Manifest,
    bootstrap: PathBuf,
    candidate: PathBuf,
    workspace: PathBuf,
    session: String,
}
impl Environment {
    async fn new(resolver: &DependencyResolver, script: String) -> Result<Self, DependencyError> {
        // Installer registries have no wildcard contract in M0.5. Exact hosts
        // and IP:port entries still pass through the normal proxy validation.
        if resolver
            .config
            .installer
            .registries
            .iter()
            .any(|registry| registry.contains('*'))
        {
            return Err(DependencyError::RegistryPolicy);
        }
        let root = Arc::new(
            tempfile::Builder::new()
                .prefix("fx-deps-")
                .tempdir_in("/tmp")
                .map_err(|_| DependencyError::Storage)?,
        );
        let home = root.path().join("core");
        crate::home::prepare(&home).map_err(|_| DependencyError::Storage)?;
        let mut config = Config::create_if_missing(&home).map_err(|_| DependencyError::Storage)?;
        config.providers.clear();
        config.sandbox.home_ro_files.clear();
        config.egress.nat64_prefixes = resolver.config.egress.nat64_prefixes.clone();
        let nat64 = Nat64Prefixes::new(&config.egress.nat64_prefixes)
            .map_err(|_| DependencyError::Storage)?;
        let store = Arc::new(
            Store::open(&home)
                .await
                .map_err(|_| DependencyError::Storage)?,
        );
        let workspace = root.path().join("workspace");
        crate::home::private_dir(&workspace).map_err(|_| DependencyError::Storage)?;
        let session = store
            .create_session(NewSession {
                title: "Dependency verification".into(),
                workspace: workspace.clone(),
                workspace_trust: Trust::Untrusted,
                harness: ID.into(),
                mode: Mode::Plan,
                model: None,
            })
            .await
            .map_err(|_| DependencyError::Storage)?
            .id;
        let candidate = home
            .join("extensions/data")
            .join(ID)
            .join("sessions")
            .join(&session);
        crate::home::private_dir(candidate.parent().ok_or(DependencyError::Storage)?)
            .map_err(|_| DependencyError::Storage)?;
        let bootstrap = home.join("extensions/store").join(ID).join(KEY);
        crate::home::private_dir(&bootstrap).map_err(|_| DependencyError::Storage)?;
        fs::write(bootstrap.join("run"), script).map_err(|_| DependencyError::Storage)?;
        fs::set_permissions(bootstrap.join("run"), fs::Permissions::from_mode(0o555))
            .map_err(|_| DependencyError::Storage)?;
        let manifest = Manifest::parse(&json!({
            "schema":1,"id":ID,"version":"0.1.0","description":"Core dependency installer bootstrap",
            "scope":"session","mcp":false,"kernel":["kv"],
            "runtime":{"kind":"binary","entry":"run","args":[candidate]},
            "permissions":{"spawn":true,"net":{"allow":resolver.config.installer.registries}}
        }).to_string()).map_err(|_| DependencyError::Storage)?;
        let secrets = Arc::new(
            SecretStore::open(&home, BackendKind::File, Redactor::default())
                .map_err(|_| DependencyError::Storage)?,
        );
        let proxy = Arc::new(
            EgressProxy::bind_unix_with_nat64(
                home.join("run/proxy.sock"),
                store.clone(),
                vec![],
                nat64,
            )
            .await
            .map_err(|_| DependencyError::Storage)?,
        );
        let supervisor = Supervisor::new(
            &home,
            &resolver.real_home,
            Arc::new(config),
            secrets,
            store,
            proxy,
        )
        .map_err(|_| DependencyError::Storage)?
        .with_fictor_exe(resolver.executable.clone())
        .map_err(|_| DependencyError::Storage)?;
        Ok(Self {
            root,
            supervisor,
            manifest,
            bootstrap,
            candidate,
            workspace,
            session,
        })
    }
}

fn bootstrap(kind: DependencyKind) -> Result<String, DependencyError> {
    // Package diagnostics may echo credentials from candidate URLs/config. Only
    // the bounded exit result is exposed; stdout/stderr stay outside audit logs.
    match kind {
        DependencyKind::Npm => {
            let npm = Path::new("/usr/bin/npm")
                .canonicalize()
                .map_err(|_| DependencyError::Runtime)?;
            let node = Path::new("/usr/bin/node")
                .canonicalize()
                .map_err(|_| DependencyError::Runtime)?;
            if !npm.starts_with("/usr/")
                || !node.starts_with("/usr/")
                || !npm.is_file()
                || !node.is_file()
            {
                return Err(DependencyError::Runtime);
            }
            let npm = npm.to_str().ok_or(DependencyError::Runtime)?;
            // Node paths are separate flags; '$1' is a core-generated ext_data
            // path, never shell text from a manifest. No package child process.
            Ok(format!(
                "#!/bin/sh\nexec /usr/bin/node --permission --allow-fs-read=/usr --allow-fs-read=/tmp --allow-fs-read=\"$1\" --allow-fs-write=/tmp --allow-fs-write=\"$1\" -- '{}' ci --prefix \"$1\" --ignore-scripts --bin-links=false --audit=false --fund=false --update-notifier=false --fetch-retries=0 --cache=/tmp/npm-cache >/dev/null 2>&1\n",
                npm.replace('\'', "'\\''")
            ))
        }
        DependencyKind::Python => {
            for runtime in ["/usr/bin/uv", "/usr/bin/python3"] {
                let path = Path::new(runtime)
                    .canonicalize()
                    .map_err(|_| DependencyError::Runtime)?;
                if !path.starts_with("/usr/") || !path.is_file() {
                    return Err(DependencyError::Runtime);
                }
            }
            // uv's hash-checking mode forbids editable/Git/local-directory
            // requirements; --no-build then rejects all source distributions.
            Ok("#!/bin/sh\nexec /usr/bin/uv --no-config --no-cache --no-python-downloads pip install --python /usr/bin/python3 --require-hashes --no-build --link-mode copy --target \"$1/.pydeps\" -r \"$1/requirements.lock\" >/dev/null 2>&1\n".into())
        }
    }
}

pub fn inventory(
    kind: DependencyKind,
    path: &Path,
    inspected: &Inspection,
) -> Result<Vec<ResolvedPackage>, DependencyError> {
    let mut packages = BTreeSet::new();
    match kind {
        DependencyKind::Npm => {
            let present: BTreeSet<_> = inspected
                .files
                .iter()
                .map(|file| file.path.as_path())
                .collect();
            let lock = optional_json(&path.join("node_modules/.package-lock.json"))?
                .ok_or(DependencyError::Metadata)?;
            let entries = lock
                .get("packages")
                .and_then(Value::as_object)
                .ok_or(DependencyError::Metadata)?;
            for (entry, value) in entries {
                let relative = Path::new(entry).join("package.json");
                if !entry.starts_with("node_modules/") || !present.contains(relative.as_path()) {
                    return Err(DependencyError::Metadata);
                }
                let metadata =
                    optional_json(&path.join(relative))?.ok_or(DependencyError::Metadata)?;
                let name = text(metadata.get("name"))?;
                let version = text(metadata.get("version"))?;
                if value.get("version").and_then(Value::as_str) != Some(version) {
                    return Err(DependencyError::Metadata);
                }
                packages.insert((name.to_owned(), version.to_owned()));
            }
        }
        DependencyKind::Python => {
            for file in &inspected.files {
                let mut components = file.path.components();
                if components
                    .next()
                    .is_none_or(|part| part.as_os_str() != ".pydeps")
                {
                    continue;
                }
                let Some(directory) = components.next() else {
                    continue;
                };
                if !directory
                    .as_os_str()
                    .to_string_lossy()
                    .ends_with(".dist-info")
                    || components
                        .next()
                        .is_none_or(|part| part.as_os_str() != "METADATA")
                    || components.next().is_some()
                {
                    continue;
                }
                let bytes = metadata(&path.join(&file.path))?.ok_or(DependencyError::Metadata)?;
                let headers = std::str::from_utf8(&bytes).map_err(|_| DependencyError::Metadata)?;
                let mut name = None;
                let mut version = None;
                for line in headers.lines().take_while(|line| !line.is_empty()) {
                    if let Some(value) = line.strip_prefix("Name: ")
                        && name
                            .replace(text(Some(&Value::String(value.into())))?.to_owned())
                            .is_some()
                    {
                        return Err(DependencyError::Metadata);
                    }
                    if let Some(value) = line.strip_prefix("Version: ")
                        && version
                            .replace(text(Some(&Value::String(value.into())))?.to_owned())
                            .is_some()
                    {
                        return Err(DependencyError::Metadata);
                    }
                }
                packages.insert((
                    name.ok_or(DependencyError::Metadata)?,
                    version.ok_or(DependencyError::Metadata)?,
                ));
            }
        }
    }
    Ok(packages
        .into_iter()
        .map(|(name, version)| ResolvedPackage {
            ecosystem: match kind {
                DependencyKind::Npm => "npm",
                DependencyKind::Python => "pypi",
            }
            .into(),
            name,
            version,
        })
        .collect())
}

fn text(value: Option<&Value>) -> Result<&str, DependencyError> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty() && !text.chars().any(char::is_control))
        .ok_or(DependencyError::Metadata)
}
fn optional_json(path: &Path) -> Result<Option<Value>, DependencyError> {
    metadata(path)?
        .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| DependencyError::Metadata))
        .transpose()
}
fn metadata(path: &Path) -> Result<Option<Vec<u8>>, DependencyError> {
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(DependencyError::Metadata),
    };
    let info = file.metadata().map_err(|_| DependencyError::Metadata)?;
    if !info.is_file() {
        return Err(DependencyError::Metadata);
    }
    if info.len() > MAX_METADATA {
        return Err(DependencyError::Bundle(BundleError::Limit("file_size")));
    }
    let mut bytes = Vec::new();
    file.take(MAX_METADATA + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| DependencyError::Metadata)?;
    if bytes.len() as u64 > MAX_METADATA {
        return Err(DependencyError::Bundle(BundleError::Limit("file_size")));
    }
    Ok(Some(bytes))
}
