//! Local phase-0 preflight. Checked proposals await a separate human decision;
//! this module never activates a bundle or skips dependency resolution.
use super::{
    BundleBudget, BundleError, BundleProfile, bundle,
    manifest::{Manifest, ManifestError, RuntimeKind, Scope},
};
use crate::{
    gateway::PinnedCatalog,
    proxy::nat64::Nat64Prefixes,
    store::{
        NewProposal, Proposal, ProposalCheck, ProposalState, ProposalUpdate, Store, StoreError,
    },
    supervisor::Supervisor,
};
use serde_json::json;
use std::{
    fs,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Debug, thiserror::Error)]
pub enum LocalError {
    #[error(transparent)]
    Bundle(#[from] BundleError),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error("recebimento local indisponível")]
    Io(#[from] std::io::Error),
    #[error("armazenamento da proposta indisponível")]
    Store(#[from] StoreError),
    #[error("task de recebimento indisponível")]
    Task,
    #[error("proposta {proposal_id} falhou: {reason}")]
    Failed {
        proposal_id: String,
        reason: &'static str,
    },
}
pub struct LocalReport {
    pub proposal: Proposal,
    pub ignored: Vec<PathBuf>,
    pub catalog: PinnedCatalog,
}
#[derive(Clone)]
pub struct LocalChecker {
    home: PathBuf,
    nat64: Nat64Prefixes,
    store: Arc<Store>,
    supervisor: Arc<Supervisor>,
    provider_secrets: std::collections::BTreeSet<String>,
}
impl LocalChecker {
    pub fn new(
        home: PathBuf,
        nat64: Nat64Prefixes,
        store: Arc<Store>,
        supervisor: Arc<Supervisor>,
        provider_secrets: std::collections::BTreeSet<String>,
    ) -> Self {
        Self {
            home,
            nat64,
            store,
            supervisor,
            provider_secrets,
        }
    }
    /// Receipt and validation failures before an extension can be identified
    /// return directly. Identified proposals persist every checking transition.
    pub async fn check_local(&self, source: &Path) -> Result<LocalReport, LocalError> {
        // Dropping the caller must not strand an identified proposal in checking.
        // This core-owned worker completes its bounded receipt/smoke independently.
        let checker = self.clone();
        let source = source.to_path_buf();
        tokio::spawn(async move { checker.check_owned(&source).await })
            .await
            .map_err(|_| LocalError::Task)?
    }

    async fn check_owned(&self, source: &Path) -> Result<LocalReport, LocalError> {
        let pending = self
            .home
            .join("extensions/quarantine")
            .join(format!(".receipt-{}", ulid::Ulid::generate()));
        let src = source.to_path_buf();
        let dest = pending.clone();
        let (receipt, mut cleanup) = tokio::task::spawn_blocking(move || {
            let receipt = bundle::copy_local(
                &src,
                &dest,
                &BundleBudget::start(BundleProfile::ReceiptLocal),
            )?;
            // The detached worker owns cleanup even if its caller is cancelled.
            Ok::<_, BundleError>((receipt, ReceiptCleanup(Some(dest))))
        })
        .await
        .map_err(|_| LocalError::Task)??;
        let manifest_path = pending.join("fictor.yaml");
        let text = tokio::task::spawn_blocking(move || read_manifest(&manifest_path))
            .await
            .map_err(|_| LocalError::Task)??;
        let manifest = Manifest::parse_with_nat64(&text, &self.nat64)?;
        manifest.validate_provider_secrets(&self.provider_secrets)?;
        let lock = super::lock::Lock::load(&self.home)
            .map_err(|_| std::io::Error::other("lock indisponível"))?;
        let update_of = lock
            .extensions
            .get(&manifest.id)
            .map(|ext| ext.active.clone());
        let proposal = self
            .store
            .receive_proposal(NewProposal {
                ext_id: manifest.id.clone(),
                version: manifest.version.clone(),
                source: json!({"kind":"local"}),
                manifest: serde_json::to_value(&manifest).map_err(|_| ManifestError::Schema)?,
                tainted: false,
                update_of,
            })
            .await?;
        let mut checks = vec![
            passed("manifest", None),
            informative("receipt", json!({"ignored":receipt.ignored})),
            informative(
                "permissions",
                json!({
                    "requested":manifest.permissions,
                    "omitted_fs": {
                        "read":manifest.permissions.fs.read.iter().filter(|path| !path.starts_with("${")).collect::<Vec<_>>(),
                        "write":manifest.permissions.fs.write.iter().filter(|path| !path.starts_with("${")).collect::<Vec<_>>()
                    }
                }),
            ),
        ];
        let destination = self.home.join("extensions/quarantine").join(&proposal.id);
        // Both parents are core-owned; the randomized receipt was created new.
        if let Err(error) = fs::rename(&pending, &destination) {
            self.fail(&proposal.id, checks, "receipt", "quarantine unavailable")
                .await?;
            return Err(error.into());
        }
        cleanup.0 = None; // Identified proposals, including failures, remain reviewable.
        if let Err(error) =
            fs::File::open(self.home.join("extensions/quarantine")).and_then(|dir| dir.sync_all())
        {
            self.fail(&proposal.id, checks, "receipt", "quarantine sync failed")
                .await?;
            return Err(error.into());
        }
        self.store
            .transition_proposal(
                proposal.id.clone(),
                ProposalState::Received,
                ProposalState::Checking,
                ProposalUpdate::default(),
            )
            .await?;
        // ADR-025: process-bearing global extensions await Phase-1 watermarking.
        if manifest.scope == Scope::Global && manifest.runtime.kind != RuntimeKind::None {
            self.fail(&proposal.id, checks, "phase", "phase:global")
                .await?;
            return Err(LocalError::Failed {
                proposal_id: proposal.id,
                reason: "phase:global",
            });
        }
        // Vendored directories were intentionally discarded at receipt. Never
        // pretend npm/uv dependencies were checked until stage 3 exists.
        // A prepacked Node bundle without package.json dependencies needs no npm resolver.
        let dependency_failure = match manifest.runtime.kind {
            RuntimeKind::Binary | RuntimeKind::None => None,
            RuntimeKind::Node => match node_dependencies(&destination) {
                Ok(false) => None,
                Ok(true) => Some("dependency resolver unavailable"),
                Err(reason) => Some(reason),
            },
            _ => Some("dependency resolver unavailable"),
        };
        if let Some(reason) = dependency_failure {
            self.fail(&proposal.id, checks, "dependencies", reason)
                .await?;
            return Err(LocalError::Failed {
                proposal_id: proposal.id,
                reason,
            });
        }
        checks.push(passed(
            "dependencies",
            Some("no runtime dependency installation required".into()),
        ));
        let inspected = destination.clone();
        let post = tokio::task::spawn_blocking(move || {
            bundle::inspect(
                &inspected,
                &BundleBudget::start(BundleProfile::PostDependencies),
            )
        })
        .await;
        let post = match post {
            Ok(Ok(post)) => post,
            Ok(Err(error)) => {
                self.fail(&proposal.id, checks, "bundle", "bundle inspection failed")
                    .await?;
                return Err(error.into());
            }
            Err(_) => {
                self.fail(
                    &proposal.id,
                    checks,
                    "bundle",
                    "bundle inspection interrupted",
                )
                .await?;
                return Err(LocalError::Task);
            }
        };
        checks.push(passed("bundle", None));
        let key = format!("{}-{}", manifest.version, &post.bundle_hash[7..19]);
        let report = match self.supervisor.smoke(&manifest, &destination, &key).await {
            Ok(report) => report,
            Err(_) => {
                self.fail(&proposal.id, checks, "smoke", "sandbox smoke failed")
                    .await?;
                return Err(LocalError::Failed {
                    proposal_id: proposal.id,
                    reason: "sandbox smoke failed",
                });
            }
        };
        let hooks_valid = manifest.hooks.iter().flatten().all(|hook| {
            let name = format!("hook_{}", hook.point.replace('.', "_"));
            report
                .catalog
                .tools()
                .iter()
                .any(|tool| tool["name"].as_str() == Some(&name))
        });
        let surfaces_valid = manifest.surfaces.iter().all(|surface| {
            report
                .resources
                .iter()
                .any(|resource| resource.uri == surface.resource)
        });
        // `default` supplies fallback classification; it is not a declared MCP tool.
        let tools_valid = manifest
            .tools
            .keys()
            .filter(|name| *name != "default")
            .all(|name| {
                report
                    .catalog
                    .tools()
                    .iter()
                    .any(|tool| tool["name"].as_str() == Some(name))
            });
        if !hooks_valid || !surfaces_valid || !tools_valid {
            self.fail(
                &proposal.id,
                checks,
                "declarations",
                "declared MCP tools or resources absent",
            )
            .await?;
            return Err(LocalError::Failed {
                proposal_id: proposal.id,
                reason: "declared MCP tools or resources absent",
            });
        }
        let catalog = report.catalog;
        checks.extend([
            passed("declarations", None),
            passed(
                "smoke",
                Some(json!({"tools":catalog.tools(),"tools_hash":catalog.hash()}).to_string()),
            ),
        ]);
        let proposal = self
            .store
            .transition_proposal(
                proposal.id,
                ProposalState::Checking,
                ProposalState::Checked,
                ProposalUpdate {
                    checks: Some(checks),
                    hash: Some(post.bundle_hash),
                    packages: Some(vec![]),
                    ..Default::default()
                },
            )
            .await?;
        Ok(LocalReport {
            proposal,
            ignored: receipt.ignored,
            catalog,
        })
    }
    async fn fail(
        &self,
        id: &str,
        mut checks: Vec<ProposalCheck>,
        name: &str,
        reason: &'static str,
    ) -> Result<(), StoreError> {
        let current = self.store.proposal(id.into()).await?;
        checks.push(ProposalCheck {
            name: name.into(),
            passed: false,
            blocking: true,
            detail: Some(reason.into()),
        });
        let update = ProposalUpdate {
            checks: Some(checks),
            ..Default::default()
        };
        self.store
            .transition_proposal(id.into(), current.state, ProposalState::Failed, update)
            .await?;
        Ok(())
    }
}
fn node_dependencies(bundle: &Path) -> Result<bool, &'static str> {
    let text = match read_manifest(&bundle.join("package.json")) {
        Ok(text) => text,
        Err(LocalError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(false);
        }
        Err(_) => return Err("invalid package metadata"),
    };
    let package: serde_json::Value =
        serde_json::from_str(&text).map_err(|_| "invalid package metadata")?;
    let package = package.as_object().ok_or("invalid package metadata")?;
    let mut dependencies = false;
    for name in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(value) = package.get(name) {
            dependencies |= !value
                .as_object()
                .ok_or("invalid package metadata")?
                .is_empty();
        }
    }
    for name in ["bundledDependencies", "bundleDependencies"] {
        if let Some(value) = package.get(name) {
            dependencies |= match value {
                serde_json::Value::Array(entries) => !entries.is_empty(),
                serde_json::Value::Bool(enabled) => *enabled,
                _ => return Err("invalid package metadata"),
            };
        }
    }
    Ok(dependencies)
}
fn informative(name: &str, detail: serde_json::Value) -> ProposalCheck {
    ProposalCheck {
        name: name.into(),
        passed: true,
        blocking: false,
        detail: Some(detail.to_string()),
    }
}
fn passed(name: &str, detail: Option<String>) -> ProposalCheck {
    ProposalCheck {
        name: name.into(),
        passed: true,
        blocking: true,
        detail,
    }
}
fn read_manifest(path: &Path) -> Result<String, LocalError> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("manifest não é arquivo regular").into());
    }
    let mut bytes = Vec::new();
    file.take(50 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 50 * 1024 * 1024 {
        return Err(ManifestError::Limit.into());
    }
    String::from_utf8(bytes).map_err(|_| ManifestError::Parse.into())
}
struct ReceiptCleanup(Option<PathBuf>);
impl Drop for ReceiptCleanup {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_dir_all(path);
        }
    }
}
