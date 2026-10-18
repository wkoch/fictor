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
        let destination = self.home.join("extensions/quarantine").join(&proposal.id);
        // Both parents are core-owned; the randomized receipt was created new.
        if let Err(error) = fs::rename(&pending, &destination) {
            self.fail(&proposal.id, "receipt", "quarantine unavailable")
                .await?;
            return Err(error.into());
        }
        cleanup.0 = None; // Identified proposals, including failures, remain reviewable.
        if let Err(error) =
            fs::File::open(self.home.join("extensions/quarantine")).and_then(|dir| dir.sync_all())
        {
            self.fail(&proposal.id, "receipt", "quarantine sync failed")
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
            self.fail(&proposal.id, "phase", "phase:global").await?;
            return Err(LocalError::Failed {
                proposal_id: proposal.id,
                reason: "phase:global",
            });
        }
        // Vendored directories were intentionally discarded at receipt. Never
        // pretend Deno/npm/uv dependencies were checked until stage 3 exists.
        if !matches!(
            manifest.runtime.kind,
            RuntimeKind::Binary | RuntimeKind::None
        ) {
            self.fail(
                &proposal.id,
                "dependencies",
                "dependency resolver unavailable",
            )
            .await?;
            return Err(LocalError::Failed {
                proposal_id: proposal.id,
                reason: "dependency resolver unavailable",
            });
        }
        let inspected = destination.clone();
        let post = tokio::task::spawn_blocking(move || {
            bundle::inspect(
                &inspected,
                &BundleBudget::start(BundleProfile::PostDependencies),
            )
        })
        .await
        .map_err(|_| LocalError::Task)?;
        let post = match post {
            Ok(post) => post,
            Err(error) => {
                self.fail(&proposal.id, "bundle", "bundle inspection failed")
                    .await?;
                return Err(error.into());
            }
        };
        let key = format!("{}-{}", manifest.version, &post.bundle_hash[7..19]);
        let report = match self.supervisor.smoke(&manifest, &destination, &key).await {
            Ok(report) => report,
            Err(_) => {
                self.fail(&proposal.id, "smoke", "sandbox smoke failed")
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
        let tools_valid = manifest.tools.keys().all(|name| {
            report
                .catalog
                .tools()
                .iter()
                .any(|tool| tool["name"].as_str() == Some(name))
        });
        if !hooks_valid || !surfaces_valid || !tools_valid {
            self.fail(
                &proposal.id,
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
        let checks = vec![
            passed("manifest", None),
            passed(
                "dependencies",
                Some("no runtime dependency installation required".into()),
            ),
            passed("bundle", None),
            passed("declarations", None),
            passed(
                "smoke",
                Some(json!({"tools":catalog.tools(),"tools_hash":catalog.hash()}).to_string()),
            ),
        ];
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
    async fn fail(&self, id: &str, name: &str, reason: &'static str) -> Result<(), StoreError> {
        let current = self.store.proposal(id.into()).await?;
        let update = if current.state == ProposalState::Checking {
            ProposalUpdate {
                checks: Some(vec![ProposalCheck {
                    name: name.into(),
                    passed: false,
                    blocking: true,
                    detail: Some(reason.into()),
                }]),
                ..Default::default()
            }
        } else {
            ProposalUpdate::default()
        };
        self.store
            .transition_proposal(id.into(), current.state, ProposalState::Failed, update)
            .await?;
        Ok(())
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
