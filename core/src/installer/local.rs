//! Local phase-0 preflight. Checked proposals await a separate human decision;
//! this module never activates a bundle or skips dependency resolution.
use super::{
    BundleBudget, BundleError, BundleProfile, bundle,
    dependencies::{self, DependencyReport, DependencyResolver},
    lease::InstallerLease,
    manifest::{Manifest, ManifestError, RuntimeKind, Scope},
    recovery,
};
use crate::{
    gateway::PinnedCatalog,
    proxy::nat64::Nat64Prefixes,
    store::{
        NewProposal, Proposal, ProposalCheck, ProposalIdentity, ProposalState, ProposalUpdate,
        Store, StoreError,
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
    time::Instant,
};
use tokio::sync::OnceCell;

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
    #[error("outra operação do instalador está ativa ou a quarentena está indisponível")]
    Admission,
    #[error("recuperação do instalador indisponível; nenhum recebimento iniciado")]
    Recovery,
    #[error("persistência da proposta {proposal_id} indisponível; transição não confirmada")]
    Persistence { proposal_id: String },
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
    lease: Arc<OnceCell<Arc<InstallerLease>>>,
    dependency_resolver: Option<Arc<DependencyResolver>>,
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
            lease: Arc::new(OnceCell::new()),
            dependency_resolver: None,
        }
    }

    pub fn with_dependency_resolver(mut self, resolver: Arc<DependencyResolver>) -> Self {
        self.dependency_resolver = Some(resolver);
        self
    }
    pub(crate) fn control_registry(&self) -> crate::supervisor::controls::ControlRegistry {
        self.supervisor.control_registry()
    }

    /// Admit durably before opening source; all objective refusals retain their ID.
    pub async fn check_local(&self, source: &Path) -> Result<LocalReport, LocalError> {
        // Dropping the caller must not strand an identified proposal in checking.
        // This core-owned worker completes its bounded receipt/smoke independently.
        // Runtime/process shutdown is recovered on the next boot. Blocking jobs
        // retain a lease clone until their filesystem work has actually ended.
        let checker = self.clone();
        let source = source.to_path_buf();
        tokio::spawn(async move { checker.check_owned(&source, None, None).await })
            .await
            .map_err(|_| LocalError::Task)?
    }

    /// ADR-045: acknowledge only the durable receipt. The owned checker keeps
    /// copying/checking after the observer disconnects, without approving it.
    pub async fn prepare_local(&self, source: &Path) -> Result<String, LocalError> {
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        self.prepare_local_before(source, deadline).await
    }

    pub(crate) async fn prepare_local_before(
        &self,
        source: &Path,
        deadline: Instant,
    ) -> Result<String, LocalError> {
        let checker = self.clone();
        let source = source.to_path_buf();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _ = checker
                .check_owned(&source, Some(sender), Some(deadline))
                .await;
        });
        receiver.await.map_err(|_| LocalError::Task)?
    }

    pub(crate) async fn shared_lease(&self) -> Result<Arc<InstallerLease>, LocalError> {
        let _section = self.store.owner().installer_gate().lock_owned().await;
        self.admission().await
    }

    async fn check_owned(
        &self,
        source: &Path,
        admitted: Option<tokio::sync::oneshot::Sender<Result<String, LocalError>>>,
        deadline: Option<Instant>,
    ) -> Result<LocalReport, LocalError> {
        let owner = self.store.owner().clone();
        let setup = async {
            owner.verify().map_err(|_| LocalError::Admission)?;
            if self
                .home
                .canonicalize()
                .map_err(|_| LocalError::Admission)?
                != owner.home()
            {
                return Err(LocalError::Admission);
            }
            let section = tokio::time::timeout_at(
                tokio::time::Instant::from_std(
                    deadline.unwrap_or_else(|| Instant::now() + std::time::Duration::from_secs(5)),
                ),
                owner.installer_gate().lock_owned(),
            )
            .await
            .map_err(|_| LocalError::Admission)?;
            if self.store.pending_promotion().await?.is_some() {
                return Err(LocalError::Admission);
            }
            let lease = self.admission().await?;
            // No source access, including metadata or canonicalization, precedes this commit.
            let proposal = self
                .store
                .begin_attempt_before(
                    NewProposal {
                        source: json!({"kind":"local"}),
                        tainted: false,
                    },
                    deadline,
                )
                .await?;
            Ok::<_, LocalError>((section, lease, proposal))
        }
        .await;
        let (_section, lease, proposal) = match setup {
            Ok(result) => result,
            Err(error) => {
                if let Some(admitted) = admitted {
                    let _ = admitted.send(Err(error));
                    return Err(LocalError::Task);
                }
                return Err(error);
            }
        };
        if let Some(admitted) = admitted {
            let _ = admitted.send(Ok(proposal.id.clone()));
        }
        let pending = self
            .home
            .join("extensions/quarantine")
            .join(format!(".receipt-{}", proposal.id));
        let src = source.to_path_buf();
        let dest = pending.clone();
        let receipt_lease = lease.clone();
        let receipt = tokio::task::spawn_blocking(move || {
            let _lease = receipt_lease;
            bundle::copy_receipt(
                &src,
                &dest,
                &BundleBudget::start(BundleProfile::ReceiptLocal),
            )
        })
        .await;
        let receipt = match receipt {
            Ok(Ok(receipt)) => receipt,
            Ok(Err(error)) => {
                return self
                    .refuse(
                        &proposal.id,
                        ProposalState::Received,
                        vec![],
                        "receipt",
                        error.receipt_reason(),
                        false,
                    )
                    .await;
            }
            Err(_) => {
                return self
                    .refuse(
                        &proposal.id,
                        ProposalState::Received,
                        vec![],
                        "receipt",
                        "receipt:io",
                        false,
                    )
                    .await;
            }
        };
        let mut checks = vec![informative("receipt", json!({"ignored":receipt.ignored}))];
        let manifest_path = pending.join("fictor.yaml");
        let manifest_lease = lease.clone();
        let text = tokio::task::spawn_blocking(move || {
            let _lease = manifest_lease;
            read_manifest(&manifest_path)
        })
        .await;
        let text = match text {
            Ok(Ok(text)) => text,
            Ok(Err(LocalError::Io(error))) if error.kind() == std::io::ErrorKind::NotFound => {
                return self
                    .refuse(
                        &proposal.id,
                        ProposalState::Received,
                        checks,
                        "manifest",
                        "manifest:missing",
                        false,
                    )
                    .await;
            }
            Ok(Err(LocalError::Manifest(_))) => {
                return self
                    .refuse(
                        &proposal.id,
                        ProposalState::Received,
                        checks,
                        "manifest",
                        "manifest:invalid_yaml",
                        false,
                    )
                    .await;
            }
            _ => {
                return self
                    .refuse(
                        &proposal.id,
                        ProposalState::Received,
                        checks,
                        "receipt",
                        "receipt:io",
                        false,
                    )
                    .await;
            }
        };
        let manifest = match Manifest::parse_with_nat64(&text, &self.nat64) {
            Ok(manifest) => manifest,
            Err(ManifestError::Parse) => {
                return self
                    .refuse(
                        &proposal.id,
                        ProposalState::Received,
                        checks,
                        "manifest",
                        "manifest:invalid_yaml",
                        false,
                    )
                    .await;
            }
            Err(_) => {
                return self
                    .refuse(
                        &proposal.id,
                        ProposalState::Received,
                        checks,
                        "manifest",
                        "manifest:invalid",
                        false,
                    )
                    .await;
            }
        };
        if manifest
            .validate_provider_secrets(&self.provider_secrets)
            .is_err()
        {
            return self
                .refuse(
                    &proposal.id,
                    ProposalState::Received,
                    checks,
                    "manifest",
                    "manifest:invalid",
                    false,
                )
                .await;
        }
        // ADR-025 is a manifest refusal, before binding an otherwise valid identity.
        if manifest.scope == Scope::Global && manifest.runtime.kind != RuntimeKind::None {
            return self
                .refuse(
                    &proposal.id,
                    ProposalState::Received,
                    checks,
                    "manifest",
                    "phase:global",
                    false,
                )
                .await;
        }
        let lock = match super::lock::Lock::load(&self.home) {
            Ok(lock) => lock,
            Err(_) => {
                return self
                    .refuse(
                        &proposal.id,
                        ProposalState::Received,
                        checks,
                        "receipt",
                        "receipt:io",
                        false,
                    )
                    .await;
            }
        };
        let update_of = lock
            .extensions
            .get(&manifest.id)
            .map(|ext| ext.active.clone());
        let omitted_home_ro_files = self.supervisor.configured_home_ro_files().to_vec();
        let mut omitted_fs_complete: Vec<String> = manifest
            .permissions
            .fs
            .read
            .iter()
            .chain(&manifest.permissions.fs.write)
            .filter(|path| !path.starts_with("${"))
            .chain(&omitted_home_ro_files)
            .cloned()
            .collect();
        omitted_fs_complete.sort();
        omitted_fs_complete.dedup();
        checks.extend([
            passed("manifest", None),
            informative(
                "permissions",
                json!({
                    "requested":manifest.permissions,
                    "omitted_fs": {
                        "read":manifest.permissions.fs.read.iter().filter(|path| !path.starts_with("${")).collect::<Vec<_>>(),
                        "write":manifest.permissions.fs.write.iter().filter(|path| !path.starts_with("${")).collect::<Vec<_>>()
                    },
                    "omitted_home_ro_files": omitted_home_ro_files,
                    "omitted_fs_complete": omitted_fs_complete
                }),
            ),
        ]);
        let destination = self.home.join("extensions/quarantine").join(&proposal.id);
        if lease.retain_receipt(&proposal.id).is_err() {
            return self
                .refuse(
                    &proposal.id,
                    ProposalState::Received,
                    checks,
                    "receipt",
                    "receipt:io",
                    false,
                )
                .await;
        }
        if lease.sync_receipts().is_err() {
            return self
                .refuse(
                    &proposal.id,
                    ProposalState::Received,
                    checks,
                    "receipt",
                    "receipt:io",
                    true,
                )
                .await;
        }
        let normalized = serde_json::to_value(&manifest).map_err(|_| LocalError::Persistence {
            proposal_id: proposal.id.clone(),
        })?;
        self.store
            .transition_proposal(
                proposal.id.clone(),
                ProposalState::Received,
                ProposalState::Checking,
                ProposalUpdate {
                    identity: Some(ProposalIdentity {
                        ext_id: manifest.id.clone(),
                        version: manifest.version.clone(),
                        manifest: normalized,
                        update_of,
                    }),
                    checks: Some(checks.clone()),
                    ..Default::default()
                },
            )
            .await
            .map_err(|_| LocalError::Persistence {
                proposal_id: proposal.id.clone(),
            })?;
        let dependency_plan = dependencies::plan(manifest.runtime.kind, &destination);
        let resolved = match dependency_plan {
            Ok(Some(kind)) => match &self.dependency_resolver {
                Some(resolver) => resolver
                    .resolve(kind, &destination, lease.clone())
                    .await
                    .map(Some)
                    .map_err(|error| error.reason()),
                None => Err("dependency resolver unavailable"),
            },
            Ok(None) => Ok(None),
            Err(error) => Err(error.reason()),
        };
        let resolved = match resolved {
            Ok(resolved) => resolved,
            Err(reason) => {
                self.fail(&proposal.id, checks, "dependencies", reason)
                    .await?;
                return Err(LocalError::Failed {
                    proposal_id: proposal.id,
                    reason,
                });
            }
        };
        checks.push(passed(
            "dependencies",
            Some(if resolved.is_some() {
                "installed from locked dependencies with scripts and source builds disabled".into()
            } else {
                "no runtime dependency installation required".into()
            }),
        ));
        let (post, packages) = if let Some(DependencyReport {
            inspection,
            packages,
        }) = resolved
        {
            (inspection, packages)
        } else {
            let inspected = destination.clone();
            let inspection_lease = lease.clone();
            let post = tokio::task::spawn_blocking(move || {
                let _lease = inspection_lease;
                bundle::inspect(
                    &inspected,
                    &BundleBudget::start(BundleProfile::PostDependencies),
                )
            })
            .await;
            let post = match post {
                Ok(Ok(post)) => post,
                Ok(Err(error)) => {
                    let reason = error.receipt_reason();
                    self.fail(&proposal.id, checks, "bundle", reason).await?;
                    return Err(LocalError::Failed {
                        proposal_id: proposal.id,
                        reason,
                    });
                }
                Err(_) => {
                    self.fail(
                        &proposal.id,
                        checks,
                        "bundle",
                        "bundle inspection interrupted",
                    )
                    .await?;
                    return Err(LocalError::Failed {
                        proposal_id: proposal.id,
                        reason: "bundle inspection interrupted",
                    });
                }
            };
            (post, vec![])
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
        let reviewed =
            super::lock::Lock::load(&self.home).map_err(|_| LocalError::Persistence {
                proposal_id: proposal.id.clone(),
            })?;
        let review_base = crate::store::ReviewBase {
            update_of: reviewed
                .extensions
                .get(&manifest.id)
                .map(|extension| extension.active.clone()),
            hash: reviewed
                .review_base_hash(&manifest.id)
                .map_err(|_| LocalError::Persistence {
                    proposal_id: proposal.id.clone(),
                })?,
        };
        let proposal = self
            .store
            .transition_proposal(
                proposal.id.clone(),
                ProposalState::Checking,
                ProposalState::Checked,
                ProposalUpdate {
                    checks: Some(checks),
                    hash: Some(post.bundle_hash),
                    packages: Some(packages),
                    review_base: Some(review_base),
                    ..Default::default()
                },
            )
            .await
            .map_err(|_| LocalError::Persistence {
                proposal_id: proposal.id,
            })?;
        Ok(LocalReport {
            proposal,
            ignored: receipt.ignored,
            catalog,
        })
    }

    async fn admission(&self) -> Result<Arc<InstallerLease>, LocalError> {
        let lease = self
            .lease
            .get_or_try_init(|| async {
                let home = self.home.clone();
                let lease = tokio::task::spawn_blocking(move || InstallerLease::acquire(&home))
                    .await
                    .map_err(|_| LocalError::Admission)?
                    .map_err(|_| LocalError::Admission)?;
                let lease = Arc::new(lease);
                let report = recovery::recover(&self.home, self.store.clone(), lease.clone())
                    .await
                    .map_err(|_| LocalError::Recovery)?;
                for diagnostic in report.diagnostics {
                    tracing::warn!(
                        code = diagnostic.code.as_str(),
                        proposal_id = diagnostic.proposal_id,
                        "installer recovery diagnostic"
                    );
                }
                Ok::<_, LocalError>(lease)
            })
            .await?;
        Ok(lease.clone())
    }

    async fn refuse(
        &self,
        id: &str,
        state: ProposalState,
        checks: Vec<ProposalCheck>,
        name: &str,
        reason: &'static str,
        final_owned: bool,
    ) -> Result<LocalReport, LocalError> {
        self.record_failure(id, state, checks, name, reason).await?;
        if state == ProposalState::Received {
            // The terminal commit precedes deletion. Failed persistence returns
            // above, retaining the bytes for the next boot's reconciliation.
            let home = self.home.clone();
            let proposal_id = id.to_owned();
            let lease = self.lease.get().cloned();
            let cleaned = tokio::task::spawn_blocking(move || {
                let _lease = lease;
                recovery::remove_receipt(&home, &proposal_id, final_owned)
            })
            .await;
            if !matches!(cleaned, Ok(Ok(()))) {
                tracing::warn!(
                    proposal_id = id,
                    code = "cleanup_failed",
                    "installer receipt cleanup deferred"
                );
            }
        }
        Err(LocalError::Failed {
            proposal_id: id.into(),
            reason,
        })
    }

    async fn fail(
        &self,
        id: &str,
        checks: Vec<ProposalCheck>,
        name: &str,
        reason: &'static str,
    ) -> Result<(), LocalError> {
        let current =
            self.store
                .proposal(id.into())
                .await
                .map_err(|_| LocalError::Persistence {
                    proposal_id: id.into(),
                })?;
        self.record_failure(id, current.state, checks, name, reason)
            .await
    }

    async fn record_failure(
        &self,
        id: &str,
        state: ProposalState,
        mut checks: Vec<ProposalCheck>,
        name: &str,
        reason: &'static str,
    ) -> Result<(), LocalError> {
        checks.push(ProposalCheck {
            name: name.into(),
            passed: false,
            blocking: true,
            detail: Some(reason.into()),
        });
        let update = ProposalUpdate {
            checks: Some(checks),
            failure_reason: Some(
                if state == ProposalState::Received
                    || reason.starts_with("limit:")
                    || reason.starts_with("receipt:")
                {
                    reason
                } else {
                    "check:failed"
                }
                .into(),
            ),
            ..Default::default()
        };
        self.store
            .transition_proposal(id.into(), state, ProposalState::Failed, update)
            .await
            .map_err(|_| LocalError::Persistence {
                proposal_id: id.into(),
            })?;
        Ok(())
    }
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
