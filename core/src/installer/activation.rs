//! ADR-036 coordinator. A durable lock is still a candidate until the writer
//! commits its promotion and public event together. All entrypoints own their
//! worker so cancellation cannot release exclusion before mutations finish.
use super::{
    lease::InstallerLease,
    lock::{Approval, Lock, LockedExtension, LockedVersion, Package, approval_at_ms},
    overrides::Overrides,
    promotion,
    publication::PromotionPublication,
    recovery,
};
use crate::store::{
    HumanDecision, NewPromotionIntent, PromotionAbortReason, PromotionIntent, PromotionState,
    Proposal, ProposalNonce, ProposalState, ProposalUpdate, ReviewBase, Store, StoreError,
};
use std::{sync::Arc, time::Instant};

#[derive(Debug, thiserror::Error)]
pub enum ActivationError {
    #[error("promotion:publication_incomplete")]
    Publication,
    #[error("promotion:busy")]
    Busy,
    #[error("promotion:stale_base")]
    StaleBase,
    #[error("promotion:already_active")]
    AlreadyActive,
    #[error("promotion:key_conflict")]
    KeyConflict,
    #[error("promotion:integrity")]
    Integrity,
    #[error("promotion:recovery_conflict")]
    RecoveryConflict,
    #[error("promotion:aborted")]
    Aborted,
    #[error("promotion:persistence")]
    Persistence(#[source] StoreError),
    #[error("promotion:io")]
    Io,
    #[error("promotion:worker_unavailable")]
    Task,
}
impl From<StoreError> for ActivationError {
    fn from(error: StoreError) -> Self {
        match &error {
            StoreError::Invalid("administrative admission expired") => Self::Busy,
            StoreError::Invalid("promotion:stale_base") => Self::StaleBase,
            StoreError::Invalid("promotion:already_active") => Self::AlreadyActive,
            StoreError::Invalid("promotion:key_conflict") => Self::KeyConflict,
            StoreError::Invalid("promotion:integrity") => Self::Integrity,
            StoreError::Invalid("promotion:recovery_conflict") => Self::RecoveryConflict,
            _ => Self::Persistence(error),
        }
    }
}

#[derive(Clone)]
pub struct PromotionCoordinator {
    store: Arc<Store>,
    lease: Arc<InstallerLease>,
    publication: Option<Arc<dyn PromotionPublication>>,
}
impl PromotionCoordinator {
    /// The caller shares the installer's existing file lease; acquiring a
    /// second independent flock would exclude its own checker/recovery worker.
    /// Only for exclusive offline work or boot before a runtime registry exists.
    pub fn new_offline(store: Arc<Store>, lease: Arc<InstallerLease>) -> Self {
        Self {
            store,
            lease,
            publication: None,
        }
    }

    pub fn with_publication(
        store: Arc<Store>,
        lease: Arc<InstallerLease>,
        publication: Arc<dyn PromotionPublication>,
    ) -> Self {
        Self {
            store,
            lease,
            publication: Some(publication),
        }
    }

    pub async fn approve(
        &self,
        proposal_id: String,
        nonce: ProposalNonce,
        overrides: Overrides,
    ) -> Result<Proposal, ActivationError> {
        let coordinator = self.clone();
        tokio::spawn(async move {
            let _section = coordinator
                .store
                .owner()
                .installer_gate()
                .lock_owned()
                .await;
            coordinator.reconcile_locked().await?;
            coordinator.verify_owner()?;
            let proposal = coordinator.store.proposal(proposal_id.clone()).await?;
            let id = proposal
                .ext_id
                .as_deref()
                .ok_or(ActivationError::Integrity)?;
            let lock =
                Lock::load(coordinator.store.owner().home()).map_err(|_| ActivationError::Io)?;
            let review_base = ReviewBase {
                update_of: lock
                    .extensions
                    .get(id)
                    .map(|extension| extension.active.clone()),
                hash: lock
                    .review_base_hash(id)
                    .map_err(|_| ActivationError::Integrity)?,
            };
            coordinator
                .store
                .transition_proposal(
                    proposal_id,
                    ProposalState::Checked,
                    ProposalState::Approved,
                    ProposalUpdate {
                        decision: Some(HumanDecision::User(nonce)),
                        review_base: Some(review_base),
                        overrides: Some(overrides),
                        ..Default::default()
                    },
                )
                .await
                .map_err(Into::into)
        })
        .await
        .map_err(|_| ActivationError::Task)?
    }

    pub async fn promote(&self, proposal_id: String) -> Result<PromotionIntent, ActivationError> {
        let coordinator = self.clone();
        tokio::spawn(async move { coordinator.promote_owned(proposal_id, None, None).await })
            .await
            .map_err(|_| ActivationError::Task)?
    }

    /// ADR-045 acknowledges the durable intent, while its owned worker keeps
    /// exclusion through materialization, lock publication and writer commit.
    pub async fn admit_promotion(
        &self,
        proposal_id: String,
    ) -> Result<PromotionIntent, ActivationError> {
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        if let Some(intent) = self
            .store
            .installation_snapshot(proposal_id.clone())
            .await?
            .promotion
            && matches!(
                intent.state,
                PromotionState::Prepared | PromotionState::Committed
            )
        {
            if intent.state == PromotionState::Committed {
                let coordinator = self.clone();
                return tokio::spawn(async move {
                    let _section = tokio::time::timeout_at(
                        deadline.into(),
                        coordinator.store.owner().installer_gate().lock_owned(),
                    )
                    .await
                    .map_err(|_| ActivationError::Busy)?;
                    coordinator.republish_current(&intent).await?;
                    Ok(intent)
                })
                .await
                .map_err(|_| ActivationError::Task)?;
            }
            return Ok(intent);
        }
        let coordinator = self.clone();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _ = coordinator
                .promote_owned(proposal_id, Some(sender), Some(deadline))
                .await;
        });
        receiver.await.map_err(|_| ActivationError::Task)?
    }

    async fn promote_owned(
        &self,
        proposal_id: String,
        admitted: Option<tokio::sync::oneshot::Sender<Result<PromotionIntent, ActivationError>>>,
        deadline: Option<Instant>,
    ) -> Result<PromotionIntent, ActivationError> {
        let coordinator = self.clone();
        let setup = async {
            let section = tokio::time::timeout_at(
                tokio::time::Instant::from_std(
                    deadline.unwrap_or_else(|| Instant::now() + std::time::Duration::from_secs(5)),
                ),
                coordinator.store.owner().installer_gate().lock_owned(),
            )
            .await
            .map_err(|_| ActivationError::Busy)?;
            if let Some(intent) = coordinator
                .store
                .installation_snapshot(proposal_id.clone())
                .await?
                .promotion
                && matches!(
                    intent.state,
                    PromotionState::Prepared | PromotionState::Committed
                )
            {
                if intent.state == PromotionState::Committed {
                    coordinator.republish_current(&intent).await?;
                }
                return Ok((section, intent, false));
            }
            coordinator.reconcile_locked().await?;
            coordinator.verify_owner()?;
            let proposal = coordinator.store.proposal(proposal_id.clone()).await?;
            let before = Lock::read_snapshot(coordinator.store.owner().home())
                .map_err(|_| ActivationError::Io)?;
            let previous = before
                .as_deref()
                .map(Lock::parse_snapshot)
                .transpose()
                .map_err(|_| ActivationError::Integrity)?
                .unwrap_or_default();
            let after = next_lock(&previous, &proposal)?
                .encode_snapshot()
                .map_err(|_| ActivationError::Integrity)?;
            let before = before
                .map(String::from_utf8)
                .transpose()
                .map_err(|_| ActivationError::Integrity)?;
            let intent = coordinator
                .store
                .prepare_promotion_before(
                    NewPromotionIntent {
                        proposal_id: proposal_id.clone(),
                        before_lock: before,
                        after_lock: after,
                    },
                    deadline,
                )
                .await?;
            Ok::<_, ActivationError>((section, intent, true))
        }
        .await;
        let (_section, intent, publish) = match setup {
            Ok(result) => result,
            Err(error) => {
                if let Some(admitted) = admitted {
                    let _ = admitted.send(Err(error));
                    return Err(ActivationError::Task);
                }
                return Err(error);
            }
        };
        if let Some(admitted) = admitted {
            let _ = admitted.send(Ok(intent.clone()));
        }
        if !publish {
            return Ok(intent);
        }
        if let Err(error) = promotion::materialize_intent(
            coordinator.store.owner().home(),
            coordinator.store.clone(),
            coordinator.lease.clone(),
            proposal_id,
            intent.operation_id.clone(),
        )
        .await
        {
            let reason = match error {
                promotion::PromotionError::Changed
                | promotion::PromotionError::UnsafePath
                | promotion::PromotionError::Unapproved
                | promotion::PromotionError::Bundle(_) => PromotionAbortReason::Integrity,
                _ => PromotionAbortReason::Io,
            };
            // No lock write was attempted. Still reread exact bytes rather
            // than assuming a concurrent/external change did not occur.
            let current = Lock::read_snapshot(coordinator.store.owner().home())
                .map_err(|_| ActivationError::RecoveryConflict)?;
            if current.as_deref() != intent.before_lock.as_deref().map(str::as_bytes) {
                return Err(ActivationError::RecoveryConflict);
            }
            coordinator
                .store
                .abort_promotion(intent.operation_id.clone(), reason)
                .await?;
            coordinator.cleanup(&intent, false).await;
            return Err(if reason == PromotionAbortReason::Integrity {
                ActivationError::Integrity
            } else {
                ActivationError::Io
            });
        }
        if let Some(publication) = &coordinator.publication {
            publication
                .block_before_lock(&intent.ext_id)
                .map_err(|_| ActivationError::Publication)?;
        }
        let owner = coordinator.store.owner().clone();
        let text = intent.after_lock.clone();
        let published = tokio::task::spawn_blocking(move || {
            owner.verify().map_err(|_| ActivationError::Io)?;
            Lock::write_snapshot(owner.home(), text.as_bytes()).map_err(|_| ActivationError::Io)
        })
        .await
        .map_err(|_| ActivationError::Task)?;
        if published.is_err() {
            // rename/fsync outcome may be uncertain. The common recovery
            // table is the authority; never compensate an unknown lock.
            return coordinator
                .reconcile_locked()
                .await?
                .ok_or(ActivationError::RecoveryConflict)
                .and_then(|reconciled| {
                    if reconciled.state == PromotionState::Committed {
                        Ok(reconciled)
                    } else {
                        Err(ActivationError::Io)
                    }
                });
        }
        let committed = coordinator
            .store
            .commit_promotion(intent.operation_id.clone())
            .await?;
        if let Some(publication) = &coordinator.publication {
            publication
                .publish_after_commit(&committed)
                .await
                .map_err(|_| ActivationError::Publication)?;
        }
        coordinator.cleanup(&committed, true).await;
        Ok(committed)
    }

    /// Call after instance recovery, before permitting extension dispatch or
    /// lock mutations. Unknown state is retained, never overwritten or guessed.
    pub async fn reconcile(&self) -> Result<Option<PromotionIntent>, ActivationError> {
        let coordinator = self.clone();
        tokio::spawn(async move {
            let _section = coordinator
                .store
                .owner()
                .installer_gate()
                .lock_owned()
                .await;
            coordinator.reconcile_locked().await
        })
        .await
        .map_err(|_| ActivationError::Task)?
    }

    pub async fn operation(
        &self,
        operation_id: String,
    ) -> Result<PromotionIntent, ActivationError> {
        let coordinator = self.clone();
        tokio::spawn(async move {
            let _section = coordinator
                .store
                .owner()
                .installer_gate()
                .lock_owned()
                .await;
            let intent = coordinator.store.promotion_intent(operation_id).await?;
            match intent.state {
                PromotionState::Committed => Ok(intent),
                PromotionState::Aborted => Err(ActivationError::Aborted),
                PromotionState::Prepared => coordinator
                    .reconcile_locked()
                    .await?
                    .ok_or(ActivationError::RecoveryConflict),
            }
        })
        .await
        .map_err(|_| ActivationError::Task)?
    }

    fn verify_owner(&self) -> Result<(), ActivationError> {
        self.store.owner().verify().map_err(|_| ActivationError::Io)
    }

    // An explicit repeated request may finish a failed in-memory publication,
    // but cannot select a historical version or rewrite the durable lock.
    async fn republish_current(&self, intent: &PromotionIntent) -> Result<(), ActivationError> {
        let Some(publication) = &self.publication else {
            return Ok(());
        };
        self.verify_owner()?;
        let current = Lock::load_required(self.store.owner().home())
            .map_err(|_| ActivationError::RecoveryConflict)?;
        let after = Lock::parse_snapshot(intent.after_lock.as_bytes())
            .map_err(|_| ActivationError::Integrity)?;
        if current
            .review_base_hash(&intent.ext_id)
            .map_err(|_| ActivationError::Integrity)?
            == after
                .review_base_hash(&intent.ext_id)
                .map_err(|_| ActivationError::Integrity)?
        {
            publication
                .publish_after_commit(intent)
                .await
                .map_err(|_| ActivationError::Publication)?;
        }
        Ok(())
    }

    pub(crate) async fn reconcile_locked(
        &self,
    ) -> Result<Option<PromotionIntent>, ActivationError> {
        self.verify_owner()?;
        let Some(intent) = self.store.pending_promotion().await? else {
            // No temporary can authorize a version. Cleanup is best effort and
            // follows full journal validation, never an alternative to it.
            let owner = self.store.owner().clone();
            let lease = self.lease.clone();
            let result = tokio::task::spawn_blocking(move || {
                let _lease = lease;
                owner.verify().map_err(std::io::Error::other)?;
                Lock::load_required(owner.home()).map_err(std::io::Error::other)?;
                recovery::remove_orphan_promotion_staging(owner.home())?;
                Lock::discard_temporary(owner.home()).map_err(std::io::Error::other)
            })
            .await;
            if !matches!(result, Ok(Ok(()))) {
                tracing::warn!("promotion orphan cleanup incomplete; resources retained");
            }
            return Ok(None);
        };
        if let Some(publication) = &self.publication {
            publication
                .block_before_lock(&intent.ext_id)
                .map_err(|_| ActivationError::Publication)?;
        }
        let current = Lock::read_snapshot(self.store.owner().home())
            .map_err(|_| ActivationError::RecoveryConflict)?;
        if current.as_deref() == intent.before_lock.as_deref().map(str::as_bytes) {
            let aborted = self
                .store
                .abort_promotion(
                    intent.operation_id.clone(),
                    PromotionAbortReason::Interrupted,
                )
                .await?;
            if let Some(publication) = &self.publication {
                publication
                    .reconcile(&aborted)
                    .await
                    .map_err(|_| ActivationError::Publication)?;
            }
            self.cleanup(&aborted, false).await;
            Ok(Some(aborted))
        } else if current.as_deref() == Some(intent.after_lock.as_bytes()) {
            promotion::verify_published(self.store.clone(), intent.proposal_id.clone())
                .await
                .map_err(|_| ActivationError::RecoveryConflict)?;
            Lock::sync_snapshot(self.store.owner().home())
                .map_err(|_| ActivationError::RecoveryConflict)?;
            let committed = self
                .store
                .commit_promotion(intent.operation_id.clone())
                .await?;
            if let Some(publication) = &self.publication {
                publication
                    .reconcile(&committed)
                    .await
                    .map_err(|_| ActivationError::Publication)?;
            }
            self.cleanup(&committed, true).await;
            Ok(Some(committed))
        } else {
            Err(ActivationError::RecoveryConflict)
        }
    }

    async fn cleanup(&self, intent: &PromotionIntent, committed: bool) {
        let owner = self.store.owner().clone();
        let operation = intent.operation_id.clone();
        let proposal = intent.proposal_id.clone();
        let lease = self.lease.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _lease = lease;
            owner.verify().map_err(std::io::Error::other)?;
            recovery::remove_promotion_staging(owner.home(), &operation)?;
            Lock::discard_temporary(owner.home()).map_err(std::io::Error::other)?;
            if committed {
                recovery::remove_receipt(owner.home(), &proposal, true)?;
            }
            Ok::<_, std::io::Error>(())
        })
        .await;
        if !matches!(result, Ok(Ok(()))) {
            tracing::warn!(
                operation_id = intent.operation_id,
                "promotion cleanup incomplete; resources retained"
            );
        }
    }
}

fn next_lock(previous: &Lock, proposal: &Proposal) -> Result<Lock, ActivationError> {
    if proposal.review_base_hash.is_none() {
        return Err(ActivationError::StaleBase);
    }
    let (manifest, hash) = promotion::approved(proposal).map_err(|_| ActivationError::Integrity)?;
    let id = &manifest.id;
    if proposal.review_base_hash.as_deref()
        != Some(
            previous
                .review_base_hash(id)
                .map_err(|_| ActivationError::Integrity)?
                .as_str(),
        )
        || previous
            .extensions
            .get(id)
            .map(|extension| extension.active.as_str())
            != proposal.update_of.as_deref()
    {
        return Err(ActivationError::StaleBase);
    }
    let key = format!("{}-{}", manifest.version, &hash[7..19]);
    if previous
        .extensions
        .get(id)
        .is_some_and(|extension| extension.active == key)
    {
        return Err(ActivationError::AlreadyActive);
    }
    let smoke = proposal
        .checks
        .as_ref()
        .and_then(|checks| checks.iter().find(|check| check.name == "smoke"))
        .and_then(|check| check.detail.as_ref())
        .ok_or(ActivationError::Integrity)?;
    let catalog =
        crate::strict_json::parse(smoke.as_bytes()).map_err(|_| ActivationError::Integrity)?;
    let tools = catalog
        .get("tools")
        .and_then(serde_json::Value::as_array)
        .ok_or(ActivationError::Integrity)?
        .clone();
    let tools_hash = catalog
        .get("tools_hash")
        .and_then(serde_json::Value::as_str)
        .ok_or(ActivationError::Integrity)?
        .to_owned();
    let candidate = LockedVersion {
        version: manifest.version,
        hash,
        path: format!("store/{id}/{key}"),
        source: proposal.source.clone(),
        approved: Approval {
            by: "user".into(),
            at: approval_at_ms(proposal.updated_at).map_err(|_| ActivationError::Integrity)?,
            approval_id: None,
        },
        overrides: proposal.overrides.clone(),
        privileges: vec![],
        tools,
        tools_hash,
        packages: proposal
            .packages
            .as_ref()
            .ok_or(ActivationError::Integrity)?
            .iter()
            .map(|package| Package {
                ecosystem: package.ecosystem.clone(),
                name: package.name.clone(),
                version: package.version.clone(),
            })
            .collect(),
        audit: None,
    };
    let mut next = previous.clone();
    let extension = next
        .extensions
        .entry(id.clone())
        .or_insert_with(|| LockedExtension {
            enabled: true,
            active: key.clone(),
            versions: Default::default(),
        });
    if let Some(existing) = extension.versions.get(&key) {
        let mut comparable = candidate;
        comparable.source = existing.source.clone();
        comparable.approved = existing.approved.clone();
        if serde_json::to_value(&comparable).map_err(|_| ActivationError::Integrity)?
            != serde_json::to_value(existing).map_err(|_| ActivationError::Integrity)?
        {
            return Err(ActivationError::KeyConflict);
        }
    } else {
        extension.versions.insert(key.clone(), candidate);
    }
    extension.active = key;
    Ok(next)
}
