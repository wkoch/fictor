//! ADR-045's trusted local installation flow. None of these methods is a
//! Kernel/MCP method. Long work owns its task independently of the RPC peer.
use super::{
    activation::{ActivationError, PromotionCoordinator},
    local::{LocalChecker, LocalError},
    lock::Lock,
    manifest::Manifest,
    overrides::{self, Overrides},
};
use crate::{
    admin::{
        AdminMutationError as Error, AdminMutationFuture, AdminMutationHandler,
        MutationReason as Reason,
    },
    proxy::nat64::Nat64Prefixes,
    store::{
        HumanDecision, PromotionState, Proposal, ProposalCheck, ProposalNonce, ProposalState,
        ProposalUpdate, ResolvedPackage, ReviewBase, Store, StoreError,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Review {
    pub source: Value,
    pub tainted: bool,
    pub manifest: Value,
    pub bundle_hash: String,
    pub tools: Vec<Value>,
    pub tools_hash: String,
    #[serde(deserialize_with = "nullable")]
    pub update_of: Option<String>,
    pub review_base_hash: String,
    #[serde(deserialize_with = "nullable")]
    pub base: Option<Value>,
    pub packages: Vec<ResolvedPackage>,
    #[serde(serialize_with = "serialize_review_checks")]
    pub checks: Vec<ProposalCheck>,
    pub omitted_fs: Vec<String>,
    pub overrides: Overrides,
}

fn serialize_review_checks<S: serde::Serializer>(
    checks: &[ProposalCheck],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Check<'a> {
        name: &'a str,
        passed: bool,
        blocking: bool,
        detail: Option<&'a str>,
    }
    checks
        .iter()
        .map(|check| Check {
            name: &check.name,
            passed: check.passed,
            blocking: check.blocking,
            detail: check.detail.as_deref(),
        })
        .collect::<Vec<_>>()
        .serialize(serializer)
}
impl Review {
    pub fn hash(&self) -> Result<String, Error> {
        hash(&serde_json::to_value(self).map_err(|_| integrity())?)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionStatus {
    pub operation_id: String,
    pub state: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallStatus {
    pub schema: u32,
    pub proposal_id: String,
    pub state: ProposalState,
    #[serde(deserialize_with = "nullable")]
    pub ext_id: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub version: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub reason: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub review: Option<Review>,
    #[serde(deserialize_with = "nullable")]
    pub nonce: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub review_hash: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub promotion: Option<PromotionStatus>,
}

fn nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}

impl InstallStatus {
    /// A trusted CLI verifies the complete response and review before showing
    /// consent. A hash alone never makes missing/invalid fields acceptable.
    pub fn parse(value: Value, id: &str) -> Result<Self, Error> {
        if let Some(review) = value.get("review").filter(|v| !v.is_null()) {
            if !review
                .get("packages")
                .and_then(Value::as_array)
                .is_some_and(|items| {
                    items
                        .iter()
                        .all(|item| object_fields(item, &["ecosystem", "name", "version"]))
                })
                || !review
                    .get("checks")
                    .and_then(Value::as_array)
                    .is_some_and(|items| {
                        items.iter().all(|item| {
                            object_fields(item, &["name", "passed", "blocking", "detail"])
                        })
                    })
            {
                return Err(integrity());
            }
            if let Some(base) = review.get("base").filter(|base| !base.is_null()) {
                let version = base.get("version").ok_or_else(integrity)?;
                if !object_fields(
                    version,
                    &[
                        "version",
                        "hash",
                        "path",
                        "source",
                        "approved",
                        "overrides",
                        "privileges",
                        "tools",
                        "tools_hash",
                        "packages",
                        "audit",
                    ],
                ) || !version
                    .get("approved")
                    .is_some_and(|approval| object_fields(approval, &["by", "at", "approval_id"]))
                {
                    return Err(integrity());
                }
            }
        }
        let status: Self = serde_json::from_value(value).map_err(|_| integrity())?;
        if status.schema != 1
            || status.proposal_id != id
            || !valid_id(id)
            || status.promotion.as_ref().is_some_and(|p| {
                !valid_id(&p.operation_id)
                    || !matches!(p.state.as_str(), "prepared" | "committed" | "aborted")
            })
        {
            return Err(integrity());
        }
        let reviewed = matches!(
            status.state,
            ProposalState::Checked | ProposalState::Approved | ProposalState::Promoted
        );
        if !reviewed && (status.review.is_some() || status.review_hash.is_some()) {
            return Err(integrity());
        }
        if (status.state == ProposalState::Checked) != status.nonce.is_some()
            || status.nonce.as_ref().is_some_and(|n| !valid_nonce(n))
            || (status.review.is_some() != status.review_hash.is_some())
            || status.state == ProposalState::Checked && status.review.is_none()
            || status.state != ProposalState::Failed && status.reason.is_some()
        {
            return Err(integrity());
        }
        if let Some(review) = &status.review {
            if review.source != json!({"kind":"local"})
                || review.tainted
                || review.hash()?.as_str() != status.review_hash.as_deref().ok_or_else(integrity)?
                || !valid_hash(&review.bundle_hash)
                || hash(review.base.as_ref().unwrap_or(&Value::Null))? != review.review_base_hash
            {
                return Err(integrity());
            }
            let manifest =
                Manifest::parse(&review.manifest.to_string()).map_err(|_| integrity())?;
            if status.ext_id.as_deref() != Some(manifest.id.as_str())
                || status.version.as_deref() != Some(manifest.version.as_str())
            {
                return Err(integrity());
            }
            let catalog = crate::gateway::PinnedCatalog::new(review.tools.clone())
                .map_err(|_| integrity())?;
            if catalog.tools() != review.tools || catalog.hash() != review.tools_hash {
                return Err(integrity());
            }
            overrides::resolve(
                &manifest,
                &catalog,
                &review.overrides,
                "user",
                &Nat64Prefixes::default(),
            )
            .map_err(|_| integrity())?;
            for name in [
                "manifest",
                "dependencies",
                "bundle",
                "declarations",
                "smoke",
            ] {
                if review
                    .checks
                    .iter()
                    .filter(|c| c.name == name && c.blocking && c.passed)
                    .count()
                    != 1
                {
                    return Err(integrity());
                }
            }
            if review.checks.iter().any(|c| c.blocking && !c.passed) {
                return Err(integrity());
            }
            let omitted = omitted_files(&review.checks, &manifest)?;
            if omitted != review.omitted_fs {
                return Err(integrity());
            }
            match &review.base {
                None if review.update_of.is_none() => {}
                Some(base) => {
                    #[derive(Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct Base {
                        active: String,
                        enabled: bool,
                        version: super::lock::LockedVersion,
                    }
                    let base: Base =
                        serde_json::from_value(base.clone()).map_err(|_| integrity())?;
                    if review.update_of.as_deref() != Some(base.active.as_str()) {
                        return Err(integrity());
                    }
                    let mut lock = Lock::default();
                    lock.extensions.insert(
                        manifest.id,
                        super::lock::LockedExtension {
                            enabled: base.enabled,
                            active: base.active.clone(),
                            versions: BTreeMap::from([(base.active, base.version)]),
                        },
                    );
                    lock.encode_snapshot().map_err(|_| integrity())?;
                }
                _ => return Err(integrity()),
            }
        }
        Ok(status)
    }
}

fn valid_id(value: &str) -> bool {
    value
        .parse::<ulid::Ulid>()
        .is_ok_and(|id| id.to_string() == value)
}
fn valid_nonce(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_hash(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(valid_nonce)
}

#[derive(Clone)]
struct Presented {
    review: Review,
    nonce: String,
}

#[derive(Clone)]
pub struct InstallService {
    store: Arc<Store>,
    checker: LocalChecker,
    coordinator: PromotionCoordinator,
    // A rejection may use the base actually presented before another operation
    // changed it. No cache survives restart or silently renews that review.
    presented: Arc<Mutex<BTreeMap<(String, String), Presented>>>,
}
impl InstallService {
    pub async fn new(store: Arc<Store>, checker: LocalChecker) -> Result<Self, Error> {
        let lease = checker.shared_lease().await.map_err(local_error)?;
        Ok(Self {
            coordinator: PromotionCoordinator::with_publication(
                store.clone(),
                lease,
                Arc::new(checker.control_registry()),
            ),
            store,
            checker,
            presented: Arc::default(),
        })
    }
    pub fn coordinator(&self) -> PromotionCoordinator {
        self.coordinator.clone()
    }

    pub async fn prepare(&self, path: &str) -> Result<String, Error> {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        if !Path::new(path).is_absolute() || path.contains('\0') {
            return Err(Error::none(Reason::InvalidState));
        }
        let section = tokio::time::timeout_at(
            deadline.into(),
            self.store.owner().installer_gate().lock_owned(),
        )
        .await
        .map_err(|_| Error::none(Reason::Busy))?;
        self.coordinator
            .reconcile_locked()
            .await
            .map_err(|_| Error::none(Reason::RecoveryRequired))?;
        drop(section);
        self.checker
            .prepare_local_before(Path::new(path), deadline)
            .await
            .map_err(local_error)
    }

    pub async fn status(
        &self,
        id: String,
        patch: Option<Overrides>,
    ) -> Result<InstallStatus, Error> {
        self.store.owner().verify().map_err(|_| integrity())?;
        let mut snapshot = self
            .store
            .installation_snapshot(id.clone())
            .await
            .map_err(read_error)?;
        let reviewed = matches!(
            snapshot.proposal.state,
            ProposalState::Checked | ProposalState::Approved | ProposalState::Promoted
        );
        let requested_patch = patch.clone();
        let patch = select_patch(&snapshot.proposal, patch)?;
        let mut review = None;
        let mut review_hash = None;
        if reviewed {
            // A prepared publication must remain observable without waiting for
            // its copying/fsync worker's section. Its exact before snapshot is
            // the historical base, already validated with the journal row.
            let historical = if snapshot.proposal.state != ProposalState::Checked {
                snapshot.promotion.as_ref().map(|intent| {
                    intent
                        .before_lock
                        .as_deref()
                        .map(|text| Lock::parse_snapshot(text.as_bytes()))
                        .transpose()
                        .map(|lock| lock.unwrap_or_default())
                })
            } else {
                None
            };
            let built = if let Some(historical) = historical {
                historical
                    .map_err(|_| integrity())
                    .and_then(|lock| build_status_review(&snapshot.proposal, &lock, patch.clone()))
            } else {
                let _section = tokio::time::timeout(
                    Duration::from_secs(5),
                    self.store.owner().installer_gate().lock_owned(),
                )
                .await
                .map_err(|_| Error::none(Reason::Busy))?;
                snapshot = self
                    .store
                    .installation_snapshot(id.clone())
                    .await
                    .map_err(read_error)?;
                if !matches!(
                    snapshot.proposal.state,
                    ProposalState::Checked | ProposalState::Approved | ProposalState::Promoted
                ) {
                    Ok(None)
                } else {
                    let patch = select_patch(&snapshot.proposal, requested_patch)?;
                    let lock = if snapshot.proposal.state != ProposalState::Checked
                        && snapshot.promotion.is_some()
                    {
                        snapshot
                            .promotion
                            .as_ref()
                            .and_then(|intent| intent.before_lock.as_deref())
                            .map(|text| Lock::parse_snapshot(text.as_bytes()))
                            .transpose()
                            .map_err(|_| integrity())
                            .map(|lock| lock.unwrap_or_default())
                    } else {
                        Lock::load_required(self.store.owner().home()).map_err(|_| {
                            if snapshot.proposal.state == ProposalState::Checked {
                                integrity()
                            } else {
                                Error::none(Reason::StaleBase)
                            }
                        })
                    };
                    lock.and_then(|lock| build_status_review(&snapshot.proposal, &lock, patch))
                }
            };
            match built {
                Ok(Some(built)) => {
                    review_hash = Some(built.hash()?);
                    review = Some(built);
                }
                Ok(None) => {}
                Err(error)
                    if snapshot.proposal.state != ProposalState::Checked
                        && error.reason == Reason::StaleBase => {}
                Err(error) => return Err(error),
            }
        }
        let nonce = snapshot
            .nonce
            .as_ref()
            .map(|nonce| nonce.as_str().to_owned());
        let status = InstallStatus {
            schema: 1,
            proposal_id: id.clone(),
            state: snapshot.proposal.state,
            ext_id: snapshot.proposal.ext_id.clone(),
            version: snapshot.proposal.version.clone(),
            reason: failure_reason(&snapshot.proposal),
            review,
            nonce,
            review_hash,
            promotion: snapshot.promotion.as_ref().map(|intent| PromotionStatus {
                operation_id: intent.operation_id.clone(),
                state: match intent.state {
                    PromotionState::Prepared => "prepared",
                    PromotionState::Committed => "committed",
                    PromotionState::Aborted => "aborted",
                }
                .into(),
            }),
        };
        if status
            .promotion
            .as_ref()
            .is_some_and(|promotion| promotion.state == "committed")
        {
            let id = status.ext_id.as_deref().ok_or_else(integrity)?;
            if !self
                .checker
                .control_registry()
                .publication_ready(id)
                .map_err(Error::none)?
            {
                return Err(Error::none(Reason::Busy));
            }
        }
        let value = serde_json::to_value(&status).map_err(|_| integrity())?;
        crate::admin::bounded_json(&value).map_err(|_| Error::none(Reason::TooLarge))?;
        if let (Some(review), Some(nonce), Some(hash)) =
            (&status.review, &status.nonce, &status.review_hash)
        {
            self.presented.lock().map_err(|_| integrity())?.insert(
                (id, hash.clone()),
                Presented {
                    review: review.clone(),
                    nonce: nonce.clone(),
                },
            );
        }
        Ok(status)
    }

    pub async fn decision(
        &self,
        id: String,
        nonce: String,
        review_hash: String,
        approve: bool,
        patch: Overrides,
    ) -> Result<ProposalState, Error> {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let service = self.clone();
        tokio::spawn(async move {
            service
                .decide_owned(id, nonce, review_hash, approve, patch, deadline)
                .await
        })
        .await
        .map_err(|_| Error::unknown(Reason::IoError))?
    }
    async fn decide_owned(
        &self,
        id: String,
        nonce: String,
        review_hash: String,
        approve: bool,
        patch: Overrides,
        deadline: std::time::Instant,
    ) -> Result<ProposalState, Error> {
        let _section = tokio::time::timeout_at(
            deadline.into(),
            self.store.owner().installer_gate().lock_owned(),
        )
        .await
        .map_err(|_| Error::none(Reason::Busy))?;
        self.coordinator
            .reconcile_locked()
            .await
            .map_err(|_| Error::none(Reason::RecoveryRequired))?;
        let snapshot = self
            .store
            .installation_snapshot(id.clone())
            .await
            .map_err(read_error)?;
        if snapshot.proposal.state != ProposalState::Checked {
            return Err(Error::none(Reason::InvalidState));
        }
        let supplied = ProposalNonce::from_admin(nonce.clone())
            .map_err(|_| Error::none(Reason::InvalidNonce))?;
        let expected = snapshot.nonce.as_ref().ok_or_else(integrity)?.as_str();
        if !nonce_equal(expected, &nonce) {
            return Err(Error::none(Reason::InvalidNonce));
        }
        let review = if approve {
            let lock = Lock::load_required(self.store.owner().home()).map_err(|_| integrity())?;
            build_review(&snapshot.proposal, &lock, patch.clone())?
        } else {
            let presented = self
                .presented
                .lock()
                .map_err(|_| integrity())?
                .get(&(id.clone(), review_hash.clone()))
                .cloned();
            if let Some(presented) = presented {
                if presented.review.overrides != patch || !nonce_equal(&presented.nonce, &nonce) {
                    return Err(Error::none(Reason::ReviewMismatch));
                }
                presented.review
            } else {
                let lock =
                    Lock::load_required(self.store.owner().home()).map_err(|_| integrity())?;
                build_review(&snapshot.proposal, &lock, patch.clone())?
            }
        };
        if review.hash()? != review_hash {
            return Err(Error::none(Reason::ReviewMismatch));
        }
        // Review must fit as a whole before a decision, even if the caller
        // already knows a hash from another or older request.
        crate::admin::bounded_json(&serde_json::to_value(&review).map_err(|_| integrity())?)
            .map_err(|_| Error::none(Reason::TooLarge))?;
        let next = if approve {
            ProposalState::Approved
        } else {
            ProposalState::Rejected
        };
        self.store
            .transition_proposal(
                id.clone(),
                ProposalState::Checked,
                next,
                ProposalUpdate {
                    decision: Some(HumanDecision::User(supplied)),
                    review_base: approve.then(|| ReviewBase {
                        update_of: review.update_of.clone(),
                        hash: review.review_base_hash.clone(),
                    }),
                    overrides: approve.then_some(patch),
                    ..Default::default()
                },
            )
            .await
            .map_err(write_error)?;
        if let Ok(mut presented) = self.presented.lock() {
            presented.retain(|(proposal, _), _| proposal != &id);
        }
        Ok(next)
    }

    pub async fn promote(&self, id: String) -> Result<Value, Error> {
        let intent = self
            .coordinator
            .admit_promotion(id.clone())
            .await
            .map_err(activation_error)?;
        Ok(json!({"schema":1,"proposal_id":id,"operation_id":intent.operation_id}))
    }
}

impl AdminMutationHandler for InstallService {
    fn call_mutation<'a>(&'a self, method: &'a str, params: &'a Value) -> AdminMutationFuture<'a> {
        Box::pin(async move {
            let text = |key: &str| {
                params
                    .get(key)
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| Error::none(Reason::InvalidState))
            };
            match method {
                "ext.install.prepare" => {
                    Ok(json!({"schema":1,"proposal_id":self.prepare(&text("path")?).await?}))
                }
                "ext.install.status" => {
                    let patch = params
                        .get("overrides")
                        .cloned()
                        .map(Overrides::from_value)
                        .transpose()
                        .map_err(|_| Error::none(Reason::InvalidOverrides))?;
                    serde_json::to_value(self.status(text("proposal_id")?, patch).await?)
                        .map_err(|_| integrity())
                }
                "ext.install.decision" => {
                    let id = text("proposal_id")?;
                    let decision = text("decision")?;
                    if !matches!(decision.as_str(), "approve" | "reject") {
                        return Err(Error::none(Reason::InvalidState));
                    }
                    let patch = Overrides::from_value(
                        params.get("overrides").cloned().ok_or_else(integrity)?,
                    )
                    .map_err(|_| Error::none(Reason::InvalidOverrides))?;
                    let state = self
                        .decision(
                            id.clone(),
                            text("nonce")?,
                            text("review_hash")?,
                            decision == "approve",
                            patch,
                        )
                        .await?;
                    Ok(json!({"schema":1,"proposal_id":id,"state":state}))
                }
                "ext.install.promote" => self.promote(text("proposal_id")?).await,
                _ => Err(Error::none(Reason::InvalidState)),
            }
        })
    }
}

fn integrity() -> Error {
    Error::none(Reason::IntegrityFailed)
}
fn hash(value: &Value) -> Result<String, Error> {
    let canonical = serde_json_canonicalizer::to_vec(value).map_err(|_| integrity())?;
    Ok(format!(
        "sha256:{}",
        Sha256::digest(canonical)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
}
fn nonce_equal(expected: &str, provided: &str) -> bool {
    let mut different = expected.len() ^ provided.len();
    for (i, byte) in expected.bytes().enumerate() {
        different |= usize::from(byte ^ provided.as_bytes().get(i).copied().unwrap_or(0));
    }
    different == 0
}
fn build_status_review(
    proposal: &Proposal,
    lock: &Lock,
    patch: Overrides,
) -> Result<Option<Review>, Error> {
    if proposal.state != ProposalState::Checked {
        // Older approvals did not capture the boot's omitted home files. Their
        // state remains observable; current config cannot supply that history.
        let detail = proposal
            .checks
            .as_deref()
            .and_then(|checks| checks.iter().find(|check| check.name == "permissions"))
            .and_then(|check| check.detail.as_deref());
        let detail = detail
            .map(|detail| crate::strict_json::parse(detail.as_bytes()).map_err(|_| integrity()))
            .transpose()?;
        if detail.as_ref().is_none_or(|detail| {
            detail.get("omitted_home_ro_files").is_none()
                || detail.get("omitted_fs_complete").is_none()
        }) {
            return Ok(None);
        }
    }
    build_review(proposal, lock, patch).map(Some)
}

fn build_review(proposal: &Proposal, lock: &Lock, patch: Overrides) -> Result<Review, Error> {
    let id = proposal.ext_id.as_deref().ok_or_else(integrity)?;
    let base_hash = lock.review_base_hash(id).map_err(|_| integrity())?;
    if proposal.review_base_hash.as_deref() != Some(base_hash.as_str())
        || proposal.update_of.as_deref() != lock.extensions.get(id).map(|ext| ext.active.as_str())
    {
        return Err(Error::none(Reason::StaleBase));
    }
    let catalog = crate::store::validate_approval(proposal, &Overrides::default())
        .map_err(|_| integrity())?;
    let manifest = Manifest::parse(
        &proposal
            .manifest
            .as_ref()
            .ok_or_else(integrity)?
            .to_string(),
    )
    .map_err(|_| integrity())?;
    overrides::resolve(
        &manifest,
        &catalog,
        &patch,
        "user",
        &Nat64Prefixes::default(),
    )
    .map_err(|_| Error::none(Reason::InvalidOverrides))?;
    let base = lock.extensions.get(id).map(|ext| json!({"active":ext.active,"enabled":ext.enabled,"version":ext.versions[&ext.active]}));
    let omitted_fs = omitted_files(proposal.checks.as_deref().ok_or_else(integrity)?, &manifest)?;
    Ok(Review {
        source: json!({"kind":"local"}),
        tainted: false,
        manifest: proposal.manifest.clone().ok_or_else(integrity)?,
        bundle_hash: proposal.hash.clone().ok_or_else(integrity)?,
        tools: catalog.tools().to_vec(),
        tools_hash: catalog.hash().into(),
        update_of: proposal.update_of.clone(),
        review_base_hash: base_hash,
        base,
        packages: proposal.packages.clone().ok_or_else(integrity)?,
        checks: proposal.checks.clone().ok_or_else(integrity)?,
        omitted_fs,
        overrides: patch,
    })
}
fn failure_reason(proposal: &Proposal) -> Option<String> {
    if proposal.state != ProposalState::Failed {
        return None;
    }
    let detail = proposal
        .checks
        .as_ref()?
        .iter()
        .find(|check| check.blocking && !check.passed)?
        .detail
        .as_deref()?;
    // Only stable code syntax leaves this boundary, never arbitrary diagnostics.
    Some(
        if detail.contains(':')
            && detail
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b':' | b'_'))
        {
            detail.to_owned()
        } else {
            "check:failed".into()
        },
    )
}
fn read_error(error: StoreError) -> Error {
    match error {
        StoreError::NotFound => Error::none(Reason::NotFound),
        StoreError::Invalid("invalid local installation state") => {
            Error::none(Reason::InvalidState)
        }
        _ => Error::none(Reason::IoError),
    }
}
fn write_error(error: StoreError) -> Error {
    match error {
        StoreError::Invalid("administrative admission expired") => Error::none(Reason::Busy),
        StoreError::NotFound => Error::none(Reason::NotFound),
        StoreError::Invalid("invalid proposal decision") => Error::none(Reason::InvalidNonce),
        StoreError::Invalid("proposal state changed") => Error::none(Reason::InvalidState),
        StoreError::Invalid("promotion:stale_base") => Error::none(Reason::StaleBase),
        StoreError::Invalid(_) => integrity(),
        _ => Error::unknown(Reason::IoError),
    }
}
fn activation_error(error: ActivationError) -> Error {
    match error {
        ActivationError::Publication => Error::committed(Reason::IoError),
        ActivationError::Busy => Error::none(Reason::Busy),
        ActivationError::StaleBase => Error::none(Reason::StaleBase),
        ActivationError::AlreadyActive
        | ActivationError::KeyConflict
        | ActivationError::Aborted => Error::none(Reason::InvalidState),
        ActivationError::Integrity => integrity(),
        ActivationError::RecoveryConflict => Error::none(Reason::RecoveryRequired),
        ActivationError::Persistence(error) => write_error(error),
        _ => Error::unknown(Reason::IoError),
    }
}
fn local_error(error: LocalError) -> Error {
    match error {
        LocalError::Admission => Error::none(Reason::Busy),
        LocalError::Recovery => Error::none(Reason::RecoveryRequired),
        LocalError::Store(error) => write_error(error),
        _ => Error::unknown(Reason::IoError),
    }
}

fn object_fields(value: &Value, fields: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field))
    })
}
fn select_patch(proposal: &Proposal, patch: Option<Overrides>) -> Result<Overrides, Error> {
    if proposal.state == ProposalState::Checked {
        return Ok(patch.unwrap_or_default());
    }
    if patch
        .as_ref()
        .is_some_and(|patch| patch != &proposal.overrides)
    {
        return Err(Error::none(Reason::InvalidState));
    }
    Ok(proposal.overrides.clone())
}
fn omitted_files(checks: &[ProposalCheck], manifest: &Manifest) -> Result<Vec<String>, Error> {
    let detail = checks
        .iter()
        .find(|check| check.name == "permissions")
        .and_then(|check| check.detail.as_deref())
        .ok_or_else(integrity)?;
    let detail = crate::strict_json::parse(detail.as_bytes()).map_err(|_| integrity())?;
    let home: Vec<String> = serde_json::from_value(
        detail
            .get("omitted_home_ro_files")
            .cloned()
            .ok_or_else(integrity)?,
    )
    .map_err(|_| integrity())?;
    let complete: Vec<String> = serde_json::from_value(
        detail
            .get("omitted_fs_complete")
            .cloned()
            .ok_or_else(integrity)?,
    )
    .map_err(|_| integrity())?;
    let mut expected = manifest
        .permissions
        .fs
        .read
        .iter()
        .chain(&manifest.permissions.fs.write)
        .filter(|p| !p.starts_with("${"))
        .cloned()
        .chain(home)
        .collect::<Vec<_>>();
    expected.sort();
    expected.dedup();
    if expected != complete {
        return Err(integrity());
    }
    Ok(complete)
}
