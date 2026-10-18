//! Trusted installer API only; never deserialize these commands from extensions.
//! Every state change and its sys audit event commit in one writer transaction.
use super::{Event, Sensitivity, Store, StoreError, Trust, events, now_ms};
use crate::{gateway::PinnedCatalog, installer::overrides::Overrides};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProposalState {
    Received,
    Checking,
    Checked,
    Approved,
    Rejected,
    Promoted,
    Failed,
}
impl ProposalState {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::Checking => "checking",
            Self::Checked => "checked",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Promoted => "promoted",
            Self::Failed => "failed",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalCheck {
    pub name: String,
    pub passed: bool,
    pub blocking: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedPackage {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

pub struct NewProposal {
    pub source: Value,
    pub tainted: bool,
}
/// Trusted installer input, supplied only after complete manifest validation.
/// Binding it is part of the received -> checking transaction, never receipt.
pub struct ProposalIdentity {
    pub ext_id: String,
    pub version: String,
    pub manifest: Value,
    pub update_of: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct Proposal {
    pub id: String,
    pub ext_id: Option<String>,
    pub version: Option<String>,
    pub hash: Option<String>,
    pub source: Value,
    pub state: ProposalState,
    pub update_of: Option<String>,
    pub review_base_hash: Option<String>,
    pub overrides: Overrides,
    pub tainted: bool,
    pub manifest: Option<Value>,
    pub checks: Option<Vec<ProposalCheck>>,
    pub packages: Option<Vec<ResolvedPackage>>,
    pub audit_blob: Option<String>,
    pub decided_by: Option<String>,
    pub note: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}
/// Bearer nonce for a trusted user decision. Never included in Proposal JSON,
/// Debug output, audit payloads, or errors. Future trusted frontends may expose
/// it only through their separate authenticated decision channel.
pub struct ProposalNonce(String);
impl ProposalNonce {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
pub enum HumanDecision {
    User(ProposalNonce),
}
/// Captured by the installer in the same protected lock read. Checking fixes
/// both fields together; approval compares them without refreshing the review.
#[derive(Clone, Debug)]
pub struct ReviewBase {
    pub update_of: Option<String>,
    pub hash: String,
}
#[derive(Default)]
pub struct ProposalUpdate {
    pub identity: Option<ProposalIdentity>,
    pub failure_reason: Option<String>,
    pub checks: Option<Vec<ProposalCheck>>,
    pub hash: Option<String>,
    pub packages: Option<Vec<ResolvedPackage>>,
    pub decision: Option<HumanDecision>,
    pub review_base: Option<ReviewBase>,
    pub overrides: Option<Overrides>,
}

impl Store {
    pub async fn begin_attempt(&self, input: NewProposal) -> Result<Proposal, StoreError> {
        if input.source.get("kind").and_then(Value::as_str) != Some("local")
            || !input.source.is_object()
        {
            return Err(StoreError::Invalid("invalid local proposal"));
        }
        let nonce = nonce()?;
        self.with_writer(move |writer| {
            let id = writer.next_id()?;
            let event_id = writer.next_id()?;
            let timestamp = now_ms()?;
            let tx = writer.db.transaction()?;
            tx.execute(
                "INSERT INTO proposals(id,source,state,tainted,nonce,created_at,updated_at) VALUES (?1,?2,'received',?3,?4,?5,?5)",
                params![id, serde_json::to_string(&input.source)?, input.tainted, nonce, timestamp],
            )?;
            audit(&tx, event_id, timestamp, Audit {
                kind: "ext.proposed", actor: "core", proposal_id: &id,
                ext_id: None, version: None, from: None,
                state: ProposalState::Received, reason: None,
            })?;
            let proposal = get(&tx, &id)?;
            tx.commit()?;
            Ok(proposal)
        }).await
    }
    pub async fn proposal(&self, id: String) -> Result<Proposal, StoreError> {
        self.read(move |db| get(db, &id)).await
    }
    /// Trusted local caller only. This capability is never a Kernel Protocol method.
    pub async fn proposal_nonce(&self, id: String) -> Result<ProposalNonce, StoreError> {
        self.read(move |db| {
            db.query_row("SELECT nonce FROM proposals WHERE id=?1", [id], |row| {
                row.get::<_, String>(0)
            })
            .optional()?
            .map(ProposalNonce)
            .ok_or(StoreError::NotFound)
        })
        .await
    }
    pub async fn transition_proposal(
        &self,
        id: String,
        expected: ProposalState,
        next: ProposalState,
        mut update: ProposalUpdate,
    ) -> Result<Proposal, StoreError> {
        let valid = matches!(
            (expected, next),
            (
                ProposalState::Received,
                ProposalState::Checking | ProposalState::Failed
            ) | (
                ProposalState::Checking,
                ProposalState::Checked | ProposalState::Failed
            ) | (
                ProposalState::Checked,
                ProposalState::Approved | ProposalState::Rejected
            )
        );
        if !valid {
            return Err(StoreError::Invalid("invalid proposal transition"));
        }
        let binds_review = expected == ProposalState::Checking && next == ProposalState::Checked;
        let approves = expected == ProposalState::Checked && next == ProposalState::Approved;
        if update.review_base.as_ref().is_some_and(|base| {
            !valid_hash(&base.hash)
                || base
                    .update_of
                    .as_ref()
                    .is_some_and(|key| key.is_empty() || key.chars().any(char::is_control))
        }) || (update.review_base.is_some() && !binds_review && !approves)
            || (update.overrides.is_some() && !approves)
        {
            return Err(StoreError::Invalid("invalid proposal review"));
        }
        if (binds_review || approves) && update.review_base.is_none() {
            return Err(StoreError::Invalid("promotion:stale_base"));
        }
        if update.hash.as_ref().is_some_and(|hash| !valid_hash(hash)) {
            return Err(StoreError::Invalid("invalid proposal hash"));
        }
        if let Some(identity) = &mut update.identity {
            if expected != ProposalState::Received || next != ProposalState::Checking {
                return Err(StoreError::Invalid("invalid proposal identity"));
            }
            validate_identity(identity)?;
        }
        if update.failure_reason.as_ref().is_some_and(|reason| {
            next != ProposalState::Failed || failure_check_name(reason).is_none()
        }) {
            return Err(StoreError::Invalid("invalid proposal failure reason"));
        }
        let decision = matches!(next, ProposalState::Approved | ProposalState::Rejected);
        if decision != update.decision.is_some() {
            return Err(StoreError::Invalid("invalid proposal decision"));
        }
        // Receipt may retain completed checks while binding or refusing identity.
        // Successful bundle hashes and resolved packages still require checking.
        if expected != ProposalState::Checking
            && (update.hash.is_some()
                || update.packages.is_some()
                || (update.checks.is_some() && expected != ProposalState::Received))
        {
            return Err(StoreError::Invalid("invalid proposal results"));
        }
        if update.checks.as_ref().is_some_and(|checks| {
            checks
                .iter()
                .any(|check| check.name.is_empty() || check.name.chars().any(char::is_control))
        }) || update.packages.as_ref().is_some_and(|packages| {
            packages
                .iter()
                .any(|p| p.ecosystem.is_empty() || p.name.is_empty() || p.version.is_empty())
        }) {
            return Err(StoreError::Invalid("invalid proposal results"));
        }
        let replacement = if decision { Some(nonce()?) } else { None };
        self.with_writer(move |writer| {
            let event_id = writer.next_id()?;
            let timestamp = now_ms()?;
            let tx = writer.db.transaction()?;
            let current = get(&tx, &id)?;
            if current.state != expected {
                return Err(StoreError::Invalid("proposal state changed"));
            }
            if approves {
                let base = update.review_base.as_ref().ok_or(StoreError::Invalid("promotion:stale_base"))?;
                if current.review_base_hash.as_deref() != Some(base.hash.as_str()) || current.update_of != base.update_of {
                    return Err(StoreError::Invalid("promotion:stale_base"));
                }
                let patch = update.overrides.as_ref().cloned().unwrap_or_default();
                validate_approval(&current, &patch)?;
            }
            if let Some(HumanDecision::User(confirmed)) = &update.decision {
                let existing: String = tx.query_row(
                    "SELECT nonce FROM proposals WHERE id=?1", [&id], |row| row.get(0),
                )?;
                if !constant_time(&existing, &confirmed.0) {
                    return Err(StoreError::Invalid("invalid proposal decision"));
                }
            }
            let (ext_id, version, manifest, mut update_of) = match update.identity {
                Some(identity) => {
                    if current.ext_id.is_some() || current.version.is_some() {
                        return Err(StoreError::Invalid("proposal identity already bound"));
                    }
                    (Some(identity.ext_id), Some(identity.version), Some(identity.manifest), identity.update_of)
                }
                None => (current.ext_id, current.version, current.manifest, current.update_of),
            };
            let review_base_hash = if binds_review {
                if current.review_base_hash.is_some() {
                    return Err(StoreError::Invalid("proposal review already bound"));
                }
                let base = update.review_base.ok_or(StoreError::Invalid("promotion:stale_base"))?;
                update_of = base.update_of;
                Some(base.hash)
            } else {
                current.review_base_hash
            };
            let overrides = if approves { update.overrides.unwrap_or_default() } else { current.overrides };
            if next != ProposalState::Failed && (ext_id.is_none() || version.is_none()) {
                return Err(StoreError::Invalid("proposal identity required"));
            }
            if next == ProposalState::Failed
                && let (Some(existing), Some(replacement)) = (&current.checks, &update.checks)
                && !replacement.starts_with(existing)
            {
                return Err(StoreError::Invalid("proposal failure must preserve checks"));
            }
            let checks = update.checks.or(current.checks);
            let hash = update.hash.or(current.hash);
            let packages = update.packages.or(current.packages);
            if next == ProposalState::Checked && (hash.is_none() || checks.as_ref().is_none_or(|checks| {
                checks.is_empty() || checks.iter().any(|check| check.blocking && !check.passed)
            })) {
                return Err(StoreError::Invalid("proposal checks incomplete"));
            }
            let reason = if next == ProposalState::Failed {
                let reason = update.failure_reason.as_deref().unwrap_or("check:failed");
                if checks.as_ref().is_none_or(|checks| !checks.iter().any(|check| {
                    check.blocking && !check.passed
                })) || (ext_id.is_none() && !receipt_failure_matches(checks.as_deref(), reason)) {
                    return Err(StoreError::Invalid("proposal failure check required"));
                }
                Some(reason)
            } else {
                None
            };
            let changed = tx.execute(
                "UPDATE proposals SET state=?1,checks=?2,hash=?3,packages=?4,decided_by=CASE WHEN ?5 THEN 'user' ELSE decided_by END,nonce=COALESCE(?6,nonce),updated_at=?7,ext_id=?10,version=?11,manifest=?12,update_of=?13,review_base_hash=?14,overrides=?15 WHERE id=?8 AND state=?9",
                params![next.name(), checks.as_ref().map(serde_json::to_string).transpose()?, hash,
                    packages.as_ref().map(serde_json::to_string).transpose()?, decision, replacement,
                    timestamp, id, expected.name(), ext_id, version,
                    manifest.as_ref().map(serde_json::to_string).transpose()?, update_of,
                    review_base_hash, serde_json::to_string(&overrides)?],
            )?;
            if changed != 1 {
                return Err(StoreError::Invalid("proposal state changed"));
            }
            let kind = match next {
                ProposalState::Checking => "ext.checking", ProposalState::Checked => "ext.checked",
                ProposalState::Approved => "ext.approved", ProposalState::Rejected => "ext.rejected",
                ProposalState::Failed => "ext.failed",
                _ => return Err(StoreError::Invalid("invalid proposal transition")),
            };
            audit(&tx, event_id, timestamp, Audit {
                kind, actor: if decision { "user" } else { "core" }, proposal_id: &id,
                ext_id: ext_id.as_deref(), version: version.as_deref(),
                from: Some(expected), state: next, reason,
            })?;
            let proposal = get(&tx, &id)?;
            tx.commit()?;
            Ok(proposal)
        }).await
    }

    /// Run before installer admission while its exclusive recovery lease is held.
    /// All interrupted records reconcile atomically; returning old failures lets
    /// quarantine cleanup retry without creating another failure event.
    pub async fn recover_interrupted_proposals(&self) -> Result<Vec<Proposal>, StoreError> {
        self.with_writer(|writer| {
            let pending = ids_with_states(&writer.db, "'received','checking'")?;
            // Allocate IDs before borrowing the writer connection for its transaction.
            let events = pending.iter().map(|_| writer.next_id()).collect::<Result<Vec<_>, _>>()?;
            let timestamp = now_ms()?;
            let tx = writer.db.transaction()?;
            for (id, event_id) in pending.iter().zip(events) {
                let current = get(&tx, id)?;
                if !matches!(current.state, ProposalState::Received | ProposalState::Checking) {
                    return Err(StoreError::Invalid("proposal state changed"));
                }
                let mut checks = current.checks.unwrap_or_default();
                checks.push(ProposalCheck {
                    name: "recovery".into(), passed: false, blocking: true,
                    detail: Some("recovery:interrupted".into()),
                });
                let changed = tx.execute(
                    "UPDATE proposals SET state='failed',checks=?1,updated_at=?2 WHERE id=?3 AND state=?4",
                    params![serde_json::to_string(&checks)?, timestamp, id, current.state.name()],
                )?;
                if changed != 1 {
                    return Err(StoreError::Invalid("proposal state changed"));
                }
                audit(&tx, event_id, timestamp, Audit {
                    kind: "ext.failed", actor: "core", proposal_id: id,
                    ext_id: current.ext_id.as_deref(), version: current.version.as_deref(),
                    from: Some(current.state), state: ProposalState::Failed,
                    reason: Some("recovery:interrupted"),
                })?;
            }
            let failed = ids_with_states(&tx, "'failed'")?.into_iter()
                .map(|id| get(&tx, &id)).collect::<Result<Vec<_>, _>>()?;
            tx.commit()?;
            Ok(failed)
        }).await
    }
}
fn ids_with_states(db: &Connection, states: &str) -> Result<Vec<String>, StoreError> {
    // Only the fixed state lists above reach this helper; no caller-supplied SQL.
    let mut statement = db.prepare(&format!(
        "SELECT id FROM proposals WHERE state IN ({states}) ORDER BY created_at,id"
    ))?;
    Ok(statement
        .query_map([], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?)
}
fn validate_identity(identity: &mut ProposalIdentity) -> Result<(), StoreError> {
    // Structural and generic semantic validation is repeated at the writer API.
    // Configured NAT64 prefixes and provider-secret names are checked earlier by
    // the installer, which owns that context; default validation cannot add grants.
    let manifest = crate::installer::manifest::Manifest::parse(&identity.manifest.to_string())
        .map_err(|_| StoreError::Invalid("invalid proposal identity"))?;
    if manifest.id != identity.ext_id || manifest.version != identity.version {
        return Err(StoreError::Invalid("invalid proposal identity"));
    }
    identity.manifest = serde_json::to_value(manifest)?;
    Ok(())
}
/// Replay the stored approval inputs, never a new MCP discovery or a caller's
/// replacement catalog. Configured NAT64 context is also checked by the
/// installer; this generic subset validation cannot introduce a new grant.
pub(super) fn validate_approval(
    proposal: &Proposal,
    patch: &Overrides,
) -> Result<PinnedCatalog, StoreError> {
    let invalid = || StoreError::Invalid("promotion:integrity");
    if proposal.source.get("kind").and_then(Value::as_str) != Some("local")
        || proposal.packages.is_none()
        || proposal.audit_blob.is_some()
        || proposal
            .hash
            .as_deref()
            .is_none_or(|hash| !valid_hash(hash))
    {
        return Err(invalid());
    }
    let checks = proposal.checks.as_deref().ok_or_else(invalid)?;
    if checks.iter().any(|check| check.blocking && !check.passed)
        || [
            "manifest",
            "dependencies",
            "bundle",
            "declarations",
            "smoke",
        ]
        .iter()
        .any(|name| {
            checks
                .iter()
                .filter(|check| check.name == *name && check.passed && check.blocking)
                .count()
                != 1
        })
    {
        return Err(invalid());
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Smoke {
        tools: Vec<Value>,
        tools_hash: String,
    }
    let detail = checks
        .iter()
        .find(|check| check.name == "smoke")
        .and_then(|check| check.detail.as_deref())
        .ok_or_else(invalid)?;
    let value = crate::strict_json::parse(detail.as_bytes()).map_err(|_| invalid())?;
    let smoke: Smoke = serde_json::from_value(value).map_err(|_| invalid())?;
    let catalog = PinnedCatalog::new(smoke.tools).map_err(|_| invalid())?;
    if catalog.hash() != smoke.tools_hash {
        return Err(invalid());
    }
    let manifest = crate::installer::manifest::Manifest::parse(
        &proposal.manifest.as_ref().ok_or_else(invalid)?.to_string(),
    )
    .map_err(|_| invalid())?;
    if proposal.ext_id.as_deref() != Some(manifest.id.as_str())
        || proposal.version.as_deref() != Some(manifest.version.as_str())
        || (manifest.scope == crate::installer::manifest::Scope::Global
            && manifest.runtime.kind != crate::installer::manifest::RuntimeKind::None)
    {
        return Err(invalid());
    }
    crate::installer::overrides::resolve(
        &manifest,
        &catalog,
        patch,
        "user",
        &crate::proxy::nat64::Nat64Prefixes::default(),
    )
    .map_err(|_| invalid())?;
    Ok(catalog)
}
fn failure_check_name(reason: &str) -> Option<&'static str> {
    match reason {
        "limit:entries"
        | "limit:bytes"
        | "limit:file_size"
        | "limit:depth"
        | "limit:path_length"
        | "limit:time"
        | "receipt:symlink"
        | "receipt:special_file"
        | "receipt:invalid_path"
        | "receipt:source_changed"
        | "receipt:io" => Some("receipt"),
        "manifest:missing" | "manifest:invalid_yaml" | "manifest:invalid" | "phase:global" => {
            Some("manifest")
        }
        "recovery:interrupted" => Some("recovery"),
        "check:failed" => Some("check"),
        _ => None,
    }
}
fn receipt_failure_matches(checks: Option<&[ProposalCheck]>, reason: &str) -> bool {
    reason != "check:failed"
        && checks.is_some_and(|checks| {
            checks.iter().any(|check| {
                Some(check.name.as_str()) == failure_check_name(reason)
                    && !check.passed
                    && check.blocking
                    && check.detail.as_deref() == Some(reason)
            })
        })
}
pub(super) fn valid_hash(hash: &str) -> bool {
    hash.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}
fn nonce() -> Result<String, StoreError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| StoreError::Invalid("randomness unavailable"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn constant_time(expected: &str, provided: &str) -> bool {
    let mut diff = expected.len() ^ provided.len();
    for (i, b) in expected.bytes().enumerate() {
        diff |= usize::from(b ^ provided.as_bytes().get(i).copied().unwrap_or(0));
    }
    diff == 0
}
struct Audit<'a> {
    kind: &'a str,
    actor: &'a str,
    proposal_id: &'a str,
    ext_id: Option<&'a str>,
    version: Option<&'a str>,
    from: Option<ProposalState>,
    state: ProposalState,
    reason: Option<&'a str>,
}
fn audit(
    tx: &rusqlite::Transaction<'_>,
    id: String,
    created_at: i64,
    change: Audit<'_>,
) -> Result<(), StoreError> {
    let Audit {
        kind,
        actor,
        proposal_id,
        ext_id,
        version,
        from,
        state,
        reason,
    } = change;
    let session = super::sessions::get(tx, "sys")?;
    let mut payload = json!({"proposal_id":proposal_id,"ext_id":ext_id,"version":version,"from":from,"state":state});
    if let Some(reason) = reason {
        payload["reason"] = reason.into();
    }
    let event = Event {
        id,
        parent_id: session.head_id,
        session_id: "sys".into(),
        kind: kind.into(),
        actor: actor.into(),
        payload,
        blob_refs: vec![],
        trust: Trust::Trusted,
        sensitivity: Sensitivity::Public,
        source: "core".into(),
        flags: session.flags,
        text: None,
        created_at,
    };
    events::insert(tx, &event)?;
    tx.execute(
        "UPDATE sessions SET head_id=?1,updated_at=?2 WHERE id='sys'",
        params![event.id, created_at],
    )?;
    Ok(())
}
pub(super) fn get(db: &Connection, id: &str) -> Result<Proposal, StoreError> {
    db.query_row("SELECT id,ext_id,version,hash,source,state,update_of,tainted,manifest,checks,packages,audit_blob,decided_by,note,created_at,updated_at,review_base_hash,overrides FROM proposals WHERE id=?1",[id],|r|{
        let source:String=r.get(4)?;let state:String=r.get(5)?;
        Ok(Proposal{id:r.get(0)?,ext_id:r.get(1)?,version:r.get(2)?,hash:r.get(3)?,source:decode(&source,4)?,state:decode(&format!("\"{state}\""),5)?,update_of:r.get(6)?,tainted:r.get(7)?,manifest:decode_optional(r.get(8)?,8)?,checks:decode_optional(r.get(9)?,9)?,packages:decode_optional(r.get(10)?,10)?,audit_blob:r.get(11)?,decided_by:r.get(12)?,note:r.get(13)?,created_at:r.get(14)?,updated_at:r.get(15)?,review_base_hash:r.get(16)?,overrides:decode(&r.get::<_,String>(17)?,17)?})
    }).optional()?.ok_or(StoreError::NotFound)
}
fn decode<T: serde::de::DeserializeOwned>(value: &str, index: usize) -> rusqlite::Result<T> {
    serde_json::from_str(value).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Text, Box::new(e))
    })
}
fn decode_optional<T: serde::de::DeserializeOwned>(
    value: Option<String>,
    index: usize,
) -> rusqlite::Result<Option<T>> {
    value.map(|value| decode(&value, index)).transpose()
}
