//! ADR-036: private exact lock snapshots and their public audit commit together.
//! Filesystem durability and the shared installer gate are the coordinator's
//! responsibility. These commands are trusted core APIs, never wire inputs.
use super::{
    Event, Proposal, ProposalState, Sensitivity, Store, StoreError, Trust, events, now_ms,
    proposals, sessions,
};
use crate::installer::lock::{Lock, LockedVersion, approval_at_ms};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fmt, time::Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromotionState {
    Prepared,
    Committed,
    Aborted,
}
impl PromotionState {
    fn name(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Committed => "committed",
            Self::Aborted => "aborted",
        }
    }
}

/// Snapshots are deliberately neither serialized nor included in Debug. They
/// contain private core metadata, including the approved environment patch.
#[derive(Clone)]
pub struct PromotionIntent {
    pub operation_id: String,
    pub proposal_id: String,
    pub ext_id: String,
    pub key: String,
    pub before_lock: Option<String>,
    pub before_hash: Option<String>,
    pub after_lock: String,
    pub after_hash: String,
    pub state: PromotionState,
    pub created_at: i64,
    pub updated_at: i64,
}
impl fmt::Debug for PromotionIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PromotionIntent")
            .field("operation_id", &self.operation_id)
            .field("proposal_id", &self.proposal_id)
            .field("ext_id", &self.ext_id)
            .field("key", &self.key)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}
pub struct NewPromotionIntent {
    pub proposal_id: String,
    pub before_lock: Option<String>,
    pub after_lock: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromotionAbortReason {
    Interrupted,
    Integrity,
    Io,
}
impl PromotionAbortReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Interrupted => "promotion:interrupted",
            Self::Integrity => "promotion:integrity",
            Self::Io => "promotion:io",
        }
    }
}

impl Store {
    /// Caller holds the common installer gate and supplied the exact protected
    /// lock read. No candidate bytes may be published before this commit.
    pub async fn prepare_promotion(
        &self,
        input: NewPromotionIntent,
    ) -> Result<PromotionIntent, StoreError> {
        self.prepare_promotion_before(input, None).await
    }

    pub(crate) async fn prepare_promotion_before(
        &self,
        input: NewPromotionIntent,
        deadline: Option<Instant>,
    ) -> Result<PromotionIntent, StoreError> {
        self.with_writer(move |writer| {
            proposals::check_admission_deadline(deadline)?;
            let operation_id = writer.next_id()?;
            let event_id = writer.next_id()?;
            let timestamp = now_ms()?;
            let tx = writer.db.transaction()?;
            if read_promotion_intents(&tx)?.is_some() { return Err(conflict()); }
            let proposal = proposals::get(&tx, &input.proposal_id)?;
            if proposal.state != ProposalState::Approved { return Err(integrity()); }
            let (ext_id, key) = validate_snapshots(&tx, &proposal, input.before_lock.as_deref(), &input.after_lock)?;
            let intent = PromotionIntent {
                operation_id, proposal_id: input.proposal_id, ext_id, key,
                before_hash: input.before_lock.as_deref().map(hash), before_lock: input.before_lock,
                after_hash: hash(&input.after_lock), after_lock: input.after_lock,
                state: PromotionState::Prepared, created_at: timestamp, updated_at: timestamp,
            };
            tx.execute("INSERT INTO promotion_intents(operation_id,proposal_id,before_lock,before_hash,after_lock,after_hash,state,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,'prepared',?7,?7)",
                params![intent.operation_id, intent.proposal_id, intent.before_lock, intent.before_hash, intent.after_lock, intent.after_hash, timestamp])?;
            audit(&tx, event_id, timestamp, &intent, None)?;
            proposals::check_admission_deadline(deadline)?;
            tx.commit()?;
            Ok(intent)
        }).await
    }

    pub async fn pending_promotion(&self) -> Result<Option<PromotionIntent>, StoreError> {
        self.read(read_promotion_intents).await
    }
    pub async fn promotion_intent(
        &self,
        operation_id: String,
    ) -> Result<PromotionIntent, StoreError> {
        self.read(move |db| load(db, &operation_id)).await
    }

    /// Only after the coordinator proved after_lock and the published bundle
    /// durable and intact. A cancelled caller cannot split this transaction.
    pub async fn commit_promotion(
        &self,
        operation_id: String,
    ) -> Result<PromotionIntent, StoreError> {
        self.finish_promotion(operation_id, None).await
    }
    /// Only while the exact before_lock remains authoritative. Uncertain
    /// rename/fsync results must be reconciled by the coordinator first.
    pub async fn abort_promotion(
        &self,
        operation_id: String,
        reason: PromotionAbortReason,
    ) -> Result<PromotionIntent, StoreError> {
        self.finish_promotion(operation_id, Some(reason)).await
    }
    async fn finish_promotion(
        &self,
        operation_id: String,
        reason: Option<PromotionAbortReason>,
    ) -> Result<PromotionIntent, StoreError> {
        self.with_writer(move |writer| {
            let event_id = writer.next_id()?;
            let timestamp = now_ms()?;
            let tx = writer.db.transaction()?;
            let mut intent = load(&tx, &operation_id)?;
            let target = if reason.is_some() { PromotionState::Aborted } else { PromotionState::Committed };
            if intent.state != PromotionState::Prepared {
                if intent.state == target { tx.commit()?; return Ok(intent); }
                return Err(conflict());
            }
            if read_promotion_intents(&tx)?.as_ref().map(|pending| pending.operation_id.as_str()) != Some(operation_id.as_str()) {
                return Err(conflict());
            }
            if target == PromotionState::Committed
                && tx.execute("UPDATE proposals SET state='promoted',updated_at=?1 WHERE id=?2 AND state='approved'", params![timestamp,intent.proposal_id])? != 1
            { return Err(conflict()); }
            if tx.execute("UPDATE promotion_intents SET state=?1,updated_at=?2 WHERE operation_id=?3 AND state='prepared'", params![target.name(),timestamp,operation_id])? != 1 { return Err(conflict()); }
            intent.state = target;
            intent.updated_at = timestamp;
            audit(&tx, event_id, timestamp, &intent, reason)?;
            tx.commit()?;
            Ok(intent)
        }).await
    }
}

fn integrity() -> StoreError {
    StoreError::Invalid("promotion:integrity")
}
fn conflict() -> StoreError {
    StoreError::Invalid("promotion:recovery_conflict")
}
fn hash(text: &str) -> String {
    let hex: String = Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("sha256:{hex}")
}

/// Streaming validation for the read-only administrative snapshot as well as
/// recovery. Validate historical rows too, retaining only one row's snapshots.
pub(crate) fn read_promotion_intents(
    db: &Connection,
) -> Result<Option<PromotionIntent>, StoreError> {
    let mut statement = db.prepare("SELECT operation_id,proposal_id,before_lock,before_hash,after_lock,after_hash,state,created_at,updated_at FROM promotion_intents ORDER BY created_at,operation_id")?;
    let mut rows = statement.query([])?;
    let mut pending = None;
    while let Some(row) = rows.next()? {
        let intent = decode(db, row)?;
        if intent.state == PromotionState::Prepared {
            if pending.is_some() {
                return Err(conflict());
            }
            pending = Some(intent);
        }
    }
    Ok(pending)
}
pub(super) fn load(db: &Connection, id: &str) -> Result<PromotionIntent, StoreError> {
    let mut statement = db.prepare("SELECT operation_id,proposal_id,before_lock,before_hash,after_lock,after_hash,state,created_at,updated_at FROM promotion_intents WHERE operation_id=?1")?;
    let mut rows = statement.query([id])?;
    decode(db, rows.next()?.ok_or(StoreError::NotFound)?)
}
fn decode(db: &Connection, row: &rusqlite::Row<'_>) -> Result<PromotionIntent, StoreError> {
    let operation_id: String = row.get(0)?;
    let proposal_id: String = row.get(1)?;
    let before_lock: Option<String> = row.get(2)?;
    let before_hash: Option<String> = row.get(3)?;
    let after_lock: String = row.get(4)?;
    let after_hash: String = row.get(5)?;
    let state = match row.get::<_, String>(6)?.as_str() {
        "prepared" => PromotionState::Prepared,
        "committed" => PromotionState::Committed,
        "aborted" => PromotionState::Aborted,
        _ => return Err(conflict()),
    };
    let created_at: i64 = row.get(7)?;
    let updated_at: i64 = row.get(8)?;
    if ulid::Ulid::from_string(&operation_id)
        .ok()
        .is_none_or(|id| id.to_string() != operation_id)
        || before_hash != before_lock.as_deref().map(hash)
        || after_hash != hash(&after_lock)
        || created_at < 0
        || updated_at < 0
        || (state == PromotionState::Prepared && created_at != updated_at)
    {
        return Err(conflict());
    }
    let proposal = proposals::get(db, &proposal_id)?;
    if !match state {
        PromotionState::Prepared => proposal.state == ProposalState::Approved,
        PromotionState::Committed => proposal.state == ProposalState::Promoted,
        PromotionState::Aborted => matches!(
            proposal.state,
            ProposalState::Approved | ProposalState::Promoted
        ),
    } {
        return Err(conflict());
    }
    let (ext_id, key) = validate_snapshots(db, &proposal, before_lock.as_deref(), &after_lock)
        .map_err(|_| conflict())?;
    let intent = PromotionIntent {
        operation_id,
        proposal_id,
        ext_id,
        key,
        before_lock,
        before_hash,
        after_lock,
        after_hash,
        state,
        created_at,
        updated_at,
    };
    validate_audit(db, &intent)?;
    Ok(intent)
}

fn validate_snapshots(
    db: &Connection,
    proposal: &Proposal,
    before: Option<&str>,
    after: &str,
) -> Result<(String, String), StoreError> {
    // Legacy approved proposals require a fresh review, even when their older
    // smoke representation cannot be replayed by the current validator.
    let review_hash = proposal
        .review_base_hash
        .as_deref()
        .ok_or(StoreError::Invalid("promotion:stale_base"))?;
    let catalog = proposals::validate_approval(proposal, &proposal.overrides)?;
    if proposal.decided_by.as_deref() != Some("user") {
        return Err(integrity());
    }
    let approved_at =
        approval_at_ms(approval_timestamp(db, &proposal.id)?).map_err(|_| integrity())?;
    let ext_id = proposal.ext_id.as_ref().ok_or_else(integrity)?;
    let version = proposal.version.as_ref().ok_or_else(integrity)?;
    let bundle_hash = proposal.hash.as_ref().ok_or_else(integrity)?;
    let key = format!("{version}-{}", &bundle_hash[7..19]);
    let before = before
        .map(|text| Lock::parse_snapshot(text.as_bytes()))
        .transpose()
        .map_err(|_| integrity())?
        .unwrap_or_default();
    let after = Lock::parse_snapshot(after.as_bytes()).map_err(|_| integrity())?;
    if before.review_base_hash(ext_id).map_err(|_| integrity())? != review_hash
        || before
            .extensions
            .get(ext_id)
            .map(|extension| extension.active.as_str())
            != proposal.update_of.as_deref()
    {
        return Err(StoreError::Invalid("promotion:stale_base"));
    }
    let existing = before.extensions.get(ext_id);
    if existing.is_some_and(|extension| extension.active == key) {
        return Err(StoreError::Invalid("promotion:already_active"));
    }
    let candidate = after
        .extensions
        .get(ext_id)
        .and_then(|extension| extension.versions.get(&key))
        .ok_or_else(integrity)?;
    let metadata = |candidate: &LockedVersion| -> Result<bool, StoreError> {
        Ok(candidate.version == *version
            && candidate.hash == *bundle_hash
            && candidate.path == format!("store/{ext_id}/{key}")
            && candidate.overrides == proposal.overrides
            && candidate.privileges.is_empty()
            && candidate.audit.is_none()
            && candidate.tools == catalog.tools()
            && candidate.tools_hash == catalog.hash()
            && serde_json::to_value(&candidate.packages)?
                == serde_json::to_value(proposal.packages.as_ref().ok_or_else(integrity)?)?)
    };
    if !metadata(candidate)? {
        return Err(StoreError::Invalid(
            if existing.is_some_and(|extension| extension.versions.contains_key(&key)) {
                "promotion:key_conflict"
            } else {
                "promotion:integrity"
            },
        ));
    }
    if let Some(previous) = existing.and_then(|extension| extension.versions.get(&key)) {
        if serde_json::to_value(candidate)? != serde_json::to_value(previous)? {
            return Err(StoreError::Invalid("promotion:key_conflict"));
        }
    } else if candidate.source != proposal.source
        || candidate.approved.by != "user"
        || proposal.decided_by.as_deref() != Some("user")
        || candidate.approved.approval_id.is_some()
        || candidate.approved.at != approved_at
    {
        return Err(integrity());
    }
    // Rebuild the only allowed change over the entire previous snapshot; this
    // preserves disabled state, inactive versions, other extensions and runtimes.
    let mut expected = before;
    match expected.extensions.get_mut(ext_id) {
        Some(extension) => {
            extension.active = key.clone();
            extension.versions.insert(key.clone(), candidate.clone());
        }
        None => {
            expected.extensions.insert(
                ext_id.clone(),
                crate::installer::lock::LockedExtension {
                    enabled: true,
                    active: key.clone(),
                    versions: [(key.clone(), candidate.clone())].into(),
                },
            );
        }
    }
    if serde_json::to_value(&expected)? != serde_json::to_value(&after)? {
        return Err(integrity());
    }
    Ok((ext_id.clone(), key))
}
fn approval_timestamp(db: &Connection, proposal_id: &str) -> Result<i64, StoreError> {
    let mut statement = db.prepare("SELECT created_at FROM events WHERE kind='ext.approved' AND actor='user' AND session_id='sys' AND json_extract(payload,'$.proposal_id')=?1")?;
    let mut rows = statement.query([proposal_id])?;
    let timestamp = rows.next()?.ok_or_else(integrity)?.get(0)?;
    if rows.next()?.is_some() {
        return Err(integrity());
    }
    Ok(timestamp)
}
fn payload(
    intent: &PromotionIntent,
    state: PromotionState,
    reason: Option<PromotionAbortReason>,
) -> Value {
    let mut payload = json!({"operation_id":intent.operation_id,"proposal_id":intent.proposal_id,"ext_id":intent.ext_id,"key":intent.key});
    match state {
        PromotionState::Prepared => {
            payload["before_hash"] = json!(intent.before_hash);
            payload["after_hash"] = json!(intent.after_hash);
        }
        PromotionState::Aborted => {
            if let Some(reason) = reason {
                payload["reason"] = reason.as_str().into();
            }
        }
        PromotionState::Committed => {}
    }
    payload
}
fn kind(state: PromotionState) -> &'static str {
    match state {
        PromotionState::Prepared => "ext.promotion_prepared",
        PromotionState::Committed => "ext.promoted",
        PromotionState::Aborted => "ext.promotion_aborted",
    }
}
fn audit(
    tx: &rusqlite::Transaction<'_>,
    id: String,
    created_at: i64,
    intent: &PromotionIntent,
    reason: Option<PromotionAbortReason>,
) -> Result<(), StoreError> {
    let session = sessions::get(tx, "sys")?;
    let event = Event {
        id,
        parent_id: session.head_id,
        session_id: "sys".into(),
        kind: kind(intent.state).into(),
        actor: "core".into(),
        payload: payload(intent, intent.state, reason),
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
fn validate_audit(db: &Connection, intent: &PromotionIntent) -> Result<(), StoreError> {
    let mut statement = db.prepare("SELECT kind,payload,created_at,actor,session_id,source,trust,sensitivity FROM events WHERE json_extract(payload,'$.operation_id')=?1 AND kind IN ('ext.promotion_prepared','ext.promoted','ext.promotion_aborted')")?;
    let mut rows = statement.query([&intent.operation_id])?;
    let mut prepared = false;
    let mut terminal = false;
    while let Some(row) = rows.next()? {
        let event_kind: String = row.get(0)?;
        let text: String = row.get(1)?;
        let value = crate::strict_json::parse(text.as_bytes()).map_err(|_| conflict())?;
        let timestamp: i64 = row.get(2)?;
        if row.get::<_, String>(3)? != "core"
            || row.get::<_, String>(4)? != "sys"
            || row.get::<_, String>(5)? != "core"
            || row.get::<_, String>(6)? != "trusted"
            || row.get::<_, String>(7)? != "public"
        {
            return Err(conflict());
        }
        if event_kind == kind(PromotionState::Prepared) {
            if prepared
                || value != payload(intent, PromotionState::Prepared, None)
                || timestamp != intent.created_at
            {
                return Err(conflict());
            }
            prepared = true;
        } else {
            let reason = match value.get("reason").and_then(Value::as_str) {
                Some("promotion:interrupted") => Some(PromotionAbortReason::Interrupted),
                Some("promotion:integrity") => Some(PromotionAbortReason::Integrity),
                Some("promotion:io") => Some(PromotionAbortReason::Io),
                None => None,
                _ => return Err(conflict()),
            };
            if terminal
                || intent.state == PromotionState::Prepared
                || event_kind != kind(intent.state)
                || (intent.state == PromotionState::Aborted) != reason.is_some()
                || value != payload(intent, intent.state, reason)
                || timestamp != intent.updated_at
            {
                return Err(conflict());
            }
            terminal = true;
        }
    }
    if !prepared || terminal != (intent.state != PromotionState::Prepared) {
        return Err(conflict());
    }
    Ok(())
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use crate::{
        gateway::PinnedCatalog,
        installer::lock::{Approval, LockedExtension},
        store::{
            HumanDecision, NewProposal, ProposalCheck, ProposalIdentity, ProposalUpdate, ReviewBase,
        },
    };
    use std::{future::Future, task::Poll, time::Duration};

    async fn candidate(store: &Store) -> NewPromotionIntent {
        let lock = Lock::default();
        let review = || ReviewBase {
            update_of: None,
            hash: lock.review_base_hash("sample").unwrap(),
        };
        let proposal = store
            .begin_attempt(NewProposal {
                source: json!({"kind":"local"}),
                tainted: false,
            })
            .await
            .unwrap();
        store
            .transition_proposal(
                proposal.id.clone(),
                ProposalState::Received,
                ProposalState::Checking,
                ProposalUpdate {
                    identity: Some(ProposalIdentity {
                        ext_id: "sample".into(),
                        version: "0.1.0".into(),
                        manifest: json!({"schema":1,"id":"sample","version":"0.1.0","description":"admission fixture","scope":"session","runtime":{"kind":"node","entry":"index.mjs"},"mcp":false,"kernel":["kv"]}),
                        update_of: None,
                    }),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let catalog = PinnedCatalog::new(vec![]).unwrap();
        let checks = [
            "manifest",
            "dependencies",
            "bundle",
            "declarations",
            "smoke",
        ]
        .into_iter()
        .map(|name| ProposalCheck {
            name: name.into(),
            passed: true,
            blocking: true,
            detail: (name == "smoke")
                .then(|| json!({"tools":catalog.tools(),"tools_hash":catalog.hash()}).to_string()),
        })
        .collect();
        store
            .transition_proposal(
                proposal.id.clone(),
                ProposalState::Checking,
                ProposalState::Checked,
                ProposalUpdate {
                    hash: Some(format!("sha256:{}", "a".repeat(64))),
                    checks: Some(checks),
                    packages: Some(vec![]),
                    review_base: Some(review()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let nonce = store.proposal_nonce(proposal.id.clone()).await.unwrap();
        let proposal = store
            .transition_proposal(
                proposal.id,
                ProposalState::Checked,
                ProposalState::Approved,
                ProposalUpdate {
                    decision: Some(HumanDecision::User(nonce)),
                    review_base: Some(review()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let key = "0.1.0-aaaaaaaaaaaa";
        let candidate = LockedVersion {
            version: "0.1.0".into(),
            hash: proposal.hash.clone().unwrap(),
            path: format!("store/sample/{key}"),
            source: proposal.source.clone(),
            approved: Approval {
                by: "user".into(),
                at: approval_at_ms(proposal.updated_at).unwrap(),
                approval_id: None,
            },
            overrides: proposal.overrides,
            privileges: vec![],
            tools: vec![],
            tools_hash: catalog.hash().into(),
            packages: vec![],
            audit: None,
        };
        let mut after = lock.clone();
        after.extensions.insert(
            "sample".into(),
            LockedExtension {
                enabled: true,
                active: key.into(),
                versions: [(key.into(), candidate)].into(),
            },
        );
        NewPromotionIntent {
            proposal_id: proposal.id,
            before_lock: Some(lock.encode_snapshot().unwrap()),
            after_lock: after.encode_snapshot().unwrap(),
        }
    }

    #[tokio::test]
    async fn queued_promotion_cannot_commit_after_its_admission_deadline() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        crate::home::prepare(&home).unwrap();
        let store = Store::open(&home).await.unwrap();
        let input = candidate(&store).await;
        let retry = NewPromotionIntent {
            proposal_id: input.proposal_id.clone(),
            before_lock: input.before_lock.clone(),
            after_lock: input.after_lock.clone(),
        };
        let (entered, waiting) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let barrier = store.with_writer(move |_| {
            let _ = entered.send(());
            blocked.recv_timeout(Duration::from_secs(5)).unwrap();
            Ok(())
        });
        tokio::pin!(barrier);
        std::future::poll_fn(|cx| {
            assert!(barrier.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        waiting.await.unwrap();
        let deadline = Instant::now() + Duration::from_millis(100);
        let admission = store.prepare_promotion_before(input, Some(deadline));
        tokio::pin!(admission);
        std::future::poll_fn(|cx| {
            assert!(admission.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert!(Instant::now() < deadline, "job queued before its deadline");
        tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
        release.send(()).unwrap();
        barrier.await.unwrap();
        assert!(matches!(
            admission.await,
            Err(StoreError::Invalid("administrative admission expired"))
        ));
        let (intents, events) = store
            .read(|db| {
                Ok((
                    db.query_row("SELECT count(*) FROM promotion_intents", [], |row| {
                        row.get::<_, i64>(0)
                    })?,
                    db.query_row(
                        "SELECT count(*) FROM events WHERE kind='ext.promotion_prepared'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!((intents, events), (0, 0));
        assert_eq!(
            store
                .proposal(retry.proposal_id.clone())
                .await
                .unwrap()
                .state,
            ProposalState::Approved
        );
        store.prepare_promotion(retry).await.unwrap();
    }
}
