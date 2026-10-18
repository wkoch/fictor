//! Trusted installer API only; never deserialize these commands from extensions.
//! Every state change and its sys audit event commit in one writer transaction.
use super::{Event, Sensitivity, Store, StoreError, Trust, events, now_ms};
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
    fn name(self) -> &'static str {
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
    pub ext_id: String,
    pub version: String,
    pub source: Value,
    pub manifest: Value,
    pub tainted: bool,
    pub update_of: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct Proposal {
    pub id: String,
    pub ext_id: String,
    pub version: String,
    pub hash: Option<String>,
    pub source: Value,
    pub state: ProposalState,
    pub update_of: Option<String>,
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
#[derive(Default)]
pub struct ProposalUpdate {
    pub checks: Option<Vec<ProposalCheck>>,
    pub hash: Option<String>,
    pub packages: Option<Vec<ResolvedPackage>>,
    pub decision: Option<HumanDecision>,
}

impl Store {
    pub async fn receive_proposal(&self, input: NewProposal) -> Result<Proposal, StoreError> {
        if input.tainted
            || input.source.get("kind").and_then(Value::as_str) != Some("local")
            || !input.source.is_object()
            || !valid_ext_id(&input.ext_id)
            || input.version.is_empty()
            || input.version.chars().any(char::is_control)
            || input.manifest.get("id").and_then(Value::as_str) != Some(input.ext_id.as_str())
            || input.manifest.get("version").and_then(Value::as_str) != Some(input.version.as_str())
        {
            return Err(StoreError::Invalid("invalid local proposal"));
        }
        let nonce = nonce()?;
        self.with_writer(move|writer|{
            let id=writer.next_id()?;let event_id=writer.next_id()?;let timestamp=now_ms()?;
            let tx=writer.db.transaction()?;
            tx.execute("INSERT INTO proposals(id,ext_id,version,source,state,update_of,tainted,manifest,nonce,created_at,updated_at) VALUES (?1,?2,?3,?4,'received',?5,0,?6,?7,?8,?8)",params![id,input.ext_id,input.version,serde_json::to_string(&input.source)?,input.update_of,serde_json::to_string(&input.manifest)?,nonce,timestamp])?;
            audit(&tx,event_id,timestamp,Audit {kind:"ext.proposed",actor:"core",proposal_id:&id,ext_id:&input.ext_id,from:None,state:ProposalState::Received})?;
            let proposal=get(&tx,&id)?;tx.commit()?;Ok(proposal)
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
        update: ProposalUpdate,
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
        if update.hash.as_ref().is_some_and(|hash| !valid_hash(hash)) {
            return Err(StoreError::Invalid("invalid proposal hash"));
        }
        let decision = matches!(next, ProposalState::Approved | ProposalState::Rejected);
        if decision != update.decision.is_some() {
            return Err(StoreError::Invalid("invalid proposal decision"));
        }
        // Only the checking stage may attach deterministic check/hash/package results.
        if expected != ProposalState::Checking
            && (update.checks.is_some() || update.hash.is_some() || update.packages.is_some())
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
        self.with_writer(move|writer|{
            let event_id=writer.next_id()?;let timestamp=now_ms()?;
            let tx=writer.db.transaction()?;
            let current=get(&tx,&id)?;
            if current.state!=expected {return Err(StoreError::Invalid("proposal state changed"));}
            if let Some(HumanDecision::User(confirmed))=&update.decision {
                let existing:String=tx.query_row("SELECT nonce FROM proposals WHERE id=?1",[&id],|row|row.get(0))?;
                if !constant_time(&existing,&confirmed.0){return Err(StoreError::Invalid("invalid proposal decision"));}
            }
            let checks=update.checks.or(current.checks);
            let hash=update.hash.or(current.hash);
            let packages=update.packages.or(current.packages);
            if next==ProposalState::Checked && (hash.is_none()||checks.as_ref().is_none_or(|checks|checks.is_empty()||checks.iter().any(|check|check.blocking&&!check.passed))) {
                return Err(StoreError::Invalid("proposal checks incomplete"));
            }
            let changed=tx.execute("UPDATE proposals SET state=?1,checks=?2,hash=?3,packages=?4,decided_by=CASE WHEN ?5 THEN 'user' ELSE decided_by END,nonce=COALESCE(?6,nonce),updated_at=?7 WHERE id=?8 AND state=?9",params![next.name(),checks.map(|value|serde_json::to_string(&value)).transpose()?,hash,packages.map(|value|serde_json::to_string(&value)).transpose()?,decision,replacement,timestamp,id,expected.name()])?;
            if changed!=1{return Err(StoreError::Invalid("proposal state changed"));}
            let kind=match next {ProposalState::Checking=>"ext.checking",ProposalState::Checked=>"ext.checked",ProposalState::Approved=>"ext.approved",ProposalState::Rejected=>"ext.rejected",ProposalState::Failed=>"ext.failed",_=>return Err(StoreError::Invalid("invalid proposal transition"))};
            audit(&tx,event_id,timestamp,Audit{kind,actor:if decision{"user"}else{"core"},proposal_id:&id,ext_id:&current.ext_id,from:Some(expected),state:next})?;
            let proposal=get(&tx,&id)?;tx.commit()?;Ok(proposal)
        }).await
    }
}
fn valid_ext_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 40
        && id.as_bytes()[0].is_ascii_lowercase()
        && id.split('-').all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
}
fn valid_hash(hash: &str) -> bool {
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
    ext_id: &'a str,
    from: Option<ProposalState>,
    state: ProposalState,
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
        from,
        state,
    } = change;
    let session = super::sessions::get(tx, "sys")?;
    let event = Event {
        id,
        parent_id: session.head_id,
        session_id: "sys".into(),
        kind: kind.into(),
        actor: actor.into(),
        payload: json!({"proposal_id":proposal_id,"ext_id":ext_id,"from":from,"state":state}),
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
fn get(db: &Connection, id: &str) -> Result<Proposal, StoreError> {
    db.query_row("SELECT id,ext_id,version,hash,source,state,update_of,tainted,manifest,checks,packages,audit_blob,decided_by,note,created_at,updated_at FROM proposals WHERE id=?1",[id],|r|{
        let source:String=r.get(4)?;let state:String=r.get(5)?;
        Ok(Proposal{id:r.get(0)?,ext_id:r.get(1)?,version:r.get(2)?,hash:r.get(3)?,source:decode(&source,4)?,state:decode(&format!("\"{state}\""),5)?,update_of:r.get(6)?,tainted:r.get(7)?,manifest:decode_optional(r.get(8)?,8)?,checks:decode_optional(r.get(9)?,9)?,packages:decode_optional(r.get(10)?,10)?,audit_blob:r.get(11)?,decided_by:r.get(12)?,note:r.get(13)?,created_at:r.get(14)?,updated_at:r.get(15)?})
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
