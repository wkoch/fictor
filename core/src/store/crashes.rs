//! ADR-039: the writer commits recovery and its append-only audit together.
use super::{Event, Sensitivity, Store, StoreError, Trust, events, sessions};
use crate::crash_recovery::{
    CrashClock, CrashObservation, CrashRecorded, CrashTime, CrashesReset, RecoveryKey,
    RecoveryScope, RecoveryStatus, ResetCrashes, valid_boot_id,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Arc, OnceLock};

const WINDOW_MS: i64 = 60_000;
const DELAYS: [i64; 5] = [1000, 2000, 4000, 8000, 16_000];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sample {
    instance_id: String,
    at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Recovery {
    id: Option<i64>,
    recovery: RecoveryKey,
    boot_id: String,
    crashes: Vec<Sample>,
    retry_at_ms: i64,
    blocked: bool,
    updated_at: i64,
}

impl Store {
    /// Trusted admission check. The serialized writer samples the clock and
    /// confirms any rebase/prune before returning; this never schedules work.
    pub async fn crash_availability(
        &self,
        key: RecoveryKey,
        clock: Arc<dyn CrashClock>,
    ) -> Result<RecoveryStatus, StoreError> {
        self.with_writer(move |writer| {
            let time = clock.now()?;
            time.validate()?;
            validate_key(&writer.db, &key)?;
            let tx = writer.db.transaction()?;
            let state = persist_normalized(&tx, &key, &time)?;
            let status = status(state.as_ref(), &time);
            tx.commit()?;
            Ok(status)
        })
        .await
    }

    /// Only the core's observation of an unexpected *active* process exit calls
    /// this API. Requested stops, failed pre-spawn attempts and smoke do not.
    pub async fn record_crash(
        &self,
        observation: CrashObservation,
        clock: Arc<dyn CrashClock>,
    ) -> Result<CrashRecorded, StoreError> {
        self.with_writer(move |writer| {
            let time = clock.now()?; time.validate()?;
            validate_key(&writer.db, &observation.recovery)?;
            if !valid_ulid(&observation.instance_id)
                || observation.stderr.blob.is_none() && !observation.stderr.unavailable
            { return Err(invalid()); }
            let duplicate = historical_observation(&writer.db, &observation)?;
            let mut blob = observation.stderr.blob.clone();
            let mut unavailable = observation.stderr.unavailable;
            if !duplicate && let Some(hash) = &blob {
                match writer.blobs.verify(hash) {
                    Ok(()) => {},
                    Err(error @ super::blobs::BlobError::Ownership) => return Err(error.into()),
                    Err(_) => { blob = None; unavailable = true; },
                }
            }
            let crash_event_id = writer.next_id()?;
            let blocked_event_id = writer.next_id()?;
            let tx = writer.db.transaction()?;
            let mut state = persist_normalized(&tx, &observation.recovery, &time)?;
            if duplicate {
                let result = CrashRecorded { recorded: false, status: status(state.as_ref(), &time) };
                tx.commit()?;
                return Ok(result);
            }
            if state.as_ref().is_some_and(|row| row.blocked) {
                // No seventh active instance may have been admitted. Do not
                // silently discard an inconsistent new observation.
                return Err(StoreError::Invalid("crash novo depois do bloqueio confirmado"));
            }
            let row = state.get_or_insert_with(|| Recovery { id: None, recovery: observation.recovery.clone(),
                boot_id: time.boot_id.clone(), crashes: vec![], retry_at_ms: 0, blocked: false, updated_at: time.unix_ms });
            row.crashes.push(Sample { instance_id: observation.instance_id.clone(), at_ms: time.boottime_ms });
            let count = row.crashes.len();
            row.blocked = count == 6;
            let backoff = if row.blocked { None } else { Some(DELAYS[count - 1]) };
            row.retry_at_ms = backoff.map(|delay| time.boottime_ms.checked_add(delay).ok_or(StoreError::Clock)).transpose()?.unwrap_or(0);
            row.updated_at = time.unix_ms;
            save(&tx, row)?;
            let mut payload = json!({"ext_id":row.recovery.ext_id,"key":row.recovery.key,
                "session_id":row.recovery.session_id,"instance_id":observation.instance_id,
                "code":observation.code,"signal":observation.signal,
                "recovery_count":count,"backoff_ms":backoff,"blocked":row.blocked});
            if let Some(hash) = &blob { payload["stderr_blob"] = hash.clone().into(); }
            if unavailable { payload["stderr_unavailable"] = true.into(); }
            audit(&tx, crash_event_id, time.unix_ms, "ext.crashed", "core", payload, blob.into_iter().collect())?;
            if row.blocked {
                audit(&tx, blocked_event_id, time.unix_ms, "ext.crash_blocked", "core",
                    json!({"ext_id":row.recovery.ext_id,"key":row.recovery.key,"session_id":row.recovery.session_id,
                        "instance_id":observation.instance_id,"crashes":6,"window_ms":WINDOW_MS}), vec![])?;
            }
            let result = CrashRecorded { recorded: true, status: status(state.as_ref(), &time) };
            tx.commit()?;
            Ok(result)
        }).await
    }

    /// Human-only core input, after lock/key resolution under installer
    /// exclusion. No Kernel method accepts ResetCrashes.
    pub async fn reset_crashes(
        &self,
        selection: ResetCrashes,
        unix_ms: i64,
    ) -> Result<CrashesReset, StoreError> {
        self.with_writer(move |writer| {
            let key = RecoveryKey { ext_id: selection.ext_id, key: selection.key, session_id: selection.session_id.clone() };
            validate_key(&writer.db, &key)?;
            if selection.scope == RecoveryScope::Global && selection.session_id.is_some() { return Err(invalid()); }
            let mut statement = writer.db.prepare("SELECT id,ext_id,bundle_key,session_id,boot_id,crashes,retry_at_ms,blocked,updated_at FROM extension_crash_recovery WHERE ext_id=?1 AND bundle_key=?2 AND (?3 IS NULL OR session_id=?3) ORDER BY session_id,id")?;
            let rows = statement.query_map(params![key.ext_id,key.key,key.session_id], raw_row)?
                .collect::<Result<Vec<_>, _>>()?.into_iter().map(decode).collect::<Result<Vec<_>, _>>()?;
            drop(statement);
            for row in &rows {
                validate_key(&writer.db, &row.recovery)?;
                row.validate(None)?;
                if (selection.scope == RecoveryScope::Global) != row.recovery.session_id.is_none() { return Err(invalid()); }
            }
            let ids = (0..rows.len()).map(|_| writer.next_id()).collect::<Result<Vec<_>, _>>()?;
            let tx = writer.db.transaction()?;
            for (row, event_id) in rows.iter().zip(ids) {
                tx.execute("DELETE FROM extension_crash_recovery WHERE id=?1", [row.id])?;
                audit(&tx, event_id, unix_ms, "ext.crash_reset", "user",
                    json!({"ext_id":row.recovery.ext_id,"key":row.recovery.key,"session_id":row.recovery.session_id,
                        "previous_count":row.crashes.len(),"was_blocked":row.blocked}), vec![])?;
            }
            tx.commit()?;
            Ok(CrashesReset { cleared: rows.len() })
        }).await
    }
}

fn invalid() -> StoreError {
    StoreError::Invalid("registro ou identidade de recuperação de crashes inválido")
}
fn valid_ulid(value: &str) -> bool {
    value
        .parse::<ulid::Ulid>()
        .is_ok_and(|id| id.to_string() == value)
}
fn validate_key(db: &Connection, key: &RecoveryKey) -> Result<(), StoreError> {
    static SCHEMAS: OnceLock<Option<(jsonschema::Validator, jsonschema::Validator)>> =
        OnceLock::new();
    let (id, version) = SCHEMAS
        .get_or_init(|| {
            let schema: Value =
                serde_json::from_str(include_str!("../../../spec/schemas/extension.schema.json"))
                    .ok()?;
            Some((
                jsonschema::options()
                    .offline()
                    .build(&schema["properties"]["id"])
                    .ok()?,
                jsonschema::options()
                    .offline()
                    .build(&schema["properties"]["version"])
                    .ok()?,
            ))
        })
        .as_ref()
        .ok_or_else(invalid)?;
    let (name, hash) = key.key.rsplit_once('-').ok_or_else(invalid)?;
    if !id.is_valid(&json!(key.ext_id))
        || !version.is_valid(&json!(name))
        || hash.len() != 12
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }
    if let Some(session) = &key.session_id {
        if !valid_ulid(session) {
            return Err(invalid());
        }
        if sessions::get(db, session)?.kind == "system" {
            return Err(invalid());
        }
    }
    Ok(())
}

type Raw = (
    i64,
    String,
    String,
    Option<String>,
    String,
    String,
    i64,
    i64,
    i64,
);
fn raw_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Raw> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
    ))
}
fn decode(raw: Raw) -> Result<Recovery, StoreError> {
    let (id, ext_id, key, session_id, boot_id, crashes, retry_at_ms, blocked, updated_at) = raw;
    if !matches!(blocked, 0 | 1) {
        return Err(invalid());
    }
    Ok(Recovery {
        id: Some(id),
        recovery: RecoveryKey {
            ext_id,
            key,
            session_id,
        },
        boot_id,
        crashes: serde_json::from_str(&crashes)?,
        retry_at_ms,
        blocked: blocked == 1,
        updated_at,
    })
}
fn load(db: &Connection, key: &RecoveryKey) -> Result<Option<Recovery>, StoreError> {
    db.query_row("SELECT id,ext_id,bundle_key,session_id,boot_id,crashes,retry_at_ms,blocked,updated_at FROM extension_crash_recovery WHERE ext_id=?1 AND bundle_key=?2 AND session_id IS ?3",
        params![key.ext_id,key.key,key.session_id],raw_row).optional()?.map(decode).transpose()
}
impl Recovery {
    fn validate(&self, time: Option<&CrashTime>) -> Result<(), StoreError> {
        if !valid_boot_id(&self.boot_id)
            || self.retry_at_ms < 0
            || self.crashes.len() > 6
            || (self.blocked && (self.crashes.len() != 6 || self.retry_at_ms != 0))
            || (!self.blocked && self.crashes.len() > 5)
            || (self.crashes.is_empty() && self.retry_at_ms != 0)
        {
            return Err(invalid());
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut previous = 0;
        for sample in &self.crashes {
            if !valid_ulid(&sample.instance_id)
                || sample.at_ms < previous
                || !seen.insert(&sample.instance_id)
                || time.is_some_and(|time| {
                    time.boot_id == self.boot_id && sample.at_ms > time.boottime_ms
                })
            {
                return Err(invalid());
            }
            previous = sample.at_ms;
        }
        if !self.blocked && !self.crashes.is_empty() {
            let minimum = DELAYS[self.crashes.len() - 1];
            if self.retry_at_ms != 0 {
                let delay = self.retry_at_ms.checked_sub(previous).ok_or_else(invalid)?;
                // Pruning can reduce the stored count while preserving a
                // longer existing wait; it never permits a shorter deadline.
                if !DELAYS.contains(&delay) || delay < minimum {
                    return Err(invalid());
                }
            } else if let Some(time) = time
                && time.boot_id == self.boot_id
                && time.boottime_ms < previous.checked_add(minimum).ok_or_else(invalid)?
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
fn persist_normalized(
    tx: &Transaction<'_>,
    key: &RecoveryKey,
    time: &CrashTime,
) -> Result<Option<Recovery>, StoreError> {
    let original = load(tx, key)?;
    let mut normalized = normalize_at(original.clone(), time)?;
    match (&original, &mut normalized) {
        (Some(previous), None) => {
            tx.execute(
                "DELETE FROM extension_crash_recovery WHERE id=?1",
                [previous.id],
            )?;
        }
        (Some(previous), Some(row)) if previous != row => save(tx, row)?,
        _ => {}
    }
    Ok(normalized)
}

// Deterministic state transition: all time is injected, and no I/O occurs here.
fn normalize_at(state: Option<Recovery>, time: &CrashTime) -> Result<Option<Recovery>, StoreError> {
    let Some(mut row) = state else {
        return Ok(None);
    };
    row.validate(Some(time))?;
    if row.blocked {
        return Ok(Some(row));
    }
    let original = row.clone();
    if row.boot_id != time.boot_id {
        row.boot_id = time.boot_id.clone();
        for sample in &mut row.crashes {
            sample.at_ms = time.boottime_ms;
        }
        row.retry_at_ms = if row.crashes.is_empty() {
            0
        } else {
            time.boottime_ms
                .checked_add(DELAYS[row.crashes.len() - 1])
                .ok_or(StoreError::Clock)?
        };
    } else {
        row.crashes
            .retain(|sample| sample.at_ms > time.boottime_ms - WINDOW_MS);
        if row.retry_at_ms <= time.boottime_ms {
            row.retry_at_ms = 0;
        }
    }
    if row.crashes.is_empty() {
        return Ok(None);
    }
    if row != original {
        row.updated_at = time.unix_ms;
    }
    Ok(Some(row))
}
fn status(state: Option<&Recovery>, time: &CrashTime) -> RecoveryStatus {
    match state {
        Some(row) if row.blocked => RecoveryStatus::CrashLoop,
        Some(row) if row.retry_at_ms > time.boottime_ms => RecoveryStatus::Backoff {
            retry_after_ms: row.retry_at_ms - time.boottime_ms,
        },
        _ => RecoveryStatus::Ready,
    }
}
fn save(tx: &Transaction<'_>, row: &mut Recovery) -> Result<(), StoreError> {
    row.validate(None)?;
    let crashes = serde_json::to_string(&row.crashes)?;
    if row.id.is_none() {
        tx.execute("INSERT INTO extension_crash_recovery(ext_id,bundle_key,session_id,boot_id,crashes,retry_at_ms,blocked,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",params![row.recovery.ext_id,row.recovery.key,row.recovery.session_id,row.boot_id,crashes,row.retry_at_ms,row.blocked,row.updated_at])?;
        row.id = Some(tx.last_insert_rowid());
    } else {
        tx.execute("UPDATE extension_crash_recovery SET boot_id=?1,crashes=?2,retry_at_ms=?3,blocked=?4,updated_at=?5 WHERE id=?6",params![row.boot_id,crashes,row.retry_at_ms,row.blocked,row.updated_at,row.id])?;
    }
    Ok(())
}
fn historical_observation(
    db: &Connection,
    observation: &CrashObservation,
) -> Result<bool, StoreError> {
    let mut statement=db.prepare("SELECT payload FROM events WHERE kind='ext.crashed' AND json_extract(payload,'$.instance_id')=?1 LIMIT 2")?;
    let rows = statement
        .query_map([&observation.instance_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() > 1 {
        return Err(invalid());
    }
    let Some(payload) = rows.first() else {
        return Ok(false);
    };
    let payload: Value = serde_json::from_str(payload)?;
    if payload["ext_id"] != observation.recovery.ext_id
        || payload["key"] != observation.recovery.key
        || payload
            .get("session_id")
            .is_some_and(|session| *session != json!(observation.recovery.session_id))
        || payload.get("smoke") == Some(&Value::Bool(true))
    {
        return Err(invalid());
    }
    Ok(true)
}
fn audit(
    tx: &Transaction<'_>,
    id: String,
    at: i64,
    kind: &str,
    actor: &str,
    payload: Value,
    blob_refs: Vec<String>,
) -> Result<(), StoreError> {
    let system = sessions::get(tx, "sys")?;
    let event = Event {
        id,
        parent_id: system.head_id,
        session_id: "sys".into(),
        kind: kind.into(),
        actor: actor.into(),
        payload,
        blob_refs,
        trust: Trust::Trusted,
        sensitivity: Sensitivity::Public,
        source: "core".into(),
        flags: system.flags,
        text: None,
        created_at: at,
    };
    events::insert(tx, &event)?;
    tx.execute(
        "UPDATE sessions SET head_id=?1,updated_at=?2 WHERE id='sys'",
        params![event.id, at],
    )?;
    Ok(())
}
