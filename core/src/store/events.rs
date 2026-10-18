use super::{Store, StoreError, now_ms, read_budget::ReadBudget};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const INLINE_LIMIT: usize = 64 * 1024;
const TEXT_LIMIT: usize = 32 * 1024;
pub(super) const EVENT_COLUMNS: &str = "id, parent_id, session_id, kind, actor, payload, blob_refs, trust, sensitivity, source, flags, text, created_at";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flags {
    #[serde(rename = "U")]
    pub untrusted: bool,
    #[serde(rename = "P")]
    pub private: bool,
}
impl Flags {
    pub(super) fn bits(self) -> u8 {
        u8::from(self.untrusted) | (u8::from(self.private) << 1)
    }
    pub(super) fn from_bits(bits: u8) -> Self {
        Self {
            untrusted: bits & 1 != 0,
            private: bits & 2 != 0,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Trust {
    Trusted,
    Untrusted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sensitivity {
    Public,
    Private,
}

/// Trusted core input, derived by policy/gateway. Never deserialize this from extension requests.
#[derive(Clone, Debug)]
pub struct Provenance {
    pub trust: Trust,
    pub sensitivity: Sensitivity,
    pub source: String,
}
impl Provenance {
    pub fn core() -> Self {
        Self {
            trust: Trust::Trusted,
            sensitivity: Sensitivity::Public,
            source: "core".into(),
        }
    }
}
#[derive(Clone, Debug)]
pub struct AppendEvent {
    pub session_id: String,
    pub parent_id: Option<String>,
    pub kind: String,
    pub actor: String,
    pub payload: Value,
    pub blob_refs: Vec<String>,
    pub provenance: Provenance,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub parent_id: Option<String>,
    pub session_id: String,
    pub kind: String,
    pub actor: String,
    pub payload: Value,
    pub blob_refs: Vec<String>,
    pub trust: Trust,
    pub sensitivity: Sensitivity,
    pub source: String,
    pub flags: Flags,
    #[serde(skip_serializing)]
    pub text: Option<String>,
    pub created_at: i64,
}
pub struct EventPath {
    pub events: Vec<Event>,
    pub truncated: bool,
}
#[derive(Default)]
pub struct EventQuery {
    pub session_id: Option<String>,
    pub kinds: Vec<String>,
    pub text: Option<String>,
    pub since_ms: Option<i64>,
    pub until_ms: Option<i64>,
    pub limit: Option<usize>,
}

impl Store {
    /// Core-only ingress accounting: commit U before proxy bytes reach the instance.
    /// Network reads have trusted control metadata but introduce untrusted data.
    pub async fn taint_from_network(
        &self,
        session_id: String,
        host: String,
    ) -> Result<Flags, StoreError> {
        if host.is_empty() || host.chars().any(char::is_control) {
            return Err(StoreError::Invalid(
                "host inválido para proveniência de rede",
            ));
        }
        self.with_writer(move |writer| {
            let id = writer.next_id()?;
            let transaction = writer.db.transaction()?;
            let session = super::sessions::get(&transaction, &session_id)?;
            if session.archived || session.kind == "system" {
                return Err(StoreError::Invalid(
                    "contaminação de rede exige sessão ativa",
                ));
            }
            if session.flags.untrusted {
                return Ok(session.flags);
            }
            let flags = Flags {
                untrusted: true,
                private: session.flags.private,
            };
            let event = Event {
                id,
                parent_id: session.head_id,
                session_id: session_id.clone(),
                kind: "session.tainted".into(),
                actor: "core".into(),
                payload: json!({"flag":"U","reason":format!("net:{host}")}),
                blob_refs: vec![],
                trust: Trust::Trusted,
                sensitivity: Sensitivity::Public,
                source: "core".into(),
                flags,
                text: None,
                created_at: now_ms()?,
            };
            insert(&transaction, &event)?;
            transaction.execute(
                "UPDATE sessions SET head_id=?1,updated_at=?2 WHERE id=?3",
                params![event.id, event.created_at, session_id],
            )?;
            transaction.commit()?;
            Ok(flags)
        })
        .await
    }

    pub async fn append(&self, input: AppendEvent) -> Result<Event, StoreError> {
        self.with_writer(move |writer| {
            let id = writer.next_id()?;
            let taint_ids = [writer.next_id()?, writer.next_id()?];
            let transaction = writer.db.transaction()?;
            let session = super::sessions::get(&transaction, &input.session_id)?;
            if session.archived { return Err(StoreError::Invalid("sessão arquivada")); }
            if input.parent_id.as_ref().is_some_and(|parent| Some(parent) != session.head_id.as_ref()) {
                return Err(StoreError::HeadMoved);
            }
            let payload = serde_json::to_vec(&input.payload)?;
            let mut blob_refs = input.blob_refs;
            // Validate every reference without interpreting or trusting extension paths.
            for hash in &blob_refs { writer.blobs.verify(hash)?; }
            let stored_payload = if payload.len() > INLINE_LIMIT {
                let hash = writer.blobs.put(&payload)?;
                if !blob_refs.contains(&hash) { blob_refs.push(hash.clone()); }
                json!({"$blob": hash})
            } else { input.payload.clone() };
            let added = Flags {
                untrusted: input.provenance.trust == Trust::Untrusted,
                private: input.provenance.sensitivity == Sensitivity::Private,
            };
            let flags = Flags::from_bits(session.flags.bits() | added.bits());
            let event = Event {
                id, parent_id: session.head_id, session_id: input.session_id.clone(),
                kind: input.kind.clone(), actor: input.actor, payload: stored_payload, blob_refs,
                trust: input.provenance.trust, sensitivity: input.provenance.sensitivity,
                source: input.provenance.source.clone(), flags,
                text: searchable_text(&input.kind, &input.payload), created_at: now_ms()?,
            };
            insert(&transaction, &event)?;
            let mut head = event.id.clone();
            for ((flag, newly_set), taint_id) in [
                ("U", added.untrusted && !session.flags.untrusted),
                ("P", added.private && !session.flags.private),
            ].into_iter().zip(taint_ids) {
                if newly_set {
                    let tainted = Event {
                        id: taint_id, parent_id: Some(head), session_id: input.session_id.clone(),
                        kind: "session.tainted".into(), actor: "core".into(),
                        payload: json!({"flag": flag, "reason": input.provenance.source, "source_event_id": event.id}),
                        blob_refs: vec![], trust: Trust::Trusted, sensitivity: Sensitivity::Public,
                        source: "core".into(), flags, text: None, created_at: event.created_at,
                    };
                    insert(&transaction, &tainted)?;
                    head = tainted.id;
                }
            }
            transaction.execute("UPDATE sessions SET head_id=?1, updated_at=?2 WHERE id=?3", params![head, event.created_at, input.session_id])?;
            transaction.commit()?;
            Ok(event)
        }).await
    }

    pub async fn event(&self, id: String) -> Result<Event, StoreError> {
        self.read(move |db| get(db, &id)).await
    }

    pub async fn event_path(
        &self,
        session_id: String,
        after_id: Option<String>,
        limit: Option<usize>,
    ) -> Result<EventPath, StoreError> {
        self.read(move |db| {
            let session = super::sessions::get(db, &session_id)?;
            let limit = limit.unwrap_or(2000).clamp(1, 10000);
            path(
                db,
                session.head_id.as_deref(),
                after_id.as_deref(),
                limit,
                None,
            )
        })
        .await
    }

    /// Trusted core boundary: caller must authorize this head before exposing it.
    pub async fn event_path_at(
        &self,
        head: Option<String>,
        after: Option<String>,
        limit: Option<usize>,
    ) -> Result<EventPath, StoreError> {
        self.read(move |db| {
            path(
                db,
                head.as_deref(),
                after.as_deref(),
                limit.unwrap_or(2000).clamp(1, 10000),
                None,
            )
        })
        .await
    }

    /// Kernel-only read budget; authorization of the head stays with the caller.
    pub(crate) async fn event_path_at_bounded(
        &self,
        head: Option<String>,
        after: Option<String>,
        limit: Option<usize>,
        response_limit: usize,
    ) -> Result<EventPath, StoreError> {
        self.read(move |db| {
            // Count the actual bool after discovering truncation, so a true
            // result does not lose one byte to a false worst-case estimate.
            let budget = ReadBudget::new(response_limit, b"{\"events\":[],\"truncated\":}".len())?;
            path(
                db,
                head.as_deref(),
                after.as_deref(),
                limit.unwrap_or(2000).clamp(1, 10000),
                Some(budget),
            )
        })
        .await
    }

    pub async fn event_in_lineage(
        &self,
        session_id: String,
        event_id: String,
    ) -> Result<bool, StoreError> {
        self.read(move |db| {
            let session = super::sessions::get(db, &session_id)?;
            Ok(db.query_row("WITH RECURSIVE lineage(id,parent_id) AS (SELECT id,parent_id FROM events WHERE id=?1 UNION ALL SELECT e.id,e.parent_id FROM events e JOIN lineage l ON e.id=l.parent_id) SELECT EXISTS(SELECT 1 FROM lineage WHERE id=?2)", params![session.head_id, event_id], |row| row.get(0))?)
        }).await
    }

    pub async fn query_events(&self, query: EventQuery) -> Result<Vec<Event>, StoreError> {
        self.read(move |db| {
            let head = query
                .session_id
                .as_deref()
                .map(|id| super::sessions::get(db, id).map(|session| session.head_id))
                .transpose()?;
            query_at(db, query, head, None)
        })
        .await
    }
    /// Trusted core boundary: None is an empty lineage, never a global query.
    pub async fn query_events_at(
        &self,
        head: Option<String>,
        query: EventQuery,
    ) -> Result<Vec<Event>, StoreError> {
        self.read(move |db| query_at(db, query, Some(head), None))
            .await
    }

    pub(crate) async fn query_events_bounded(
        &self,
        query: EventQuery,
        response_limit: usize,
    ) -> Result<Vec<Event>, StoreError> {
        self.read(move |db| {
            let head = query
                .session_id
                .as_deref()
                .map(|id| super::sessions::get(db, id).map(|session| session.head_id))
                .transpose()?;
            let budget = ReadBudget::new(response_limit, b"{\"events\":[]}".len())?;
            query_at(db, query, head, Some(budget))
        })
        .await
    }

    /// Kernel-only read budget; None remains an empty lineage, never global.
    pub(crate) async fn query_events_at_bounded(
        &self,
        head: Option<String>,
        query: EventQuery,
        response_limit: usize,
    ) -> Result<Vec<Event>, StoreError> {
        self.read(move |db| {
            let budget = ReadBudget::new(response_limit, b"{\"events\":[]}".len())?;
            query_at(db, query, Some(head), Some(budget))
        })
        .await
    }
}

fn query_at(
    db: &Connection,
    query: EventQuery,
    head: Option<Option<String>>,
    mut budget: Option<ReadBudget>,
) -> Result<Vec<Event>, StoreError> {
    let mut sql = format!("SELECT {EVENT_COLUMNS} FROM events WHERE 1=1");
    let mut values = Vec::<rusqlite::types::Value>::new();
    if let Some(head) = head {
        sql.push_str(" AND id IN (WITH RECURSIVE lineage(id, parent_id) AS (SELECT id, parent_id FROM events WHERE id=? UNION ALL SELECT e.id, e.parent_id FROM events e JOIN lineage l ON e.id=l.parent_id) SELECT id FROM lineage)");
        values.push(head.into());
    }
    if !query.kinds.is_empty() {
        sql.push_str(&format!(
            " AND kind IN ({})",
            vec!["?"; query.kinds.len()].join(",")
        ));
        values.extend(query.kinds.into_iter().map(Into::into));
    }
    if let Some(text) = query.text {
        sql.push_str(" AND seq IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)");
        values.push(text.into());
    }
    if let Some(since) = query.since_ms {
        sql.push_str(" AND created_at>=?");
        values.push(since.into());
    }
    if let Some(until) = query.until_ms {
        sql.push_str(" AND created_at<=?");
        values.push(until.into());
    }
    sql.push_str(" ORDER BY seq DESC LIMIT ?");
    values.push((query.limit.unwrap_or(100).clamp(1, 500) as i64).into());
    let mut statement = db.prepare(&sql)?;
    let mut rows = statement.query(rusqlite::params_from_iter(values))?;
    let mut events = Vec::new();
    while let Some(row) = rows.next()? {
        let event = from_row(row)?;
        if let Some(budget) = budget.as_mut() {
            budget.item(&event, !events.is_empty())?;
        }
        events.push(event);
    }
    Ok(events)
}

pub(super) fn insert(transaction: &Transaction<'_>, event: &Event) -> Result<(), StoreError> {
    transaction.execute("INSERT INTO events (id,parent_id,session_id,kind,actor,payload,blob_refs,trust,sensitivity,source,flags,text,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        params![event.id, event.parent_id, event.session_id, event.kind, event.actor,
            serde_json::to_string(&event.payload)?, serde_json::to_string(&event.blob_refs)?,
            match event.trust { Trust::Trusted => "trusted", Trust::Untrusted => "untrusted" },
            match event.sensitivity { Sensitivity::Public => "public", Sensitivity::Private => "private" },
            event.source, event.flags.bits(), event.text, event.created_at])?;
    Ok(())
}

pub(super) fn get(db: &Connection, id: &str) -> Result<Event, StoreError> {
    db.query_row(
        &format!("SELECT {EVENT_COLUMNS} FROM events WHERE id=?1"),
        [id],
        from_row,
    )
    .optional()?
    .ok_or(StoreError::NotFound)
}

fn path(
    db: &Connection,
    head: Option<&str>,
    after: Option<&str>,
    limit: usize,
    mut budget: Option<ReadBudget>,
) -> Result<EventPath, StoreError> {
    // Walk only IDs; read bounded payloads even when a session has a very long history.
    let lineage = "WITH RECURSIVE lineage(id,parent_id,depth) AS (SELECT id,parent_id,0 FROM events WHERE id=?1 UNION ALL SELECT e.id,e.parent_id,l.depth+1 FROM events e JOIN lineage l ON e.id=l.parent_id)";
    if let Some(after) = after {
        let belongs: bool = db.query_row(
            &format!("{lineage} SELECT EXISTS(SELECT 1 FROM lineage WHERE id=?2)"),
            params![head, after],
            |r| r.get(0),
        )?;
        if !belongs {
            return Err(StoreError::Invalid("after_id fora da linhagem"));
        }
    }
    let columns = EVENT_COLUMNS
        .split(", ")
        .map(|s| format!("e.{s}"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut statement = db.prepare(&format!("{lineage} SELECT {columns} FROM lineage l JOIN events e ON e.id=l.id WHERE (?2 IS NULL OR l.depth < (SELECT depth FROM lineage WHERE id=?2)) ORDER BY l.depth LIMIT ?3"))?;
    let mut rows = statement.query(params![head, after, (limit + 1) as i64])?;
    let mut events = Vec::new();
    let mut truncated = false;
    while let Some(row) = rows.next()? {
        if events.len() == limit {
            truncated = true;
            break;
        }
        let event = from_row(row)?;
        if let Some(budget) = budget.as_mut() {
            budget.item(&event, !events.is_empty())?;
        }
        events.push(event);
    }
    if let Some(budget) = budget.as_mut() {
        budget.value(&truncated)?;
    }
    events.reverse();
    Ok(EventPath { events, truncated })
}

fn decode<T: serde::de::DeserializeOwned>(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<T> {
    let value: String = row.get(index)?;
    serde_json::from_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}
fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Event> {
    Ok(Event {
        id: row.get(0)?,
        parent_id: row.get(1)?,
        session_id: row.get(2)?,
        kind: row.get(3)?,
        actor: row.get(4)?,
        payload: decode(row, 5)?,
        blob_refs: decode(row, 6)?,
        trust: match row.get::<_, String>(7)?.as_str() {
            "trusted" => Trust::Trusted,
            _ => Trust::Untrusted,
        },
        sensitivity: match row.get::<_, String>(8)?.as_str() {
            "public" => Sensitivity::Public,
            _ => Sensitivity::Private,
        },
        source: row.get(9)?,
        flags: Flags::from_bits(row.get(10)?),
        text: row.get(11)?,
        created_at: row.get(12)?,
    })
}

fn searchable_text(kind: &str, payload: &Value) -> Option<String> {
    let text = match kind {
        "assistant.message" => payload.get("text")?.as_str()?.to_owned(),
        "user.message" | "tool.result" => payload
            .get("content")?
            .as_array()?
            .iter()
            .filter_map(|part| {
                (part.get("type")?.as_str()? == "text")
                    .then(|| part.get("text")?.as_str())
                    .flatten()
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => return None,
    };
    if text.len() > TEXT_LIMIT {
        None
    } else {
        Some(text)
    }
}

#[cfg(test)]
mod read_limit_tests {
    use super::*;
    use crate::{config::Mode, store::NewSession};

    #[tokio::test]
    async fn event_budgets_match_exact_serialized_wrappers_and_truncation_bool() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("h");
        let workspace = root.path().join("w");
        std::fs::create_dir(&workspace).unwrap();
        crate::initialize(&home).await.unwrap();
        let store = Store::open(&home).await.unwrap();
        let session = store
            .create_session(NewSession {
                title: "boundaries".into(),
                workspace,
                workspace_trust: Trust::Trusted,
                harness: "test".into(),
                mode: Mode::Default,
                model: None,
            })
            .await
            .unwrap();
        for index in 0..2 {
            store
                .append(AppendEvent {
                    session_id: session.id.clone(),
                    parent_id: None,
                    kind: "x.test.note".into(),
                    actor: "core".into(),
                    payload: json!({"index":index,"text":"\"\n\\\u{1}"}),
                    blob_refs: vec![],
                    provenance: Provenance::core(),
                })
                .await
                .unwrap();
        }
        let head = store.session(session.id).await.unwrap().head_id;
        for head in [head, None] {
            let expected = store
                .event_path_at(head.clone(), None, Some(1))
                .await
                .unwrap();
            let bytes = serde_json::to_vec(
                &json!({"events":expected.events,"truncated":expected.truncated}),
            )
            .unwrap()
            .len();
            let actual = store
                .event_path_at_bounded(head.clone(), None, Some(1), bytes)
                .await
                .unwrap();
            assert_eq!(actual.truncated, expected.truncated);
            assert_eq!(actual.events.len(), expected.events.len());
            assert!(matches!(
                store
                    .event_path_at_bounded(head.clone(), None, Some(1), bytes - 1)
                    .await,
                Err(StoreError::TooLarge)
            ));
            let expected = store
                .query_events_at(
                    head.clone(),
                    EventQuery {
                        limit: Some(1),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            let bytes = serde_json::to_vec(&json!({"events":expected}))
                .unwrap()
                .len();
            assert_eq!(
                store
                    .query_events_at_bounded(
                        head.clone(),
                        EventQuery {
                            limit: Some(1),
                            ..Default::default()
                        },
                        bytes
                    )
                    .await
                    .unwrap()
                    .len(),
                expected.len()
            );
            assert!(matches!(
                store
                    .query_events_at_bounded(
                        head,
                        EventQuery {
                            limit: Some(1),
                            ..Default::default()
                        },
                        bytes - 1
                    )
                    .await,
                Err(StoreError::TooLarge)
            ));
        }
    }
}
