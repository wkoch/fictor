use super::{Event, Flags, Sensitivity, Store, StoreError, Trust, events, now_ms};
use crate::config::Mode;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct NewSession {
    pub title: String,
    pub workspace: PathBuf,
    pub workspace_trust: Trust,
    pub harness: String,
    pub mode: Mode,
    pub model: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub workspace: Option<String>,
    pub workspace_trust: Trust,
    pub harness: Option<String>,
    pub mode: Mode,
    pub model: Option<String>,
    pub parent_session_id: Option<String>,
    pub fork_event_id: Option<String>,
    pub head_id: Option<String>,
    pub flags: Flags,
    pub archived: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Store {
    pub async fn create_session(&self, input: NewSession) -> Result<Session, StoreError> {
        let home = self.blobs.home()?.to_path_buf();
        self.with_writer(move |writer| {
            let workspace = validate_workspace(&input.workspace, &home)?;
            let workspace = workspace.to_str().ok_or(StoreError::Invalid("workspace deve ser UTF-8"))?;
            let id = writer.next_id()?;
            let event_id = writer.next_id()?;
            let timestamp = now_ms()?;
            let transaction = writer.db.transaction()?;
            transaction.execute("INSERT INTO sessions (id,title,workspace,workspace_trust,harness,mode,model,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?8)",
                params![id, input.title, workspace, trust_name(input.workspace_trust), input.harness, mode_name(input.mode), input.model, timestamp])?;
            let event = Event {
                id: event_id, parent_id: None, session_id: id.clone(), kind: "session.created".into(), actor: "core".into(),
                payload: json!({"title": input.title, "workspace": workspace, "workspace_trust": input.workspace_trust, "harness": input.harness, "mode": input.mode, "model": input.model}),
                blob_refs: vec![], trust: Trust::Trusted, sensitivity: Sensitivity::Public,
                source: "core".into(), flags: Flags::default(), text: None, created_at: timestamp,
            };
            events::insert(&transaction, &event)?;
            transaction.execute("UPDATE sessions SET head_id=?1 WHERE id=?2", params![event.id, id])?;
            let session = get(&transaction, &id)?;
            transaction.commit()?;
            Ok(session)
        }).await
    }

    pub async fn session(&self, id: String) -> Result<Session, StoreError> {
        self.read(move |db| get(db, &id)).await
    }

    pub async fn fork_session(
        &self,
        from_event_id: String,
        title: Option<String>,
    ) -> Result<Session, StoreError> {
        self.with_writer(move |writer| {
            let id = writer.next_id()?;
            let fork_event_id = writer.next_id()?;
            let timestamp = now_ms()?;
            let transaction = writer.db.transaction()?;
            let origin = events::get(&transaction, &from_event_id)?;
            let parent = get(&transaction, &origin.session_id)?;
            if parent.kind == "system" { return Err(StoreError::Invalid("sys não pode ser ramificada")); }
            let title = title.unwrap_or(parent.title);
            transaction.execute("INSERT INTO sessions (id,title,workspace,workspace_trust,harness,mode,model,parent_session_id,fork_event_id,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10)",
                params![id, title, parent.workspace, trust_name(parent.workspace_trust), parent.harness, mode_name(parent.mode), parent.model, origin.session_id, origin.id, timestamp])?;
            let fork = Event {
                id: fork_event_id, parent_id: Some(origin.id.clone()), session_id: id.clone(),
                kind: "session.forked".into(), actor: "core".into(),
                payload: json!({"from_session_id": origin.session_id, "from_event_id": origin.id}),
                blob_refs: vec![], trust: Trust::Trusted, sensitivity: Sensitivity::Public,
                source: "core".into(), flags: origin.flags, text: None, created_at: timestamp,
            };
            events::insert(&transaction, &fork)?;
            transaction.execute("UPDATE sessions SET head_id=?1 WHERE id=?2", params![fork.id, id])?;
            let session = get(&transaction, &id)?;
            transaction.commit()?;
            Ok(session)
        }).await
    }
}

pub(super) fn get(db: &Connection, id: &str) -> Result<Session, StoreError> {
    db.query_row("SELECT s.id,s.kind,s.title,s.workspace,s.workspace_trust,s.harness,s.mode,s.model,s.parent_session_id,s.fork_event_id,s.head_id,COALESCE(e.flags,0),s.archived,s.created_at,s.updated_at FROM sessions s LEFT JOIN events e ON e.id=s.head_id WHERE s.id=?1", [id], |r| {
        Ok(Session {
            id:r.get(0)?, kind:r.get(1)?, title:r.get(2)?, workspace:r.get(3)?,
            workspace_trust: if r.get::<_, String>(4)? == "trusted" {Trust::Trusted} else {Trust::Untrusted},
            harness:r.get(5)?, mode:match r.get::<_, String>(6)?.as_str() {"auto"=>Mode::Auto,"default"=>Mode::Default,_=>Mode::Plan},
            model:r.get(7)?, parent_session_id:r.get(8)?, fork_event_id:r.get(9)?, head_id:r.get(10)?,
            flags:Flags::from_bits(r.get(11)?), archived:r.get(12)?, created_at:r.get(13)?, updated_at:r.get(14)?,
        })
    }).optional()?.ok_or(StoreError::NotFound)
}

fn validate_workspace(path: &Path, home: &Path) -> Result<PathBuf, StoreError> {
    if !path.is_absolute() {
        return Err(StoreError::Invalid("workspace deve ser absoluto"));
    }
    let canonical = path.canonicalize()?;
    let home = home.canonicalize()?;
    // Reject ancestors too: mounting a workspace must not expose FICTOR_HOME through a child directory.
    if !canonical.is_dir()
        || canonical.parent().is_none()
        || canonical.starts_with(&home)
        || home.starts_with(&canonical)
    {
        return Err(StoreError::Invalid(
            "workspace deve ser diretório fora de FICTOR_HOME, sem sobreposição",
        ));
    }
    if let Some(user_home) = std::env::var_os("HOME")
        && Path::new(&user_home)
            .canonicalize()
            .is_ok_and(|home| canonical == home)
    {
        return Err(StoreError::Invalid(
            "HOME inteiro exige confirmação no shell, disponível em M0.7",
        ));
    }
    Ok(canonical)
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Plan => "plan",
        Mode::Default => "default",
        Mode::Auto => "auto",
    }
}
fn trust_name(trust: Trust) -> &'static str {
    match trust {
        Trust::Trusted => "trusted",
        Trust::Untrusted => "untrusted",
    }
}
