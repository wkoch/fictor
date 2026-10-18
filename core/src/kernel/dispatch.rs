use super::*;
use crate::{
    config::Config,
    store::{AppendEvent, EventQuery, Provenance, Sensitivity, Trust},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionId {
    session_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventId {
    id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Append {
    session_id: String,
    kind: String,
    payload: Value,
    #[serde(default, deserialize_with = "optional")]
    parent_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Path {
    session_id: String,
    #[serde(default, deserialize_with = "optional")]
    after_id: Option<String>,
    #[serde(default, deserialize_with = "optional")]
    limit: Option<usize>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Query {
    #[serde(default, deserialize_with = "optional")]
    session_id: Option<String>,
    #[serde(default, deserialize_with = "optional")]
    kinds: Option<Vec<String>>,
    #[serde(default, deserialize_with = "optional")]
    text: Option<String>,
    #[serde(default, deserialize_with = "optional")]
    since_ms: Option<i64>,
    #[serde(default, deserialize_with = "optional")]
    until_ms: Option<i64>,
    #[serde(default, deserialize_with = "optional")]
    limit: Option<usize>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fork {
    from_event_id: String,
    #[serde(default, deserialize_with = "optional")]
    title: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Key {
    key: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Set {
    key: String,
    value: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct List {
    #[serde(default, deserialize_with = "optional")]
    prefix: Option<String>,
    #[serde(default, deserialize_with = "optional")]
    limit: Option<usize>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Put {
    #[serde(default, deserialize_with = "optional")]
    text: Option<String>,
    #[serde(default, deserialize_with = "optional")]
    base64: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hash {
    hash: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Section {
    section: String,
}
fn optional<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(d).map(Some)
}
fn ulid(value: &str) -> Result<(), RpcError> {
    if valid_ulid(value) {
        Ok(())
    } else {
        Err(RpcError::INVALID)
    }
}
fn session_id(value: &str) -> Result<(), RpcError> {
    if value == "sys" { Ok(()) } else { ulid(value) }
}
fn limit(value: Option<usize>, max: usize) -> Result<(), RpcError> {
    if value.is_some_and(|n| n == 0 || n > max) {
        Err(RpcError::INVALID)
    } else {
        Ok(())
    }
}

pub(super) async fn call(state: &State, method: &str, value: Value) -> Result<Value, RpcError> {
    let scope = match method {
        "events.append" => "events.write",
        "events.get" | "events.path" | "events.query" => "events.read",
        "sessions.get" | "sessions.fork" | "sessions.delegate" | "sessions.complete" => "sessions",
        "sessions.input" => "sessions.input",
        "blobs.put" | "blobs.get" => "blobs",
        "kv.get" | "kv.set" | "kv.delete" | "kv.list" => "kv",
        "config.get" => "config",
        "tools.list" | "tools.call" => "tools",
        "hooks.invoke" => "hooks",
        "catalog.list" => "catalog",
        "ui.emit" | "ui.mount" => "ui",
        "timers.set" | "timers.cancel" | "timers.list" => "timers",
        "approval.request" => "approval",
        "ext.propose" | "ext.proposal_status" => "ext.propose",
        _ => return Err(RpcError::METHOD),
    };
    if !state.identity.scopes.contains(scope) {
        return Err(RpcError::SCOPE);
    }
    match method {
        "events.append" => {
            let p: Append = params(value)?;
            session_id(&p.session_id)?;
            if let Some(parent) = &p.parent_id {
                ulid(parent)?;
            }
            match &state.identity.session_id {
                Some(own) if *own != p.session_id => return Err(RpcError::SCOPE),
                None if p.session_id != "sys" => return Err(RpcError::SCOPE), // Global cross-session writes await the Phase-1 watermark decision.
                _ => {}
            }
            let prefix = format!("x.{}.", state.identity.ext_id);
            let suffix = p.kind.strip_prefix(&prefix).or_else(|| {
                if state.identity.is_harness {
                    p.kind
                        .strip_prefix("assistant.")
                        .or_else(|| p.kind.strip_prefix("harness."))
                } else {
                    None
                }
            });
            if suffix.is_none_or(|s| {
                s.is_empty() || s.split('.').any(str::is_empty) || s.chars().any(char::is_control)
            }) {
                return Err(RpcError::new(-32009, "INVALID_KIND"));
            }
            let actor = format!("ext:{}", state.identity.ext_id);
            let event = state
                .store
                .append(AppendEvent {
                    session_id: p.session_id,
                    parent_id: p.parent_id,
                    kind: p.kind,
                    payload: p.payload,
                    blob_refs: vec![],
                    actor: actor.clone(),
                    provenance: Provenance {
                        trust: Trust::Trusted,
                        sensitivity: Sensitivity::Public,
                        source: actor,
                    },
                })
                .await?;
            Ok(json!({"id":event.id,"flags":event.flags}))
        }
        "events.get" => {
            let p: EventId = params(value)?;
            ulid(&p.id)?;
            authorize_event(state, &p.id).await?;
            serialize(state.store.event(p.id).await?)
        }
        "events.path" => {
            let p: Path = params(value)?;
            session_id(&p.session_id)?;
            limit(p.limit, 10000)?;
            if let Some(after) = &p.after_id {
                ulid(after)?;
            }
            let head = view_head(state, &p.session_id).await?;
            let path = state
                .store
                .event_path_at_bounded(head, p.after_id, p.limit, MAX_MESSAGE_BYTES)
                .await?;
            Ok(json!({"events":path.events,"truncated":path.truncated}))
        }
        "events.query" => {
            let p: Query = params(value)?;
            limit(p.limit, 500)?;
            if let Some(id) = &p.session_id {
                session_id(id)?;
            }
            let requested = p
                .session_id
                .clone()
                .or_else(|| state.identity.session_id.clone());
            let query = EventQuery {
                session_id: None,
                kinds: p.kinds.unwrap_or_default(),
                text: p.text,
                since_ms: p.since_ms,
                until_ms: p.until_ms,
                limit: p.limit,
            };
            let events = if let Some(session) = requested {
                let head = view_head(state, &session).await?;
                state
                    .store
                    .query_events_at_bounded(head, query, MAX_MESSAGE_BYTES)
                    .await?
            } else {
                state
                    .store
                    .query_events_bounded(query, MAX_MESSAGE_BYTES)
                    .await?
            };
            Ok(json!({"events":events}))
        }
        "sessions.get" => {
            let p: SessionId = params(value)?;
            session_id(&p.session_id)?;
            if state.identity.session_id.as_ref() != Some(&p.session_id) {
                return Err(RpcError::SCOPE);
            }
            serialize(state.store.session(p.session_id).await?)
        }
        "sessions.fork" => {
            let p: Fork = params(value)?;
            ulid(&p.from_event_id)?;
            if state.identity.session_id.is_none() {
                return Err(RpcError::SCOPE);
            }
            authorize_event(state, &p.from_event_id).await?;
            serialize(state.store.fork_session(p.from_event_id, p.title).await?)
        }
        "kv.get" => {
            let p: Key = params(value)?;
            Ok(json!({"value":state.store.kv_get(state.identity.namespace(),p.key).await?}))
        }
        "kv.set" => {
            let p: Set = params(value)?;
            state
                .store
                .kv_set(state.identity.namespace(), p.key, p.value)
                .await?;
            Ok(json!({}))
        }
        "kv.delete" => {
            let p: Key = params(value)?;
            state
                .store
                .kv_delete(state.identity.namespace(), p.key)
                .await?;
            Ok(json!({}))
        }
        "kv.list" => {
            let p: List = params(value)?;
            limit(p.limit, 10000)?;
            let items = state
                .store
                .kv_list_bounded(
                    state.identity.namespace(),
                    p.prefix.unwrap_or_default(),
                    p.limit.unwrap_or(1000),
                    MAX_MESSAGE_BYTES,
                )
                .await?
                .into_iter()
                .map(|(key, value)| json!({"key":key,"value":value}))
                .collect::<Vec<_>>();
            Ok(json!({"items":items}))
        }
        "blobs.put" => {
            let p: Put = params(value)?;
            let bytes = match (p.text, p.base64) {
                (Some(text), None) => text.into_bytes(),
                (None, Some(text)) => STANDARD.decode(text).map_err(|_| RpcError::INVALID)?,
                _ => return Err(RpcError::INVALID),
            };
            if bytes.len() > MAX_PUT_BYTES {
                return Err(RpcError::TOO_LARGE);
            }
            let size = bytes.len();
            let hash = state.store.put_blob(bytes).await?;
            Ok(json!({"hash":hash,"size":size}))
        }
        "blobs.get" => {
            let p: Hash = params(value)?;
            let bytes = state
                .store
                .get_blob_bounded(p.hash, MAX_MESSAGE_BYTES / 4 * 3)
                .await?;
            // Avoid constructing a base64 string that cannot fit the wire limit.
            if bytes.len().div_ceil(3) * 4 > MAX_MESSAGE_BYTES {
                return Err(RpcError::TOO_LARGE);
            }
            Ok(json!({"base64":STANDARD.encode(&bytes),"size":bytes.len()}))
        }
        "tools.list" => {
            let p: SessionId = params(value)?;
            session_id(&p.session_id)?;
            if state.identity.session_id.as_deref() != Some(&p.session_id) {
                return Err(RpcError::SCOPE);
            }
            state.store.session(p.session_id).await?;
            let home = state.home.clone();
            let tools =
                tokio::task::spawn_blocking(move || crate::gateway::registry::model_tools(&home))
                    .await
                    .map_err(|_| RpcError::INTERNAL)?
                    .map_err(|error| match error {
                        crate::gateway::registry::RegistryError::TooLarge => RpcError::TOO_LARGE,
                        _ => RpcError::INTERNAL,
                    })?;
            Ok(json!({"tools":tools}))
        }
        "catalog.list" => {
            let p: SessionId = params(value)?;
            session_id(&p.session_id)?;
            if state.identity.session_id.as_deref() != Some(&p.session_id) {
                return Err(RpcError::SCOPE);
            }
            state.store.session(p.session_id).await?;
            let home = state.home.clone();
            let catalog = tokio::task::spawn_blocking(move || super::catalog::list(&home))
                .await
                .map_err(|_| RpcError::INTERNAL)?
                .map_err(|error| match error {
                    super::catalog::CatalogError::TooLarge => RpcError::TOO_LARGE,
                    _ => RpcError::INTERNAL,
                })?;
            serialize(catalog)
        }
        "config.get" => {
            let p: Section = params(value)?;
            match p.section.as_str() {
                "ext" => {
                    let controls = state.controls.clone();
                    let ext = state.identity.ext_id.clone();
                    let table = tokio::task::spawn_blocking(move || {
                        Config::extension_from(&controls, &ext)
                    })
                    .await
                    .map_err(|_| RpcError::INTERNAL)?
                    .map_err(|error| match error {
                        crate::config::ConfigError::Control(error) => RpcError::from(error),
                        _ => RpcError::INTERNAL,
                    })?;
                    Ok(json!({"ext":table}))
                }
                "providers" => Ok(
                    json!({"providers":state.provider_ids.iter().map(|id|json!({"id":id,"url":format!("http://models.fictor.internal/p/{id}")})).collect::<Vec<_>>()}),
                ),
                "instructions" => {
                    let controls = state.controls.clone();
                    let text = tokio::task::spawn_blocking(move || controls.instructions())
                        .await
                        .map_err(|_| RpcError::INTERNAL)?
                        .map_err(RpcError::from)?;
                    Ok(json!({"instructions":text}))
                }
                _ => Err(RpcError::INVALID),
            }
        }
        // Routing services are deliberately unavailable until their real gateways
        // exist. Scope checks above happen before this response.
        _ => Err(RpcError::METHOD),
    }
}

fn serialize(value: impl serde::Serialize) -> Result<Value, RpcError> {
    serde_json::to_value(value).map_err(|_| RpcError::INTERNAL)
}
async fn authorize_event(state: &State, id: &str) -> Result<(), RpcError> {
    if let Some(own) = &state.identity.session_id
        && !state
            .store
            .event_in_lineage(own.clone(), id.to_owned())
            .await?
    {
        return Err(RpcError::SCOPE);
    }
    Ok(())
}
async fn view_head(state: &State, requested: &str) -> Result<Option<String>, RpcError> {
    let Some(own) = &state.identity.session_id else {
        return Ok(state.store.session(requested.to_owned()).await?.head_id);
    };
    let mut session = state.store.session(own.clone()).await?;
    if own == requested {
        return Ok(session.head_id);
    }
    // Parent/fork links are immutable core-owned columns. A parent's later head
    // is never used: this child retains its exact fork event cutoff.
    while let Some(parent) = session.parent_session_id {
        if parent == requested {
            return Ok(session.fork_event_id);
        }
        session = state.store.session(parent).await?;
    }
    Err(RpcError::SCOPE)
}
