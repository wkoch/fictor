//! Authenticated per-instance Kernel Protocol. Identity is trusted supervisor
//! input, sealed at bind; request fields can never change it.
mod catalog;
mod dispatch;
mod log;
mod transport;
pub use log::{LogFuture, LogLevel, LogRecord, LogSink};
pub use transport::KernelServer;

use crate::store::{Store, StoreError};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};

pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PUT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone)]
pub struct KernelIdentity {
    pub ext_id: String,
    pub instance_id: String,
    pub session_id: Option<String>,
    pub is_harness: bool,
    pub scopes: BTreeSet<String>,
}
impl KernelIdentity {
    fn validate(&self) -> Result<(), KernelError> {
        let valid_ext = !self.ext_id.is_empty()
            && self.ext_id.len() <= 40
            && self.ext_id.as_bytes()[0].is_ascii_lowercase()
            && self.ext_id.split('-').all(|part| {
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            });
        if !valid_ext
            || !valid_ulid(&self.instance_id)
            || self.scopes.is_empty()
            || self.session_id.as_ref().is_some_and(|id| !valid_ulid(id))
            || self
                .scopes
                .iter()
                .any(|scope| !SCOPES.contains(&scope.as_str()))
        {
            return Err(KernelError::Invalid);
        }
        if self.session_id.is_none()
            && (self.is_harness
                || self
                    .scopes
                    .iter()
                    .any(|s| matches!(s.as_str(), "sessions" | "tools" | "hooks")))
        {
            return Err(KernelError::Invalid);
        }
        Ok(())
    }
    fn namespace(&self) -> String {
        match &self.session_id {
            Some(session) => format!("{}@{session}", self.ext_id),
            None => self.ext_id.clone(),
        }
    }
}
const SCOPES: &[&str] = &[
    "events.read",
    "events.write",
    "sessions",
    "sessions.input",
    "blobs",
    "kv",
    "tools",
    "hooks",
    "catalog",
    "ui",
    "timers",
    "ext.propose",
    "config",
    "approval",
];
fn valid_ulid(id: &str) -> bool {
    id.len() == 26 && id.parse::<ulid::Ulid>().is_ok()
}

#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    #[error(transparent)]
    Control(#[from] crate::control_files::ControlError),
    #[error("invalid kernel instance identity or path")]
    Invalid,
    #[error("kernel socket unavailable")]
    Io(#[from] std::io::Error),
    #[error("kernel randomness unavailable")]
    Random,
    #[error("kernel store unavailable")]
    Store(#[from] StoreError),
    #[error("kernel task unavailable")]
    Task,
    #[error("kernel log unavailable")]
    Log,
}
struct State {
    identity: KernelIdentity,
    token: String, // Deliberately no Debug/Serialize implementation on State or KernelServer.
    revoked: AtomicBool,
    home: PathBuf,
    controls: Arc<crate::control_files::ControlFiles>,
    store: Arc<Store>,
    provider_ids: Vec<String>,
    log: Option<Arc<dyn LogSink>>,
}

#[derive(Clone, Copy, Debug)]
struct RpcError {
    code: i32,
    message: &'static str,
    control: Option<crate::control_files::ControlError>,
}
impl RpcError {
    const INVALID: Self = Self::new(-32602, "INVALID_PARAMS");
    const AUTH: Self = Self::new(-32001, "UNAUTHENTICATED");
    const SCOPE: Self = Self::new(-32002, "SCOPE_DENIED");
    const NOT_FOUND: Self = Self::new(-32006, "NOT_FOUND");
    const TOO_LARGE: Self = Self::new(-32010, "TOO_LARGE");
    const METHOD: Self = Self::new(-32601, "METHOD_NOT_FOUND");
    const INTERNAL: Self = Self::new(-32603, "INTERNAL_ERROR");
    const fn new(code: i32, message: &'static str) -> Self {
        Self {
            code,
            message,
            control: None,
        }
    }
    fn value(self) -> Value {
        let mut value = json!({"code":self.code,"message":self.message});
        if let Some(control) = self.control {
            // ADR-042 requires a logical filename alongside its normative
            // reason. Never include a filesystem path, target or raw content.
            value["data"] = json!({"reason":control.reason(),"file":control.name()});
        }
        value
    }
}
impl From<crate::control_files::ControlError> for RpcError {
    fn from(error: crate::control_files::ControlError) -> Self {
        if error.failure() == crate::control_files::Failure::TooLarge {
            return Self::TOO_LARGE;
        }
        Self {
            control: Some(error),
            ..Self::INTERNAL
        }
    }
}
impl From<StoreError> for RpcError {
    fn from(error: StoreError) -> Self {
        use crate::store::blobs::BlobError;
        match error {
            StoreError::NotFound => Self::NOT_FOUND,
            StoreError::Blob(BlobError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                Self::NOT_FOUND
            }
            StoreError::HeadMoved => Self::new(-32005, "HEAD_MOVED"),
            StoreError::Invalid(_) | StoreError::Blob(BlobError::InvalidHash) => Self::INVALID,
            StoreError::TooLarge | StoreError::Blob(BlobError::TooLarge) => Self::TOO_LARGE,
            _ => Self::INTERNAL,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    jsonrpc: String,
    #[serde(default, deserialize_with = "present_id")]
    id: Option<Value>,
    method: String,
    #[serde(default = "empty_params")]
    params: Value,
}
fn present_id<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}
fn empty_params() -> Value {
    json!({})
}
fn params<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, RpcError> {
    serde_json::from_value(value).map_err(|_| RpcError::INVALID)
}
