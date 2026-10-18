//! The scope-free `log` notification, accepted only after kernel authentication.
use super::KernelError;
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use std::{future::Future, pin::Pin};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}
impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

// No Debug: records may contain credentials before the supervisor redacts them.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogRecord {
    pub level: LogLevel,
    pub message: String,
    #[serde(default, deserialize_with = "fields")]
    pub fields: Option<Map<String, Value>>,
}
fn fields<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Map<String, Value>>, D::Error> {
    Map::deserialize(deserializer).map(Some)
}

pub type LogFuture = Pin<Box<dyn Future<Output = Result<(), KernelError>> + Send>>;

/// Trusted supervisor sink. The endpoint never selects a filename from params.
/// The owner must redact credentials before storing the record.
pub trait LogSink: Send + Sync {
    fn write(&self, record: LogRecord) -> LogFuture;
}
