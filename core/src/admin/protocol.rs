use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{future::Future, pin::Pin};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    None,
    Committed,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum MutationReason {
    #[error("not_initialized")]
    NotInitialized,
    #[error("data_version_unsupported")]
    DataVersionUnsupported,
    #[error("recovery_required")]
    RecoveryRequired,
    #[error("invalid_snapshot")]
    InvalidSnapshot,
    #[error("busy")]
    Busy,
    #[error("io_error")]
    IoError,
    #[error("too_large")]
    TooLarge,
    #[error("not_found")]
    NotFound,
    #[error("invalid_state")]
    InvalidState,
    #[error("stale_base")]
    StaleBase,
    #[error("invalid_nonce")]
    InvalidNonce,
    #[error("review_mismatch")]
    ReviewMismatch,
    #[error("invalid_overrides")]
    InvalidOverrides,
    #[error("integrity_failed")]
    IntegrityFailed,
    #[error("backend_unavailable")]
    BackendUnavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(deny_unknown_fields)]
#[error("administrative operation failed: {reason} ({effect:?})")]
pub struct AdminMutationError {
    pub reason: MutationReason,
    pub effect: Effect,
}
impl AdminMutationError {
    pub fn none(reason: MutationReason) -> Self {
        Self {
            reason,
            effect: Effect::None,
        }
    }
    pub fn committed(reason: MutationReason) -> Self {
        Self {
            reason,
            effect: Effect::Committed,
        }
    }
    pub fn unknown(reason: MutationReason) -> Self {
        Self {
            reason,
            effect: Effect::Unknown,
        }
    }
}
pub type AdminMutationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Value, AdminMutationError>> + Send + 'a>>;
/// Only trusted core services implement this interface. Transport validates the
/// closed method list and parameter shapes before admitting a service call.
pub trait AdminMutationHandler: Send + Sync {
    fn call_mutation<'a>(&'a self, method: &'a str, params: &'a Value) -> AdminMutationFuture<'a>;
}
#[derive(Debug, thiserror::Error)]
pub enum AdminClientError {
    #[error("administrative operation failed: {0}")]
    Domain(#[from] AdminMutationError),
    #[error("admin transport failed ({effect:?})")]
    Transport { effect: Effect },
    #[error("admin identity check failed")]
    Identity,
    #[error("invalid admin response ({effect:?})")]
    Protocol { effect: Effect },
}
impl AdminClientError {
    pub fn effect(&self) -> Effect {
        match self {
            Self::Domain(error) => error.effect,
            Self::Transport { effect } | Self::Protocol { effect } => *effect,
            Self::Identity => Effect::None,
        }
    }
}

pub(super) const CONTROLS: &[&str] = &[
    "ext.set_enabled",
    "ext.reset_crashes",
    "secrets.list",
    "secrets.set",
    "secrets.rm",
];
pub(super) const INSTALL: &[&str] = &[
    "ext.install.prepare",
    "ext.install.status",
    "ext.install.decision",
    "ext.install.promote",
];

pub(super) fn valid_params(method: &str, params: &serde_json::Map<String, Value>) -> bool {
    let string = |name: &str| {
        params
            .get(name)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
    };
    let optional_string = |name: &str| !params.contains_key(name) || string(name);
    let field = |name: &str, test: fn(&str) -> bool| {
        params.get(name).and_then(Value::as_str).is_some_and(test)
    };
    let exact = |required: &[&str], optional: &[&str]| {
        required.iter().all(|name| params.contains_key(*name))
            && params
                .keys()
                .all(|name| required.contains(&name.as_str()) || optional.contains(&name.as_str()))
    };
    match method {
        "ext.list" | "secrets.list" => params.is_empty(),
        "ext.set_enabled" => {
            exact(&["ext_id", "enabled"], &[])
                && field("ext_id", valid_ext_id)
                && params["enabled"].is_boolean()
        }
        "ext.reset_crashes" => {
            exact(&["ext_id"], &["key", "session_id"])
                && field("ext_id", valid_ext_id)
                && optional_string("key")
                && optional_string("session_id")
                && (!params.contains_key("key") || field("key", valid_key))
                && (!params.contains_key("session_id") || field("session_id", valid_ulid))
        }
        "secrets.set" => {
            exact(&["name", "value"], &[]) && field("name", valid_secret_name) && string("value")
        }
        "secrets.rm" => exact(&["name"], &[]) && field("name", valid_secret_name),
        "ext.install.prepare" => {
            exact(&["path"], &[])
                && params
                    .get("path")
                    .and_then(Value::as_str)
                    .is_some_and(|path| {
                        std::path::Path::new(path).is_absolute() && !path.contains('\0')
                    })
        }
        "ext.install.status" => {
            exact(&["proposal_id"], &["overrides"])
                && field("proposal_id", valid_ulid)
                && params.get("overrides").is_none_or(Value::is_object)
        }
        "ext.install.promote" => exact(&["proposal_id"], &[]) && field("proposal_id", valid_ulid),
        "ext.install.decision" => {
            exact(
                &[
                    "proposal_id",
                    "nonce",
                    "review_hash",
                    "decision",
                    "overrides",
                ],
                &[],
            ) && field("proposal_id", valid_ulid)
                && field("nonce", |value| lower_hex(value, 64))
                && field("review_hash", |value| {
                    value
                        .strip_prefix("sha256:")
                        .is_some_and(|value| lower_hex(value, 64))
                })
                && matches!(
                    params.get("decision").and_then(Value::as_str),
                    Some("approve" | "reject")
                )
                && params["overrides"].is_object()
        }
        _ => false,
    }
}
fn valid_ulid(value: &str) -> bool {
    value
        .parse::<ulid::Ulid>()
        .is_ok_and(|id| id.to_string() == value)
}
fn valid_ext_id(value: &str) -> bool {
    value.len() <= 40
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}
fn valid_secret_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}
fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn valid_key(value: &str) -> bool {
    static VERSION: std::sync::OnceLock<Option<jsonschema::Validator>> = std::sync::OnceLock::new();
    let Some((version, hash)) = value.rsplit_once('-') else {
        return false;
    };
    lower_hex(hash, 12)
        && VERSION
            .get_or_init(|| {
                let schema: Value = serde_json::from_str(include_str!(
                    "../../../spec/schemas/extension.schema.json"
                ))
                .ok()?;
                jsonschema::options()
                    .offline()
                    .build(&schema["properties"]["version"])
                    .ok()
            })
            .as_ref()
            .is_some_and(|validator| validator.is_valid(&Value::String(version.into())))
}
