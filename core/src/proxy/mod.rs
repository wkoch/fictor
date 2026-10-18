//! Authenticated egress transport. The supervisor registers trusted identities.
pub mod allowlist;
pub mod egress;
pub mod model_proxy;
pub mod models;
pub mod nat64;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Body = http_body_util::combinators::BoxBody<bytes::Bytes, BoxError>;

pub use egress::{EgressProxy, ProxyIdentity, ProxyToken};

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("proxy I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("proxy audit failed: {0}")]
    Store(#[from] crate::store::StoreError),
    #[error("invalid proxy configuration: {0}")]
    Invalid(&'static str),
    #[error("invalid egress allowlist: {0}")]
    Allowlist(#[from] allowlist::AllowlistError),
    #[error("secure proxy token generation failed")]
    Random,
    #[error("proxy is closed")]
    Closed,
    #[error("proxy task failed")]
    Task,
}
