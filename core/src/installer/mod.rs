//! Phase-0 local receipt, validation and isolated checks. No automatic activation.
pub mod bundle;
pub mod local;
pub mod lock;
pub mod manifest;

pub use bundle::{
    BundleBudget, BundleFile, BundleProfile, Inspection, MAX_BUNDLE_BYTES, copy_local, inspect,
};

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("erro de arquivo do bundle: {0}")]
    Io(#[from] std::io::Error),
    #[error("bundle inválido: {0}")]
    Invalid(&'static str),
    #[error("limit:{0}")]
    Limit(&'static str),
    #[error("fonte do bundle mudou durante o recebimento")]
    SourceChanged,
}
