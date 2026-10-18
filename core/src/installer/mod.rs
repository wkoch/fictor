//! Phase-0 local receipt, validation and isolated checks. No automatic activation.
pub mod activation;
pub mod bundle;
pub mod cli;
pub mod control;
pub mod controls;
pub mod dependencies;
pub mod lease;
pub mod listing;
pub mod local;
pub mod lock;
pub mod manifest;
pub mod online;
pub mod overrides;
pub mod promotion;
pub mod publication;
pub mod recovery;
pub(crate) mod registries;

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

impl BundleError {
    /// Stable receipt audit codes; never persist library errors or source paths.
    pub fn receipt_reason(&self) -> &'static str {
        match self {
            Self::Limit("entries") => "limit:entries",
            Self::Limit("bytes") => "limit:bytes",
            Self::Limit("file_size") => "limit:file_size",
            Self::Limit("depth") => "limit:depth",
            Self::Limit("path_length") => "limit:path_length",
            Self::Limit("time") => "limit:time",
            Self::Invalid("symlink no bundle") => "receipt:symlink",
            Self::Invalid("entrada especial no bundle") => "receipt:special_file",
            Self::Invalid(_) => "receipt:invalid_path",
            Self::SourceChanged => "receipt:source_changed",
            Self::Io(_) | Self::Limit(_) => "receipt:io",
        }
    }
}
