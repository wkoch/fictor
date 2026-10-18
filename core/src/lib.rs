#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("Fictor supports only Linux x86-64 (Fedora COSMIC Atomic); see ADR-030.");

pub mod config;
pub mod doctor;
pub mod gateway;
pub mod home;
pub mod installer;
pub mod kernel;
pub mod proxy;
pub mod sandbox;
pub mod secrets;
pub mod store;
pub mod supervisor;

use std::path::Path;

/// Bootstrap only trusted core data. Bundle installation belongs to M0.5.
pub async fn initialize(home: &Path) -> Result<(), InitError> {
    home::prepare(home)?;
    config::Config::create_if_missing(home)?;
    let lease = std::sync::Arc::new(installer::lease::InstallerLease::acquire(home)?);
    let store = store::Store::open(home).await?;
    let store = std::sync::Arc::new(store);
    let report = installer::recovery::recover(home, store.clone(), lease).await?;
    for diagnostic in report.diagnostics {
        tracing::warn!(
            code = diagnostic.code.as_str(),
            proposal_id = diagnostic.proposal_id,
            "installer recovery diagnostic"
        );
    }
    // Recovery's owned worker has completed and released its Store reference.
    match std::sync::Arc::try_unwrap(store) {
        Ok(store) => store.shutdown().await?,
        Err(_) => return Err(InitError::Store(store::StoreError::Closed)),
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Config(#[from] config::ConfigError),
    #[error(transparent)]
    Store(#[from] store::StoreError),
    #[error(transparent)]
    Recovery(#[from] installer::recovery::RecoveryError),
}
