#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("Fictor supports only Linux x86-64 (Fedora COSMIC Atomic); see ADR-030.");

pub mod admin;
pub mod config;
pub mod control_files;
pub mod crash_recovery;
pub mod doctor;
pub mod gateway;
pub mod home;
pub mod installer;
pub mod instance_recovery;
pub mod kernel;
pub mod ownership;
pub mod policy;
pub mod proxy;
pub mod sandbox;
pub mod secrets;
pub mod store;
mod strict_json;
pub mod supervisor;

use std::path::Path;

/// Bootstrap only trusted core data. Bundle installation belongs to M0.5.
pub async fn initialize(home: &Path) -> Result<(), InitError> {
    let owner = ownership::HomeLease::create_for_init(home)?;
    initialize_owned(owner).await
}

/// Reuse a caller's owner through initialization and subsequent offline work.
pub async fn initialize_owned(
    owner: std::sync::Arc<ownership::HomeLease>,
) -> Result<(), InitError> {
    tokio::spawn(initialize_worker(owner))
        .await
        .map_err(|_| InitError::Worker)?
}

async fn initialize_worker(owner: std::sync::Arc<ownership::HomeLease>) -> Result<(), InitError> {
    owner.verify()?;
    let _section = owner.installer_gate().lock_owned().await;
    let home = owner.home();
    // An existing home's lost lock is never reconstructed from config/SQLite.
    // A genuinely new home has none of the persisted initialization markers.
    let fresh = ["config.toml", "fictor.db", "extensions"].iter().all(|name| {
        matches!(std::fs::symlink_metadata(home.join(name)), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    });
    if !fresh {
        config::Config::load(home)?;
        installer::lock::Lock::load_required(home)?;
    }
    home::prepare(home)?;
    config::Config::create_if_missing(home)?;
    if fresh {
        installer::lock::Lock::initialize_empty(home)?;
    }
    let lease = std::sync::Arc::new(installer::lease::InstallerLease::acquire(home)?);
    let store = store::Store::open_with_lease(owner.clone()).await?;
    let store = std::sync::Arc::new(store);
    // Resource ownership is resolved before any installer recovery can reclaim
    // bytes. Retained/uncertain instances are diagnosed rather than signalled.
    let instances = instance_recovery::recover_locked(store.clone()).await?;
    if instances.legacy.pid_files {
        tracing::warn!("legacy PID files retained; they cannot authorize signalling or cleanup");
    }
    if instances.legacy.temporaries {
        tracing::warn!("legacy temporary resources retained without ownership records");
    }
    if instances.legacy.scan_unavailable {
        tracing::warn!("legacy resource scan incomplete; no legacy cleanup attempted");
    }
    for diagnostic in instances.diagnostics {
        tracing::warn!(
            code = ?diagnostic.code,
            instance_id = diagnostic.instance_id,
            "instance recovery retained resources"
        );
    }
    installer::activation::PromotionCoordinator::new_offline(store.clone(), lease.clone())
        .reconcile_locked()
        .await?;
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
    Instance(#[from] instance_recovery::InstanceError),
    #[error(transparent)]
    Activation(#[from] installer::activation::ActivationError),
    #[error("initialization worker unavailable")]
    Worker,
    #[error(transparent)]
    Lock(#[from] installer::lock::LockError),
    #[error(transparent)]
    Ownership(#[from] ownership::OwnershipError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Config(#[from] config::ConfigError),
    #[error(transparent)]
    Store(#[from] store::StoreError),
    #[error(transparent)]
    Recovery(#[from] installer::recovery::RecoveryError),
}
