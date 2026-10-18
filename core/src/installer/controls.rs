//! ADR-045 trusted administrative operations. Protocol parameters and backend
//! errors are never logged, including before a new secret can be masked.
use super::{
    activation::{ActivationError, PromotionCoordinator},
    lease::InstallerLease,
    listing::{self, ListingError},
    lock::{Lock, LockError},
    manifest::Scope,
};
use crate::{
    admin::{AdminMutationError, AdminMutationFuture, AdminMutationHandler, MutationReason},
    crash_recovery::{RecoveryScope, ResetCrashes},
    ownership::HomeLease,
    secrets::{Redactor, SecretError, SecretStore},
    store::{Store, StoreError},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

pub type PublicationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), MutationReason>> + Send + 'a>>;
pub trait ControlPublication: super::publication::PromotionPublication {
    /// This block remains in force on any uncertain persistence/publication.
    fn block_admissions(&self, ext_id: &str) -> Result<(), MutationReason>;
    fn publish_enabled<'a>(
        &'a self,
        ext_id: &'a str,
        key: &'a str,
        enabled: bool,
    ) -> PublicationFuture<'a>;
    fn publish_reset<'a>(&'a self, selection: &'a ResetCrashes) -> PublicationFuture<'a>;
}

#[derive(Clone)]
pub struct AdminControlService {
    store: Arc<Store>,
    secrets: SecretStore,
    coordinator: PromotionCoordinator,
    publication: Option<Arc<dyn ControlPublication>>,
}
impl AdminControlService {
    /// None explicitly offers only secret operations until a real supervisor
    /// publication implementation is supplied; it never pretends to update one.
    pub fn new(
        store: Arc<Store>,
        secrets: SecretStore,
        coordinator: PromotionCoordinator,
        publication: Option<Arc<dyn ControlPublication>>,
    ) -> Self {
        // Reconciliation may finish a different, already durable operation.
        // It must publish through the same live registry as this command.
        let coordinator = if let Some(publication) = &publication {
            coordinator.using_publication(publication.clone())
        } else {
            coordinator
        };
        Self {
            store,
            secrets,
            coordinator,
            publication,
        }
    }
    pub async fn call(&self, method: &str, params: &Value) -> Result<Value, AdminMutationError> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        if !crate::admin::valid_method_params(method, params) {
            return Err(AdminMutationError::none(MutationReason::InvalidState));
        }
        let service = self.clone();
        let method = method.to_owned();
        let params = params.clone();
        tokio::spawn(async move { service.call_owned(&method, &params, deadline).await })
            .await
            .map_err(|_| AdminMutationError::unknown(MutationReason::IoError))?
    }
    async fn call_owned(
        &self,
        method: &str,
        params: &Value,
        deadline: tokio::time::Instant,
    ) -> Result<Value, AdminMutationError> {
        let request = parse(method, params)?;
        // Dropping a timed-out acquisition removes its waiter; no writer task
        // or backend operation is queued before this succeeds.
        if tokio::time::Instant::now() >= deadline {
            return Err(AdminMutationError::none(MutationReason::Busy));
        }
        let _gate = tokio::select! {biased;
            _=tokio::time::sleep_until(deadline)=>return Err(AdminMutationError::none(MutationReason::Busy)),
            guard=self.store.owner().installer_gate().lock_owned()=>guard,
        };
        if tokio::time::Instant::now() >= deadline {
            return Err(AdminMutationError::none(MutationReason::Busy));
        }
        if !matches!(request, ControlRequest::List) {
            self.coordinator
                .reconcile_locked()
                .await
                .map_err(reconciliation)?;
        }
        match request {
            ControlRequest::Enabled(request) => self.set_enabled(request).await,
            ControlRequest::Reset(request) => self.reset(request).await,
            ControlRequest::List => {
                let secrets = self.secrets.clone();
                let names = tokio::task::spawn_blocking(move || secrets.list())
                    .await
                    .map_err(|_| AdminMutationError::none(MutationReason::BackendUnavailable))?
                    .map_err(|_| AdminMutationError::none(MutationReason::BackendUnavailable))?;
                Ok(json!({"schema":1,"names":names}))
            }
            ControlRequest::Set(request) => {
                let secrets = self.secrets.clone();
                tokio::task::spawn_blocking(move || {
                    // Backend masking may itself fail after a durable rename;
                    // only this explicit registration proves a pre-write error.
                    secrets.redactor().register(&request.value).map_err(|_| {
                        AdminMutationError::none(MutationReason::BackendUnavailable)
                    })?;
                    secrets
                        .set(&request.name, &request.value)
                        .map_err(secret_mutation)
                })
                .await
                .map_err(|_| AdminMutationError::unknown(MutationReason::BackendUnavailable))??;
                Ok(json!({"schema":1,"name":params["name"]}))
            }
            ControlRequest::Remove(request) => {
                let secrets = self.secrets.clone();
                let name = request.name.clone();
                let removed = tokio::task::spawn_blocking(move || match secrets.remove(&name) {
                    Ok(()) => Ok(true),
                    Err(SecretError::NotFound) => Ok(false),
                    Err(error) => Err(error),
                })
                .await
                .map_err(|_| AdminMutationError::unknown(MutationReason::BackendUnavailable))?
                .map_err(secret_mutation)?;
                Ok(json!({"schema":1,"name":request.name,"removed":removed}))
            }
        }
    }
    async fn set_enabled(&self, request: Enabled) -> Result<Value, AdminMutationError> {
        let publication = self
            .publication
            .as_ref()
            .ok_or_else(|| AdminMutationError::none(MutationReason::InvalidState))?;
        let owner = self.store.owner().clone();
        let ext_id = request.ext_id.clone();
        let (mut lock, key, changed) = tokio::task::spawn_blocking(move || {
            owner
                .verify()
                .map_err(|_| AdminMutationError::none(MutationReason::InvalidSnapshot))?;
            let lock = Lock::load_required(owner.home()).map_err(lock_read)?;
            let extension = lock
                .extensions
                .get(&ext_id)
                .ok_or_else(|| AdminMutationError::none(MutationReason::NotFound))?;
            let key = extension.active.clone();
            let changed = extension.enabled != request.enabled;
            Ok::<_, AdminMutationError>((lock, key, changed))
        })
        .await
        .map_err(|_| AdminMutationError::none(MutationReason::IoError))??;
        let result = json!({"schema":1,"ext_id":request.ext_id,"key":key,"enabled":request.enabled,"changed":changed});
        crate::admin::bounded_json(&result)
            .map_err(|_| AdminMutationError::none(MutationReason::TooLarge))?;
        publication
            .block_admissions(&request.ext_id)
            .map_err(AdminMutationError::none)?;
        let extension = lock
            .extensions
            .get_mut(&request.ext_id)
            .ok_or_else(|| AdminMutationError::none(MutationReason::InvalidSnapshot))?;
        extension.enabled = request.enabled;
        let owner = self.store.owner().clone();
        tokio::task::spawn_blocking(move || {
            owner
                .verify()
                .map_err(|_| AdminMutationError::none(MutationReason::InvalidSnapshot))?;
            if changed {
                lock.write_atomic(owner.home())
            } else {
                Lock::sync_snapshot(owner.home())
            }
            .map_err(|_| AdminMutationError::unknown(MutationReason::IoError))
        })
        .await
        .map_err(|_| AdminMutationError::unknown(MutationReason::IoError))??;
        publication
            .publish_enabled(&request.ext_id, &key, request.enabled)
            .await
            .map_err(AdminMutationError::committed)?;
        Ok(result)
    }
    async fn reset(&self, request: Reset) -> Result<Value, AdminMutationError> {
        let publication = self
            .publication
            .as_ref()
            .ok_or_else(|| AdminMutationError::none(MutationReason::InvalidState))?;
        let owner = self.store.owner().clone();
        let selection_request = request;
        let selection = tokio::task::spawn_blocking(move || {
            owner
                .verify()
                .map_err(|_| AdminMutationError::none(MutationReason::InvalidSnapshot))?;
            let lock = Lock::load_required(owner.home()).map_err(lock_read)?;
            let extension = lock
                .extensions
                .get(&selection_request.ext_id)
                .ok_or_else(|| AdminMutationError::none(MutationReason::NotFound))?;
            let key = selection_request
                .key
                .unwrap_or_else(|| extension.active.clone());
            let version = extension
                .versions
                .get(&key)
                .ok_or_else(|| AdminMutationError::none(MutationReason::NotFound))?;
            let effective = crate::gateway::registry::active_manifest(
                owner.home(),
                &selection_request.ext_id,
                version,
            )
            .map_err(|_| AdminMutationError::none(MutationReason::IntegrityFailed))?;
            let scope = if effective.manifest().scope == Scope::Global {
                RecoveryScope::Global
            } else {
                RecoveryScope::Session
            };
            if scope == RecoveryScope::Global && selection_request.session_id.is_some() {
                return Err(AdminMutationError::none(MutationReason::InvalidState));
            }
            Ok::<_, AdminMutationError>(ResetCrashes {
                ext_id: selection_request.ext_id,
                key,
                scope,
                session_id: selection_request.session_id,
            })
        })
        .await
        .map_err(|_| AdminMutationError::none(MutationReason::IoError))??;
        if let Some(session) = &selection.session_id {
            self.store
                .session(session.clone())
                .await
                .map_err(store_before)?;
        }
        let mut result = json!({"schema":1,"ext_id":selection.ext_id,"key":selection.key,"session_id":selection.session_id,"cleared":u64::MAX});
        crate::admin::bounded_json(&result)
            .map_err(|_| AdminMutationError::none(MutationReason::TooLarge))?;
        publication
            .block_admissions(&selection.ext_id)
            .map_err(AdminMutationError::none)?;
        let timestamp = crate::store::now_ms().map_err(store_before)?;
        let reset = self
            .store
            .reset_crashes(selection.clone(), timestamp)
            .await
            .map_err(store_mutation)?;
        publication
            .publish_reset(&selection)
            .await
            .map_err(AdminMutationError::committed)?;
        result["cleared"] = json!(reset.cleared);
        Ok(result)
    }
}
impl AdminMutationHandler for AdminControlService {
    fn call_mutation<'a>(&'a self, method: &'a str, params: &'a Value) -> AdminMutationFuture<'a> {
        Box::pin(self.call(method, params))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enabled {
    ext_id: String,
    enabled: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reset {
    ext_id: String,
    #[serde(default, deserialize_with = "non_null")]
    key: Option<String>,
    #[serde(default, deserialize_with = "non_null")]
    session_id: Option<String>,
}
fn non_null<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Set {
    name: String,
    value: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Remove {
    name: String,
}
enum ControlRequest {
    Enabled(Enabled),
    Reset(Reset),
    List,
    Set(Set),
    Remove(Remove),
}
fn parse(method: &str, params: &Value) -> Result<ControlRequest, AdminMutationError> {
    let invalid = || AdminMutationError::none(MutationReason::InvalidState);
    let request = match method {
        "ext.set_enabled" => {
            ControlRequest::Enabled(serde_json::from_value(params.clone()).map_err(|_| invalid())?)
        }
        "ext.reset_crashes" => {
            ControlRequest::Reset(serde_json::from_value(params.clone()).map_err(|_| invalid())?)
        }
        "secrets.list" if params.as_object().is_some_and(|params| params.is_empty()) => {
            ControlRequest::List
        }
        "secrets.set" => {
            ControlRequest::Set(serde_json::from_value(params.clone()).map_err(|_| invalid())?)
        }
        "secrets.rm" => {
            ControlRequest::Remove(serde_json::from_value(params.clone()).map_err(|_| invalid())?)
        }
        _ => return Err(invalid()),
    };
    Ok(request)
}
fn lock_read(error: LockError) -> AdminMutationError {
    AdminMutationError::none(match error {
        LockError::Io(error) if error.kind() == std::io::ErrorKind::NotFound => {
            MutationReason::NotInitialized
        }
        LockError::Busy => MutationReason::Busy,
        _ => MutationReason::InvalidSnapshot,
    })
}
fn store_before(error: StoreError) -> AdminMutationError {
    AdminMutationError::none(match error {
        StoreError::NotFound => MutationReason::NotFound,
        _ => MutationReason::IoError,
    })
}
fn store_mutation(error: StoreError) -> AdminMutationError {
    match error {
        StoreError::NotFound => AdminMutationError::none(MutationReason::NotFound),
        StoreError::Invalid(_) => AdminMutationError::none(MutationReason::InvalidSnapshot),
        _ => AdminMutationError::unknown(MutationReason::IoError),
    }
}
fn reconciliation(error: ActivationError) -> AdminMutationError {
    AdminMutationError::none(match error {
        ActivationError::Busy => MutationReason::Busy,
        ActivationError::RecoveryConflict => MutationReason::RecoveryRequired,
        ActivationError::Integrity => MutationReason::IntegrityFailed,
        _ => MutationReason::IoError,
    })
}
fn secret_mutation(error: SecretError) -> AdminMutationError {
    match error {
        SecretError::InvalidName | SecretError::InvalidValue => {
            AdminMutationError::none(MutationReason::BackendUnavailable)
        }
        _ => AdminMutationError::unknown(MutationReason::BackendUnavailable),
    }
}

/// A separate owner has no current manager/cache to publish. Recovery does not
/// imply that every retained predecessor sandbox has already exited.
struct OfflinePublication;
impl super::publication::PromotionPublication for OfflinePublication {
    fn block_before_lock(&self, _: &str) -> Result<(), MutationReason> {
        Ok(())
    }
    fn publish_after_commit<'a>(
        &'a self,
        _: &'a crate::store::PromotionIntent,
    ) -> super::publication::PromotionPublicationFuture<'a> {
        Box::pin(async { Ok(()) })
    }
    fn reconcile<'a>(
        &'a self,
        _: &'a crate::store::PromotionIntent,
    ) -> super::publication::PromotionPublicationFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}
impl ControlPublication for OfflinePublication {
    fn block_admissions(&self, _: &str) -> Result<(), MutationReason> {
        Ok(())
    }
    fn publish_enabled<'a>(&'a self, _: &'a str, _: &'a str, _: bool) -> PublicationFuture<'a> {
        Box::pin(async { Ok(()) })
    }
    fn publish_reset<'a>(&'a self, _: &'a ResetCrashes) -> PublicationFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

pub struct OfflineContext {
    service: AdminControlService,
}
impl OfflineContext {
    pub async fn open(
        owner: Arc<HomeLease>,
        redactor: Redactor,
    ) -> Result<Self, AdminMutationError> {
        tokio::spawn(async move { Self::open_owned(owner, redactor).await })
            .await
            .map_err(|_| AdminMutationError::none(MutationReason::IoError))?
    }
    async fn open_owned(
        owner: Arc<HomeLease>,
        redactor: Redactor,
    ) -> Result<Self, AdminMutationError> {
        let _gate = owner.installer_gate().lock_owned().await;
        let pre_owner = owner.clone();
        tokio::task::spawn_blocking(move || {
            listing::preflight_owned(pre_owner, true)
                .map_err(|error| AdminMutationError::none(error.into()))?;
            Ok(())
        })
        .await
        .map_err(|_| AdminMutationError::none(MutationReason::IoError))??;
        let store = Arc::new(
            Store::open_existing_with_lease(owner.clone())
                .await
                .map_err(|error| {
                    AdminMutationError::none(match error {
                        StoreError::ExistingSchema(_) => MutationReason::DataVersionUnsupported,
                        _ => MutationReason::IoError,
                    })
                })?,
        );
        let lease = Arc::new(
            InstallerLease::acquire(owner.home())
                .map_err(|_| AdminMutationError::none(MutationReason::Busy))?,
        );
        let report = crate::instance_recovery::recover_locked(store.clone())
            .await
            .map_err(|_| AdminMutationError::none(MutationReason::RecoveryRequired))?;
        for diagnostic in report.diagnostics {
            tracing::warn!(code=?diagnostic.code,instance_id=diagnostic.instance_id,"offline control retained instance resources");
        }
        let coordinator = PromotionCoordinator::new_offline(store.clone(), lease);
        coordinator
            .reconcile_locked()
            .await
            .map_err(reconciliation)?;
        let config = crate::config::Config::load(owner.home())
            .map_err(|_| AdminMutationError::none(MutationReason::InvalidSnapshot))?;
        let secrets = SecretStore::open_with_lease(owner, config.secrets.backend, redactor)
            .map_err(|_| AdminMutationError::none(MutationReason::BackendUnavailable))?;
        Ok(Self {
            service: AdminControlService::new(
                store,
                secrets,
                coordinator,
                Some(Arc::new(OfflinePublication)),
            ),
        })
    }
    pub async fn call(&self, method: &str, params: &Value) -> Result<Value, AdminMutationError> {
        self.service.call(method, params).await
    }
}
impl From<ListingError> for MutationReason {
    fn from(error: ListingError) -> Self {
        match error {
            ListingError::NotInitialized => Self::NotInitialized,
            ListingError::DataVersionUnsupported => Self::DataVersionUnsupported,
            ListingError::RecoveryRequired => Self::RecoveryRequired,
            ListingError::InvalidSnapshot => Self::InvalidSnapshot,
            ListingError::Busy => Self::Busy,
            ListingError::IoError => Self::IoError,
            ListingError::TooLarge => Self::TooLarge,
        }
    }
}
