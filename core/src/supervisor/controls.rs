//! Admission publication for existing supervisors; no process is started here.
use crate::{
    admin::MutationReason,
    crash_recovery::ResetCrashes,
    gateway::admission::InstanceAdmission,
    installer::{
        controls::{ControlPublication, PublicationFuture},
        lock::Lock,
        publication::{PromotionPublication, PromotionPublicationFuture},
    },
    ownership::HomeLease,
    store::{PromotionIntent, PromotionState},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};
use tokio::sync::watch;

struct Live {
    ext_id: String,
    key: Option<String>,
    admission: Option<InstanceAdmission>,
    stop: watch::Sender<bool>,
}
#[derive(Default)]
struct State {
    blocked: BTreeSet<String>,
    publishing: BTreeSet<String>,
    live: BTreeMap<String, Live>,
}
struct Inner {
    owner: Arc<HomeLease>,
    state: Mutex<State>,
}
#[derive(Clone)]
pub struct ControlRegistry(Arc<Inner>);
impl ControlRegistry {
    pub fn new(owner: Arc<HomeLease>) -> Self {
        Self(Arc::new(Inner {
            owner,
            state: Mutex::new(State::default()),
        }))
    }
    /// Caller holds the installer's gate through the spawn/register sequence.
    pub fn allow(&self, ext_id: &str) -> Result<(), MutationReason> {
        self.allow_inner(ext_id, None)
    }
    pub(crate) fn publication_ready(&self, ext_id: &str) -> Result<bool, MutationReason> {
        Ok(!self
            .0
            .state
            .lock()
            .map_err(|_| MutationReason::InvalidState)?
            .publishing
            .contains(ext_id))
    }
    pub(crate) fn allow_version(&self, ext_id: &str, key: &str) -> Result<(), MutationReason> {
        self.allow_inner(ext_id, Some(key))
    }
    fn allow_inner(&self, ext_id: &str, key: Option<&str>) -> Result<(), MutationReason> {
        if self
            .0
            .state
            .lock()
            .map_err(|_| MutationReason::InvalidState)?
            .blocked
            .contains(ext_id)
        {
            return Err(MutationReason::InvalidState);
        }
        self.0
            .owner
            .verify()
            .map_err(|_| MutationReason::InvalidSnapshot)?;
        let lock = Lock::load_required(self.0.owner.home())
            .map_err(|_| MutationReason::InvalidSnapshot)?;
        if lock.extensions.get(ext_id).is_some_and(|extension| {
            !extension.enabled || key.is_some_and(|key| key != extension.active)
        }) {
            return Err(MutationReason::InvalidState);
        }
        Ok(())
    }
    pub fn register(
        &self,
        ext_id: &str,
        instance_id: &str,
        stop: watch::Sender<bool>,
    ) -> Result<InstanceControlRegistration, MutationReason> {
        self.register_inner(ext_id, None, instance_id, stop, None)
    }
    pub(crate) fn register_version(
        &self,
        ext_id: &str,
        key: &str,
        instance_id: &str,
        stop: watch::Sender<bool>,
        admission: InstanceAdmission,
    ) -> Result<InstanceControlRegistration, MutationReason> {
        self.register_inner(ext_id, Some(key), instance_id, stop, Some(admission))
    }
    fn register_inner(
        &self,
        ext_id: &str,
        key: Option<&str>,
        instance_id: &str,
        stop: watch::Sender<bool>,
        admission: Option<InstanceAdmission>,
    ) -> Result<InstanceControlRegistration, MutationReason> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| MutationReason::InvalidState)?;
        if state.blocked.contains(ext_id) || state.live.contains_key(instance_id) {
            return Err(MutationReason::InvalidState);
        }
        state.live.insert(
            instance_id.into(),
            Live {
                ext_id: ext_id.into(),
                key: key.map(str::to_owned),
                admission,
                stop,
            },
        );
        Ok(InstanceControlRegistration {
            registry: self.clone(),
            instance_id: instance_id.into(),
        })
    }
    async fn confirmed(
        &self,
        ext_id: &str,
        key: Option<&str>,
        active: bool,
    ) -> Result<(bool, String), MutationReason> {
        let owner = self.0.owner.clone();
        let ext_id = ext_id.to_owned();
        let key = key.map(str::to_owned);
        tokio::task::spawn_blocking(move || {
            owner
                .verify()
                .map_err(|_| MutationReason::InvalidSnapshot)?;
            let lock =
                Lock::load_required(owner.home()).map_err(|_| MutationReason::InvalidSnapshot)?;
            let extension = lock
                .extensions
                .get(&ext_id)
                .ok_or(MutationReason::NotFound)?;
            if key
                .as_ref()
                .is_some_and(|key| !extension.versions.contains_key(key))
            {
                return Err(MutationReason::NotFound);
            }
            if active && key.as_ref() != Some(&extension.active) {
                return Err(MutationReason::StaleBase);
            }
            Ok((extension.enabled, extension.active.clone()))
        })
        .await
        .map_err(|_| MutationReason::IoError)?
    }

    fn suspend_admissions(&self, ext_id: &str, promotion: bool) -> Result<(), MutationReason> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| MutationReason::InvalidState)?;
        if !promotion && state.publishing.contains(ext_id) {
            return Err(MutationReason::RecoveryRequired);
        }
        if promotion {
            state.publishing.insert(ext_id.into());
        }
        state.blocked.insert(ext_id.into());
        for instance in state
            .live
            .values()
            .filter(|instance| instance.ext_id == ext_id)
        {
            if let Some(admission) = &instance.admission {
                admission
                    .suspend()
                    .map_err(|_| MutationReason::InvalidState)?;
            }
        }
        Ok(())
    }

    fn publish_current(
        &self,
        ext_id: &str,
        active: Option<&str>,
        enabled: bool,
        promotion: bool,
    ) -> Result<(), MutationReason> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| MutationReason::InvalidState)?;
        if !promotion && state.publishing.contains(ext_id) {
            return Err(MutationReason::RecoveryRequired);
        }
        for instance in state
            .live
            .values()
            .filter(|instance| instance.ext_id == ext_id)
        {
            if !enabled {
                instance.stop.send_replace(true);
            } else if active.is_some_and(|key| instance.key.as_deref() != Some(key)) {
                if let Some(admission) = &instance.admission {
                    admission
                        .drain()
                        .map_err(|_| MutationReason::InvalidState)?;
                } else {
                    // Legacy trusted registrations contain only a stop watch,
                    // never an MCP connection with calls to drain.
                    instance.stop.send_replace(true);
                }
            } else if let Some(admission) = &instance.admission {
                admission
                    .resume()
                    .map_err(|_| MutationReason::InvalidState)?;
            }
        }
        if enabled {
            state.blocked.remove(ext_id);
        } else {
            state.blocked.insert(ext_id.into());
        }
        if promotion {
            state.publishing.remove(ext_id);
        }
        Ok(())
    }

    async fn publish_intent(&self, intent: &PromotionIntent) -> Result<(), MutationReason> {
        let expected = match intent.state {
            PromotionState::Committed => Some(intent.after_lock.as_str()),
            PromotionState::Aborted => intent.before_lock.as_deref(),
            PromotionState::Prepared => return Err(MutationReason::RecoveryRequired),
        };
        let owner = self.0.owner.clone();
        let expected = expected.map(str::to_owned);
        let ext_id = intent.ext_id.clone();
        let selection = tokio::task::spawn_blocking(move || {
            owner
                .verify()
                .map_err(|_| MutationReason::InvalidSnapshot)?;
            let bytes =
                Lock::read_snapshot(owner.home()).map_err(|_| MutationReason::InvalidSnapshot)?;
            if bytes.as_deref() != expected.as_deref().map(str::as_bytes) {
                return Err(MutationReason::StaleBase);
            }
            let lock = bytes
                .as_deref()
                .map(Lock::parse_snapshot)
                .transpose()
                .map_err(|_| MutationReason::InvalidSnapshot)?
                .unwrap_or_default();
            Ok(lock
                .extensions
                .get(&ext_id)
                .map(|extension| (extension.active.clone(), extension.enabled)))
        })
        .await
        .map_err(|_| MutationReason::IoError)??;
        if intent.state == PromotionState::Committed
            && selection.as_ref().is_none_or(|(key, _)| key != &intent.key)
        {
            return Err(MutationReason::InvalidSnapshot);
        }
        match selection {
            Some((active, enabled)) => {
                self.publish_current(&intent.ext_id, Some(&active), enabled, true)
            }
            // Aborting the first installation restores the absent entry. There
            // is no new executable to activate and no old version to drain.
            None => self.publish_current(&intent.ext_id, None, true, true),
        }
    }
}
pub struct InstanceControlRegistration {
    registry: ControlRegistry,
    instance_id: String,
}
impl Drop for InstanceControlRegistration {
    fn drop(&mut self) {
        if let Ok(mut state) = self.registry.0.state.lock() {
            state.live.remove(&self.instance_id);
        }
    }
}
impl ControlPublication for ControlRegistry {
    fn block_admissions(&self, ext_id: &str) -> Result<(), MutationReason> {
        self.suspend_admissions(ext_id, false)
    }
    fn publish_enabled<'a>(
        &'a self,
        ext_id: &'a str,
        key: &'a str,
        enabled: bool,
    ) -> PublicationFuture<'a> {
        Box::pin(async move {
            if self.confirmed(ext_id, Some(key), true).await?.0 != enabled {
                return Err(MutationReason::InvalidState);
            }
            self.publish_current(ext_id, Some(key), enabled, false)
        })
    }
    fn publish_reset<'a>(&'a self, selection: &'a ResetCrashes) -> PublicationFuture<'a> {
        Box::pin(async move {
            let (enabled, active) = self
                .confirmed(&selection.ext_id, Some(&selection.key), false)
                .await?;
            // Crash admission reads the writer on each demand; its in-flight
            // observations/pending audits must never be cleared by publication.
            self.publish_current(&selection.ext_id, Some(&active), enabled, false)
        })
    }
}

impl PromotionPublication for ControlRegistry {
    fn block_before_lock(&self, ext_id: &str) -> Result<(), MutationReason> {
        self.suspend_admissions(ext_id, true)
    }

    fn publish_after_commit<'a>(
        &'a self,
        intent: &'a PromotionIntent,
    ) -> PromotionPublicationFuture<'a> {
        Box::pin(async move {
            if intent.state != PromotionState::Committed {
                return Err(MutationReason::RecoveryRequired);
            }
            self.publish_intent(intent).await
        })
    }

    fn reconcile<'a>(&'a self, intent: &'a PromotionIntent) -> PromotionPublicationFuture<'a> {
        Box::pin(self.publish_intent(intent))
    }
}
