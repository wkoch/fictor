//! ADR-038's private instance journal. No discovered numeric PID is signalled.
mod files;
mod process;

use crate::{
    ownership::HomeLease,
    store::{AppendEvent, Provenance, Store},
};
pub use process::{NamespaceIdentity, ProcessHandle, ProcessIdentity};
use serde::{Deserialize, Serialize};
use std::{io, path::PathBuf, sync::Arc, time::Duration};

#[derive(Debug, thiserror::Error)]
pub enum InstanceError {
    #[error("invalid instance journal")]
    Invalid,
    #[error("instance identity could not be confirmed")]
    Uncertain,
    #[error("previous instance owner is still alive")]
    OwnerAlive,
    #[error("instance resources could not be persisted or cleaned")]
    Io(#[from] io::Error),
    #[error("instance recovery audit failed")]
    Audit,
}

/// JSON represents u64 values as canonical decimal strings, never numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decimal(pub u64);
impl Serialize for Decimal {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}
impl<'de> Deserialize<'de> for Decimal {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        let number = value.parse::<u64>().map_err(serde::de::Error::custom)?;
        if number.to_string() != value {
            return Err(serde::de::Error::custom("noncanonical decimal"));
        }
        Ok(Self(number))
    }
}
fn nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstanceState {
    Prepared,
    Spawning,
    Armed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateRecord {
    pub schema: u32,
    pub instance_id: String,
    pub ext_id: String,
    pub key: String,
    #[serde(deserialize_with = "nullable")]
    pub session_id: Option<String>,
    pub owner_id: String,
    pub boot_id: String,
    pub observer_pidns: NamespaceIdentity,
    pub owner: ProcessIdentity,
    pub state: InstanceState,
    #[serde(deserialize_with = "nullable")]
    pub launcher: Option<ProcessIdentity>,
    #[serde(deserialize_with = "nullable")]
    pub init: Option<ProcessIdentity>,
    #[serde(deserialize_with = "nullable")]
    pub sandbox_pidns: Option<NamespaceIdentity>,
}
impl StateRecord {
    pub fn parse(bytes: &[u8], directory: &str) -> Result<Self, InstanceError> {
        let value = crate::strict_json::parse(bytes).map_err(|_| InstanceError::Invalid)?;
        let record: Self = serde_json::from_value(value).map_err(|_| InstanceError::Invalid)?;
        record.validate(directory)?;
        Ok(record)
    }
    fn validate(&self, directory: &str) -> Result<(), InstanceError> {
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../spec/schemas/extension.schema.json"))
                .map_err(|_| InstanceError::Invalid)?;
        let id = jsonschema::options()
            .offline()
            .build(&schema["properties"]["id"])
            .map_err(|_| InstanceError::Invalid)?;
        let version = jsonschema::options()
            .offline()
            .build(&schema["properties"]["version"])
            .map_err(|_| InstanceError::Invalid)?;
        let Some((ver, hash)) = self.key.rsplit_once('-') else {
            return Err(InstanceError::Invalid);
        };
        let shape = match self.state {
            InstanceState::Prepared => {
                self.launcher.is_none() && self.init.is_none() && self.sandbox_pidns.is_none()
            }
            InstanceState::Spawning => self.init.is_none() && self.sandbox_pidns.is_none(),
            InstanceState::Armed => {
                self.launcher.is_some()
                    && self.init.is_some()
                    && self
                        .sandbox_pidns
                        .is_some_and(|namespace| namespace != self.observer_pidns)
            }
        };
        if self.schema != 1
            || !valid_id(&self.instance_id)
            || self.instance_id != directory
            || !valid_id(&self.owner_id)
            || self.session_id.as_deref().is_some_and(|id| !valid_id(id))
            || !id.is_valid(&serde_json::Value::String(self.ext_id.clone()))
            || !version.is_valid(&serde_json::Value::String(ver.into()))
            || hash.len() != 12
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !process::valid_boot(&self.boot_id)
            || !self.owner.valid()
            || self.launcher.is_some_and(|identity| !identity.valid())
            || self.init.is_some_and(|identity| !identity.valid())
            || !shape
        {
            return Err(InstanceError::Invalid);
        }
        Ok(())
    }
}
fn valid_id(id: &str) -> bool {
    id.parse::<ulid::Ulid>()
        .is_ok_and(|value| value.to_string() == id)
}

pub struct NewInstance {
    pub instance_id: String,
    pub ext_id: String,
    pub key: String,
    pub session_id: Option<String>,
}

/// Dropping a journal retains every resource. Cleanup requires exit evidence.
pub struct InstanceJournal {
    owner: Arc<HomeLease>,
    directories: files::Directories,
    directory: std::fs::File,
    record: StateRecord,
}
impl InstanceJournal {
    pub fn prepare(owner: Arc<HomeLease>, identity: NewInstance) -> Result<Self, InstanceError> {
        owner.verify().map_err(|_| InstanceError::Uncertain)?;
        let context = process::Context::current()?;
        let record = StateRecord {
            schema: 1,
            instance_id: identity.instance_id,
            ext_id: identity.ext_id,
            key: identity.key,
            session_id: identity.session_id,
            owner_id: owner.owner_id().into(),
            boot_id: context.boot_id,
            observer_pidns: context.observer_pidns,
            owner: context.owner,
            state: InstanceState::Prepared,
            launcher: None,
            init: None,
            sandbox_pidns: None,
        };
        record.validate(&record.instance_id)?;
        let directories = files::Directories::open(&owner, true)?;
        let directory = directories.create(&record.instance_id)?;
        files::publish(&directory, &record)?;
        Ok(Self {
            owner,
            directories,
            directory,
            record,
        })
    }
    pub fn record(&self) -> &StateRecord {
        &self.record
    }
    pub fn temporary_path(&self) -> PathBuf {
        self.owner
            .home()
            .join("run/instances")
            .join(&self.record.instance_id)
            .join("tmp")
    }
    pub fn kernel_socket_path(&self) -> PathBuf {
        self.owner
            .home()
            .join("run/k")
            .join(format!("{}.sock", self.record.instance_id))
    }
    pub fn admission_socket_path(&self) -> PathBuf {
        self.owner
            .home()
            .join("run/instances")
            .join(&self.record.instance_id)
            .join("admission.sock")
    }
    pub fn create_temporary(&self) -> Result<PathBuf, InstanceError> {
        if self.record.state != InstanceState::Prepared {
            return Err(InstanceError::Invalid);
        }
        files::create_directory(&self.directory, c"tmp")?;
        Ok(self.temporary_path())
    }
    pub fn spawning(&mut self) -> Result<(), InstanceError> {
        if self.record.state != InstanceState::Prepared {
            return Err(InstanceError::Invalid);
        }
        let mut next = self.record.clone();
        next.state = InstanceState::Spawning;
        self.persist(next)
    }
    pub fn record_launcher(&mut self, launcher: &ProcessHandle) -> Result<(), InstanceError> {
        if self.record.state != InstanceState::Spawning || self.record.launcher.is_some() {
            return Err(InstanceError::Invalid);
        }
        let mut next = self.record.clone();
        next.launcher = Some(launcher.identity());
        self.persist(next)
    }
    pub fn arm(
        &mut self,
        launcher: &ProcessHandle,
        init: &ProcessHandle,
    ) -> Result<(), InstanceError> {
        if self.record.state != InstanceState::Spawning
            || !init.is_init()
            || init.namespace() == self.record.observer_pidns
            || self
                .record
                .launcher
                .is_some_and(|identity| identity != launcher.identity())
            || launcher.is_exited()?
            || init.is_exited()?
        {
            return Err(InstanceError::Invalid);
        }
        let mut next = self.record.clone();
        next.state = InstanceState::Armed;
        next.launcher = Some(launcher.identity());
        next.init = Some(init.identity());
        next.sandbox_pidns = Some(init.namespace());
        self.persist(next)
    }
    fn persist(&mut self, next: StateRecord) -> Result<(), InstanceError> {
        self.owner.verify().map_err(|_| InstanceError::Uncertain)?;
        if files::read_record(&self.directory, &self.record.instance_id)? != self.record {
            return Err(InstanceError::Uncertain);
        }
        next.validate(&self.record.instance_id)?;
        files::publish(&self.directory, &next)?;
        self.record = next;
        Ok(())
    }
    pub fn cleanup_confirmed(
        &self,
        launcher: &ProcessHandle,
        init: &ProcessHandle,
    ) -> Result<(), InstanceError> {
        self.owner.verify().map_err(|_| InstanceError::Uncertain)?;
        if self.record.state != InstanceState::Armed
            || self.record.launcher != Some(launcher.identity())
            || self.record.init != Some(init.identity())
            || self.record.sandbox_pidns != Some(init.namespace())
            || !launcher.is_exited()?
            || !init.is_exited()?
        {
            return Err(InstanceError::Uncertain);
        }
        self.directories.cleanup(&self.directory, &self.record)
    }
    /// Only the last durable Prepared state authorizes cleanup without pidfds:
    /// the caller must have persisted Spawning before creating any child.
    pub fn cleanup_prepared(&self) -> Result<(), InstanceError> {
        self.owner.verify().map_err(|_| InstanceError::Uncertain)?;
        if self.record.state != InstanceState::Prepared {
            return Err(InstanceError::Uncertain);
        }
        self.directories.cleanup(&self.directory, &self.record)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticCode {
    Unknown,
    Uncertain,
    CleanupFailed,
}
#[derive(Debug)]
pub struct RecoveryDiagnostic {
    pub instance_id: Option<String>,
    pub code: DiagnosticCode,
}
#[derive(Default, Debug)]
pub struct RecoveryReport {
    pub removed: Vec<String>,
    pub diagnostics: Vec<RecoveryDiagnostic>,
    pub legacy: LegacyResources,
}
/// Presence only, never an ownership claim or authority to clean a resource.
/// Keep filenames, paths, PID text and identities out of boot diagnostics.
#[derive(Default, Debug)]
pub struct LegacyResources {
    pub pid_files: bool,
    pub temporaries: bool,
    pub scan_unavailable: bool,
}

/// The owner task retains the lease even if a boot caller is cancelled. Only a
/// completed recovery result can authorize the caller to admit new work.
pub async fn recover(store: Arc<Store>) -> Result<RecoveryReport, InstanceError> {
    tokio::spawn(async move { recover_owned(store).await })
        .await
        .map_err(|_| InstanceError::Uncertain)?
}
async fn recover_owned(store: Arc<Store>) -> Result<RecoveryReport, InstanceError> {
    let owner = store.owner().clone();
    let _gate = owner.installer_gate().lock_owned().await;
    recover_locked(store).await
}

/// Boot's already-owned, cancellation-safe coordinator holds the installer
/// gate for this entire call and its following recovery operations.
pub(crate) async fn recover_locked(store: Arc<Store>) -> Result<RecoveryReport, InstanceError> {
    let owner = store.owner().clone();
    let work_owner = owner.clone();
    let (mut report, retained) = tokio::task::spawn_blocking(move || recover_files(work_owner))
        .await
        .map_err(|_| InstanceError::Uncertain)??;
    for (record, code) in retained {
        store.append(AppendEvent { session_id:"sys".into(), parent_id:None, kind:"ext.cleanup_failed".into(), actor:"core".into(), payload:serde_json::json!({"ext_id":record.ext_id,"key":record.key,"instance_id":record.instance_id}),blob_refs:vec![],provenance:Provenance::core() }).await.map_err(|_|InstanceError::Audit)?;
        report.diagnostics.push(RecoveryDiagnostic {
            instance_id: Some(record.instance_id),
            code,
        });
    }
    Ok(report)
}

fn recover_files(
    owner: Arc<HomeLease>,
) -> Result<(RecoveryReport, Vec<(StateRecord, DiagnosticCode)>), InstanceError> {
    owner.verify().map_err(|_| InstanceError::Uncertain)?;
    let context = process::Context::current()?;
    let mut report = RecoveryReport {
        legacy: files::legacy_resources(&owner),
        ..Default::default()
    };
    let Some(directories) = files::Directories::existing(&owner)? else {
        owner.verify().map_err(|_| InstanceError::Uncertain)?;
        return Ok((report, vec![]));
    };
    let mut valid = vec![];
    for name in files::names(&directories.instances)? {
        let Some(name) = name.to_str().filter(|name| valid_id(name)) else {
            report.diagnostics.push(RecoveryDiagnostic {
                instance_id: None,
                code: DiagnosticCode::Unknown,
            });
            continue;
        };
        match directories.read(name) {
            Ok((directory, record)) => valid.push((directory, record, false)),
            Err(_) => report.diagnostics.push(RecoveryDiagnostic {
                instance_id: Some(name.into()),
                code: DiagnosticCode::Unknown,
            }),
        }
    }
    // Detect an inconsistent live previous owner before deleting any record.
    for (_, record, uncertain_owner) in &mut valid {
        if context.same_boot(record) && context.observer_pidns == record.observer_pidns {
            match process::observe(record.owner, None) {
                Ok(process::Observation::Live(_)) => return Err(InstanceError::OwnerAlive),
                Ok(process::Observation::Gone) => {}
                Err(_) => *uncertain_owner = true,
            }
        }
    }
    let mut retained = vec![];
    for (directory, record, uncertain_owner) in valid {
        let confirmed = if uncertain_owner {
            false
        } else if !context.same_boot(&record) || record.state == InstanceState::Prepared {
            true
        } else if context.observer_pidns != record.observer_pidns {
            false
        } else {
            process::confirm(&record, Duration::from_secs(10)).unwrap_or(false)
        };
        let code = if !confirmed {
            Some(DiagnosticCode::Uncertain)
        } else if directories.cleanup(&directory, &record).is_err() {
            Some(DiagnosticCode::CleanupFailed)
        } else {
            report.removed.push(record.instance_id.clone());
            None
        };
        if let Some(code) = code {
            retained.push((record, code));
        }
    }
    owner.verify().map_err(|_| InstanceError::Uncertain)?;
    Ok((report, retained))
}
