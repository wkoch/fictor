//! ADR-041: a coordinated configuration snapshot, never process health.
use super::lock::{Lock, LockError};
use crate::ownership::HomeLease;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions, io, os::unix::fs::OpenOptionsExt, path::Path, sync::Arc, time::Duration,
};

pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum ListingError {
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Extension {
    pub id: String,
    pub active: String,
    pub version: String,
    pub enabled: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema: u32,
    pub extensions: Vec<Extension>,
}

impl Snapshot {
    pub(crate) fn validate(&self) -> Result<(), ListingError> {
        if self.schema != 1 {
            return Err(ListingError::InvalidSnapshot);
        }
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../../spec/schemas/extension.schema.json"))
                .map_err(|_| ListingError::InvalidSnapshot)?;
        let id = jsonschema::options()
            .offline()
            .build(&schema["properties"]["id"])
            .map_err(|_| ListingError::InvalidSnapshot)?;
        let version = jsonschema::options()
            .offline()
            .build(&schema["properties"]["version"])
            .map_err(|_| ListingError::InvalidSnapshot)?;
        let mut previous: Option<&str> = None;
        for extension in &self.extensions {
            let suffix = extension
                .active
                .strip_prefix(&format!("{}-", extension.version))
                .ok_or(ListingError::InvalidSnapshot)?;
            if !id.is_valid(&serde_json::Value::String(extension.id.clone()))
                || !version.is_valid(&serde_json::Value::String(extension.version.clone()))
                || suffix.len() != 12
                || !suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || previous.is_some_and(|previous| previous >= extension.id.as_str())
            {
                return Err(ListingError::InvalidSnapshot);
            }
            previous = Some(&extension.id);
        }
        Ok(())
    }

    /// Construct all human output before the CLI emits its first byte.
    pub fn human(&self) -> Result<String, ListingError> {
        self.validate()?;
        let mut output = String::from("ID\tCHAVE\tVERSÃO\tHABILITADA\n");
        for extension in &self.extensions {
            use std::fmt::Write;
            writeln!(
                output,
                "{}\t{}\t{}\t{}",
                extension.id, extension.active, extension.version, extension.enabled
            )
            .map_err(|_| ListingError::IoError)?;
        }
        Ok(output)
    }
}

/// The owned guard and home lease move into the worker. Timing out or dropping
/// the observer never releases them while SQLite/lock reads are still running.
pub async fn snapshot(owner: Arc<HomeLease>) -> Result<Snapshot, ListingError> {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    let guard = tokio::time::timeout_at(deadline, owner.installer_gate().lock_owned())
        .await
        .map_err(|_| ListingError::Busy)?;
    let task = tokio::task::spawn_blocking(move || {
        let _guard = guard;
        read_owned(owner)
    });
    tokio::time::timeout_at(deadline, task)
        .await
        .map_err(|_| ListingError::Busy)?
        .map_err(|_| ListingError::IoError)?
}

pub(crate) fn read_owned(owner: Arc<HomeLease>) -> Result<Snapshot, ListingError> {
    let lock = read_lock(&owner, false)?;
    let mut extensions = Vec::with_capacity(lock.extensions.len());
    for (id, extension) in lock.extensions {
        let active = extension
            .versions
            .get(&extension.active)
            .ok_or(ListingError::InvalidSnapshot)?;
        extensions.push(Extension {
            id,
            active: extension.active,
            version: active.version.clone(),
            enabled: extension.enabled,
        });
    }
    let snapshot = Snapshot {
        schema: 1,
        extensions,
    };
    snapshot.validate()?;
    crate::admin::bounded_json(&snapshot)?;
    Ok(snapshot)
}

/// Offline mutation preflight validates persisted inputs, independent of how
/// many configuration rows a listing response could fit into one admin frame.
pub(crate) fn preflight_owned(
    owner: Arc<HomeLease>,
    allow_prepared: bool,
) -> Result<(), ListingError> {
    read_lock(&owner, allow_prepared).map(|_| ())
}
fn read_lock(owner: &Arc<HomeLease>, allow_prepared: bool) -> Result<Lock, ListingError> {
    owner.verify().map_err(|_| ListingError::InvalidSnapshot)?;
    let home = owner.anchored_path().join(".");
    // SQLite's NOFOLLOW rejects /proc/self/fd directory aliases too. Use the
    // verified canonical home for its VFS and keep the owner until the read ends.
    let path = owner.home().join("fictor.db");
    // Never open a FIFO/device for SQLite, or create a missing database. The
    // directory lease remains alive through SQLite's normal WAL/SHM handling.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&path)
        .map_err(file_error)?;
    if !file.metadata().map_err(file_error)?.is_file() {
        return Err(ListingError::InvalidSnapshot);
    }
    let mut connection = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(database_error)?;
    connection.busy_timeout(TIMEOUT).map_err(database_error)?;
    let transaction = connection.transaction().map_err(database_error)?;
    let version: i64 = transaction
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(database_error)?;
    if version != crate::store::SCHEMA_VERSION {
        return Err(ListingError::DataVersionUnsupported);
    }
    let check: String = transaction
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(database_error)?;
    if check != "ok" {
        return Err(ListingError::InvalidSnapshot);
    }
    let foreign_key_error = transaction
        .prepare("PRAGMA foreign_key_check")
        .map_err(database_error)?
        .query([])
        .map_err(database_error)?
        .next()
        .map_err(database_error)?
        .is_some();
    if foreign_key_error {
        return Err(ListingError::InvalidSnapshot);
    }
    // The store owns journal decoding and invariants; a query does not reconcile.
    let blobs = crate::store::blobs::BlobStore::owned(owner.home().join("blobs"), owner.clone());
    if crate::store::read_promotion_intents(&transaction, &blobs)
        .map_err(|_| ListingError::InvalidSnapshot)?
        .is_some()
        && !allow_prepared
    {
        return Err(ListingError::RecoveryRequired);
    }
    let lock = Lock::load_required(&home).map_err(lock_error)?;
    transaction.commit().map_err(database_error)?;
    owner.verify().map_err(|_| ListingError::InvalidSnapshot)?;
    Ok(lock)
}

fn file_error(error: io::Error) -> ListingError {
    if error.kind() == io::ErrorKind::NotFound {
        ListingError::NotInitialized
    } else {
        ListingError::IoError
    }
}
fn lock_error(error: LockError) -> ListingError {
    match error {
        LockError::Io(error) => file_error(error),
        LockError::Busy => ListingError::Busy,
        _ => ListingError::InvalidSnapshot,
    }
}
fn database_error(error: rusqlite::Error) -> ListingError {
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
            ListingError::Busy
        }
        Some(
            rusqlite::ErrorCode::CannotOpen
            | rusqlite::ErrorCode::SystemIoFailure
            | rusqlite::ErrorCode::PermissionDenied,
        ) => ListingError::IoError,
        _ => ListingError::InvalidSnapshot,
    }
}

/// The command first tries ownership. A busy owner permits only an authenticated
/// online attempt; transport/authentication failure never reopens files offline.
pub async fn list(home: &Path) -> Result<Snapshot, crate::admin::AdminError> {
    let canonical = home
        .canonicalize()
        .map_err(|error| crate::admin::AdminError::Listing(file_error(error)))?;
    match HomeLease::acquire(&canonical) {
        Ok(owner) => snapshot(owner).await.map_err(Into::into),
        Err(crate::ownership::OwnershipError::Busy) => crate::admin::request(&canonical).await,
        Err(
            crate::ownership::OwnershipError::Unsafe | crate::ownership::OwnershipError::Changed,
        ) => Err(ListingError::InvalidSnapshot.into()),
        Err(_) => Err(ListingError::IoError.into()),
    }
}
