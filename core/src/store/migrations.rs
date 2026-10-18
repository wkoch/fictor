//! Startup migrations: private SQLite backups precede every schema change.
use super::{StoreError, now_ms};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, backup::Backup};
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
    time::{Duration, Instant},
};

const SCHEMA_VERSION: i64 = 5;
const MIGRATIONS: [&str; 5] = [
    include_str!("../../migrations/0001_init.sql"),
    include_str!("../../migrations/0002_flow_budget.sql"),
    include_str!("../../migrations/0003_proposal_receipts.sql"),
    include_str!("../../migrations/0004_promotion_journal.sql"),
    include_str!("../../migrations/0005_crash_recovery.sql"),
];

pub(super) fn open_writer(path: &Path) -> Result<Connection, StoreError> {
    // Serialize migration plus backup across core openers. SQLite's write
    // transaction alone cannot cover its backup API (backup needs a source
    // connection without an active write transaction).
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(StoreError::Invalid("banco deve ser arquivo regular"));
    }
    lock(&file)?;
    let preflight = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    preflight.busy_timeout(Duration::from_millis(5000))?;
    let version: i64 = preflight.pragma_query_value(None, "user_version", |row| row.get(0))?;
    // Even opening and dropping a writable SQLite connection can checkpoint
    // a future core's crashed WAL. Inspect with a read-only connection first.
    if version > SCHEMA_VERSION {
        return Err(StoreError::NewerSchema(version));
    }
    if version < 0 {
        return Err(StoreError::Invalid("versão negativa de schema"));
    }
    if version < SCHEMA_VERSION {
        backup(&preflight, path, version)?;
    }
    drop(preflight);
    let mut connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    // Set and confirm FULL before even journal-mode initialization can write.
    connection.pragma_update(None, "synchronous", "FULL")?;
    confirm_full(&connection)?;
    connection.busy_timeout(Duration::from_millis(5000))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    confirm_full(&connection)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    for (index, migration) in MIGRATIONS.iter().enumerate() {
        if version < (index + 1) as i64 {
            transaction.execute_batch(migration)?;
        }
    }
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.execute(
        "INSERT OR IGNORE INTO sessions (id, kind, created_at, updated_at) VALUES ('sys', 'system', ?1, ?1)",
        [now_ms()?],
    )?;
    transaction.commit()?;
    Ok(connection)
}

pub(super) fn confirm_full(connection: &Connection) -> Result<(), StoreError> {
    let synchronous: i64 = connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    if synchronous != 2 {
        return Err(StoreError::Invalid(
            "durabilidade SQLite FULL não confirmada",
        ));
    }
    Ok(())
}

fn lock(file: &File) -> Result<(), io::Error> {
    let start = Instant::now();
    loop {
        // SAFETY: the fd is owned and live. The advisory lock is released when
        // this function's caller drops the file after startup (including errors).
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if error.kind() != io::ErrorKind::WouldBlock || start.elapsed() >= Duration::from_secs(5) {
            return Err(error);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn backup(source: &Connection, path: &Path, version: i64) -> Result<(), StoreError> {
    let parent = path.parent().ok_or(StoreError::Invalid("banco sem pai"))?;
    let temporary = tempfile::NamedTempFile::new_in(parent)?;
    {
        let mut destination = Connection::open(temporary.path())?;
        destination.pragma_update(None, "synchronous", "FULL")?;
        confirm_full(&destination)?;
        // SQLite's backup API includes committed WAL content; copying the main
        // file alone would silently lose those transactions.
        Backup::new(source, &mut destination)?.run_to_completion(
            256,
            Duration::from_millis(5),
            None,
        )?;
    }
    temporary.as_file().sync_all()?;
    let current = parent.join(format!("fictor.db.bak-{version}"));
    temporary.persist(&current).map_err(|error| error.error)?;
    File::open(parent)?.sync_all()?;
    prune_backups(parent, &current)?;
    Ok(())
}

fn prune_backups(parent: &Path, current: &Path) -> Result<(), io::Error> {
    let mut backups = Vec::new();
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(version) = name
            .to_str()
            .and_then(|name| name.strip_prefix("fictor.db.bak-"))
            .and_then(|suffix| suffix.parse::<u32>().ok())
        else {
            continue;
        };
        // Do not inspect targets of symlinks or treat arbitrary names as backups.
        if entry.path() != current && entry.file_type()?.is_file() {
            backups.push((entry.metadata()?.modified()?, version, entry.path()));
        }
    }
    backups.sort_by(|left, right| right.cmp(left));
    // The just-published snapshot is always retained, even if a clock rollback
    // or restored timestamps make older backups appear to come from the future.
    for (_, _, path) in backups.into_iter().skip(2) {
        fs::remove_file(path)?;
    }
    File::open(parent)?.sync_all()
}
