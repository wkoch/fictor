pub mod blobs;
mod budget;
mod crashes;
mod events;
mod installations;
mod kv;
pub(crate) use proposals::validate_approval;
mod migrations;
pub(crate) use migrations::SCHEMA_VERSION;
mod promotion;
mod proposals;
pub(crate) use promotion::read_promotion_intents;
pub use promotion::{NewPromotionIntent, PromotionAbortReason, PromotionIntent, PromotionState};
mod read_budget;
pub use proposals::{
    HumanDecision, NewProposal, Proposal, ProposalCheck, ProposalIdentity, ProposalNonce,
    ProposalState, ProposalUpdate, ResolvedPackage, ReviewBase,
};
mod sessions;
pub use budget::{BudgetExceeded, local_day};
pub use events::{
    AppendEvent, Event, EventPath, EventQuery, Flags, Provenance, Sensitivity, Trust,
};
pub use sessions::{NewSession, Session};

use rusqlite::{Connection, OpenFlags, OptionalExtension};
use std::{
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, oneshot};

use migrations::open_writer;
type Job = Box<dyn FnOnce(&mut Writer) + Send>;

struct Writer {
    db: Connection,
    ids: ulid::Generator,
    last_id: Option<ulid::Ulid>,
    blobs: blobs::BlobStore,
}

impl Writer {
    fn next_id(&mut self) -> Result<String, StoreError> {
        let generated = self.ids.generate().map_err(|_| StoreError::IdOverflow)?;
        let id = match self.last_id {
            Some(last) if generated <= last => {
                last.increment().map_err(|_| StoreError::IdOverflow)?
            }
            _ => generated,
        };
        self.last_id = Some(id);
        Ok(id.to_string())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Ownership(#[from] crate::ownership::OwnershipError),
    #[error("erro no SQLite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("erro de arquivo: {0}")]
    Io(#[from] std::io::Error),
    #[error("banco com versão {0} mais nova que este core")]
    NewerSchema(i64),
    #[error("schema incompatível com operação offline: {0}")]
    ExistingSchema(i64),
    #[error("task de escrita indisponível")]
    Closed,
    #[error("relógio fora do intervalo suportado")]
    Clock,
    #[error("identificador monotônico esgotado")]
    IdOverflow,
    #[error("objeto não encontrado")]
    NotFound,
    #[error("HEAD_MOVED")]
    HeadMoved,
    #[error("parâmetro inválido: {0}")]
    Invalid(&'static str),
    #[error("conteúdo excede o limite permitido")]
    TooLarge,
    #[error("JSON inválido")]
    Json(#[from] serde_json::Error),
    #[error("falha no blob: {0}")]
    Blob(#[from] blobs::BlobError),
}

pub struct Store {
    writer: mpsc::Sender<Job>,
    task: tokio::task::JoinHandle<()>,
    readers: Arc<Readers>,
    next_reader: AtomicUsize,
    blobs: blobs::BlobStore,
    owner: Arc<crate::ownership::HomeLease>,
}

struct Readers {
    connections: Vec<Mutex<Connection>>,
    // Close every SQLite reader before relinquishing ownership, including
    // readers still held by a cancelled asynchronous caller's blocking job.
    _owner: Arc<crate::ownership::HomeLease>,
}

impl Store {
    pub fn owner(&self) -> &Arc<crate::ownership::HomeLease> {
        &self.owner
    }

    pub async fn open(home: &Path) -> Result<Self, StoreError> {
        let owner = crate::ownership::HomeLease::acquire(home)?;
        Self::open_with_lease(owner).await
    }

    pub async fn open_with_lease(
        owner: Arc<crate::ownership::HomeLease>,
    ) -> Result<Self, StoreError> {
        Self::open_mode(owner, false).await
    }

    /// Offline mutations never create a database, run a migration, repair sys,
    /// or clean capture files as an incidental effect of opening their writer.
    pub async fn open_existing_with_lease(
        owner: Arc<crate::ownership::HomeLease>,
    ) -> Result<Self, StoreError> {
        Self::open_mode(owner, true).await
    }

    async fn open_mode(
        owner: Arc<crate::ownership::HomeLease>,
        existing_only: bool,
    ) -> Result<Self, StoreError> {
        let writer_lease = owner.claim_writer()?;
        let home = owner.home();
        let path = home.join("fictor.db");
        let blobs = blobs::BlobStore::owned(home.join("blobs"), owner.clone());
        let writer_blobs = blobs.clone();
        let reader_owner = owner.clone();
        let (writer, mut queue) = mpsc::channel::<Job>(64);
        let (ready, result) = oneshot::channel();
        let task = tokio::task::spawn_blocking(move || {
            // Declared before the writer state: close SQLite before allowing
            // another writer, even when the opening future was cancelled.
            let _writer_lease = writer_lease;
            let setup = (|| -> Result<_, StoreError> {
                let db = if existing_only {
                    migrations::open_existing_writer(&path)?
                } else {
                    open_writer(&path)?
                };
                if !existing_only {
                    writer_blobs.cleanup_captures()?;
                }
                let last: Option<String> = db
                    .query_row("SELECT id FROM events ORDER BY seq DESC LIMIT 1", [], |r| {
                        r.get(0)
                    })
                    .optional()?;
                let last_id = last
                    .map(|id| {
                        id.parse()
                            .map_err(|_| StoreError::Invalid("ULID persistido inválido"))
                    })
                    .transpose()?;
                let mut readers = Vec::new();
                for _ in 0..2 {
                    let connection = Connection::open_with_flags(
                        &path,
                        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
                    )?;
                    connection.busy_timeout(Duration::from_millis(5000))?;
                    connection.pragma_update(None, "foreign_keys", "ON")?;
                    readers.push(Mutex::new(connection));
                }
                Ok((
                    Writer {
                        db,
                        ids: ulid::Generator::new(),
                        last_id,
                        blobs: writer_blobs,
                    },
                    Readers {
                        connections: readers,
                        _owner: reader_owner,
                    },
                ))
            })();
            let mut state = match setup {
                Ok((state, readers)) => {
                    let _ = ready.send(Ok(readers));
                    state
                }
                Err(error) => {
                    drop(_writer_lease);
                    let _ = ready.send(Err(error));
                    return;
                }
            };
            while let Some(job) = queue.blocking_recv() {
                job(&mut state);
            }
        });
        let readers = Arc::new(result.await.map_err(|_| StoreError::Closed)??);
        Ok(Self {
            writer,
            task,
            readers,
            next_reader: AtomicUsize::new(0),
            blobs,
            owner,
        })
    }

    pub async fn write<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        self.with_writer(move |state| operation(&mut state.db))
            .await
    }

    async fn with_writer<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut Writer) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        let (reply, result) = oneshot::channel();
        self.writer
            .send(Box::new(move |connection| {
                let result =
                    migrations::confirm_full(&connection.db).and_then(|()| operation(connection));
                let _ = reply.send(result);
            }))
            .await
            .map_err(|_| StoreError::Closed)?;
        result.await.map_err(|_| StoreError::Closed)?
    }

    async fn read<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&Connection) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        let pool = Arc::clone(&self.readers);
        let index = self.next_reader.fetch_add(1, Ordering::Relaxed) % pool.connections.len();
        tokio::task::spawn_blocking(move || {
            let connection = pool.connections[index]
                .lock()
                .map_err(|_| StoreError::Closed)?;
            operation(&connection)
        })
        .await
        .map_err(|_| StoreError::Closed)?
    }

    pub async fn put_blob(&self, data: Vec<u8>) -> Result<String, StoreError> {
        let blobs = self.blobs.clone();
        tokio::task::spawn_blocking(move || blobs.put(&data).map_err(StoreError::from))
            .await
            .map_err(|_| StoreError::Closed)?
    }

    pub fn begin_capture(&self) -> Result<blobs::Capture, StoreError> {
        Ok(self.blobs.begin_capture()?)
    }
    pub async fn finish_capture(&self, capture: blobs::Capture) -> Result<String, StoreError> {
        let blobs = self.blobs.clone();
        tokio::task::spawn_blocking(move || blobs.finish_capture(capture).map_err(StoreError::from))
            .await
            .map_err(|_| StoreError::Closed)?
    }

    pub async fn get_blob(&self, hash: String) -> Result<Vec<u8>, StoreError> {
        let blobs = self.blobs.clone();
        tokio::task::spawn_blocking(move || blobs.get(&hash).map_err(StoreError::from))
            .await
            .map_err(|_| StoreError::Closed)?
    }

    pub(crate) async fn get_blob_bounded(
        &self,
        hash: String,
        max_bytes: usize,
    ) -> Result<Vec<u8>, StoreError> {
        let blobs = self.blobs.clone();
        tokio::task::spawn_blocking(move || {
            blobs
                .get_bounded(&hash, max_bytes)
                .map_err(StoreError::from)
        })
        .await
        .map_err(|_| StoreError::Closed)?
    }

    pub async fn shutdown(self) -> Result<(), StoreError> {
        drop(self.writer);
        self.task.await.map_err(|_| StoreError::Closed)
    }
}

pub fn now_ms() -> Result<i64, StoreError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StoreError::Clock)?
        .as_millis();
    i64::try_from(millis).map_err(|_| StoreError::Clock)
}

#[cfg(test)]
mod ownership_tests {
    use super::*;
    use crate::ownership::{HomeLease, OwnershipError};
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn a_cancelled_reader_retains_ownership_until_its_connection_closes() {
        let home = tempfile::tempdir().unwrap();
        std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = Arc::new(Store::open(home.path()).await.unwrap());
        let (started, entered) = oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let reader_store = store.clone();
        let waiter = tokio::spawn(async move {
            reader_store
                .read(move |db| {
                    started.send(()).unwrap();
                    released.recv().unwrap();
                    Ok(db.query_row("SELECT count(*) FROM sessions", [], |row| {
                        row.get::<_, i64>(0)
                    })?)
                })
                .await
        });
        entered.await.unwrap();
        waiter.abort();
        let _ = waiter.await;
        Arc::try_unwrap(store)
            .ok()
            .unwrap()
            .shutdown()
            .await
            .unwrap();
        assert!(matches!(
            HomeLease::acquire(home.path()),
            Err(OwnershipError::Busy)
        ));
        release.send(()).unwrap();
        let owner = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match HomeLease::acquire(home.path()) {
                    Ok(owner) => break owner,
                    Err(OwnershipError::Busy) => tokio::task::yield_now().await,
                    Err(error) => panic!("{error}"),
                }
            }
        })
        .await
        .unwrap();
        drop(owner);
    }
}
