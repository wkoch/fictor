pub mod blobs;
mod budget;
mod events;
mod kv;
mod migrations;
mod proposals;
mod read_budget;
pub use proposals::{
    HumanDecision, NewProposal, Proposal, ProposalCheck, ProposalIdentity, ProposalNonce,
    ProposalState, ProposalUpdate, ResolvedPackage,
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
    #[error("erro no SQLite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("erro de arquivo: {0}")]
    Io(#[from] std::io::Error),
    #[error("banco com versão {0} mais nova que este core")]
    NewerSchema(i64),
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
    readers: Arc<Vec<Mutex<Connection>>>,
    next_reader: AtomicUsize,
    blobs: blobs::BlobStore,
}

impl Store {
    pub async fn open(home: &Path) -> Result<Self, StoreError> {
        let path = home.join("fictor.db");
        let blobs = blobs::BlobStore::new(home.join("blobs"));
        let writer_blobs = blobs.clone();
        let (writer, mut queue) = mpsc::channel::<Job>(64);
        let (ready, result) = oneshot::channel();
        let task = tokio::task::spawn_blocking(move || {
            let setup = (|| -> Result<_, StoreError> {
                let db = open_writer(&path)?;
                writer_blobs.cleanup_captures()?;
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
                    let connection =
                        Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
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
                    readers,
                ))
            })();
            let mut state = match setup {
                Ok((state, readers)) => {
                    let _ = ready.send(Ok(readers));
                    state
                }
                Err(error) => {
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
        let index = self.next_reader.fetch_add(1, Ordering::Relaxed) % pool.len();
        tokio::task::spawn_blocking(move || {
            let connection = pool[index].lock().map_err(|_| StoreError::Closed)?;
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
