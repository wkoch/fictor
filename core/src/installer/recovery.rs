//! ADR-035: reconcile the durable attempt before touching its abandoned copy.
//! The caller must hold the installer lease and confirm no sandbox still uses it.
use super::lease::InstallerLease;
use crate::store::{Store, StoreError};
use std::{
    collections::VecDeque,
    ffi::{CStr, CString, OsString},
    fs::OpenOptions,
    io,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd},
        unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::OpenOptionsExt,
        },
    },
    path::Path,
    sync::Arc,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticCode {
    OrphanReceipt,
    CleanupFailed,
}
impl DiagnosticCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OrphanReceipt => "recovery:orphan_receipt",
            Self::CleanupFailed => "recovery:cleanup_failed",
        }
    }
}

/// Only core codes and validated proposal IDs; never raw filenames or OS errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryDiagnostic {
    pub proposal_id: Option<String>,
    pub code: DiagnosticCode,
}

#[derive(Debug, Default)]
pub struct RecoveryReport {
    pub diagnostics: Vec<RecoveryDiagnostic>,
}

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("não foi possível reconciliar propostas interrompidas")]
    Store(#[from] StoreError),
    #[error("não foi possível acompanhar a limpeza da quarentena")]
    Task,
}

/// Run once before installer admission, while the externally held lease excludes
/// other workers. Database failure is fatal; filesystem failure is retryable.
pub async fn recover(
    home: &Path,
    store: Arc<Store>,
    lease: Arc<InstallerLease>,
) -> Result<RecoveryReport, RecoveryError> {
    let home = home.to_path_buf();
    let runtime = tokio::runtime::Handle::current();
    // Cancelling the caller cannot release admission while a queued Store job
    // or blocking filesystem work is still running. One worker owns the lease
    // throughout; Handle::block_on lets it await the existing writer/readers.
    tokio::task::spawn_blocking(move || {
        let _lease = lease;
        runtime.block_on(recover_owned(&home, store))
    })
    .await
    .map_err(|_| RecoveryError::Task)?
}

async fn recover_owned(home: &Path, store: Arc<Store>) -> Result<RecoveryReport, RecoveryError> {
    // One writer transaction commits every interrupted failure and its event.
    // It also returns old failed attempts so cleanup is retried on the next boot.
    let failed = store.recover_interrupted_proposals().await?;
    let mut report = RecoveryReport::default();
    let quarantine = match Quarantine::open(home) {
        Ok(quarantine) => quarantine,
        Err(_) => {
            report.failed(None);
            return Ok(report);
        }
    };
    for proposal in failed {
        if quarantine
            .remove(&proposal.id, proposal.ext_id.is_none())
            .is_err()
        {
            report.failed(Some(proposal.id));
        }
    }
    let receipts: Vec<String> = match directory_names(quarantine.directory.as_raw_fd()) {
        Ok(names) => names.into_iter().filter_map(receipt_id).collect(),
        Err(_) => {
            report.failed(None);
            Vec::new()
        }
    };
    for id in receipts {
        // A terminal proposal can still have a temporary left behind. Unknown
        // receipt names are diagnosed without inspecting their bytes or origin.
        match store.proposal(id.clone()).await {
            Ok(_) => {}
            Err(StoreError::NotFound) => report.diagnostics.push(RecoveryDiagnostic {
                proposal_id: Some(id.clone()),
                code: DiagnosticCode::OrphanReceipt,
            }),
            Err(error) => return Err(error.into()),
        }
        if quarantine.remove(&id, false).is_err() {
            report.failed(Some(id));
        }
    }
    Ok(report)
}

/// Caller has resolved the journal and holds installer exclusion. Only the
/// recognized quarantine namespace is collectible; store staging is retained.
pub(crate) fn remove_orphan_promotion_staging(home: &Path) -> io::Result<()> {
    let quarantine = Quarantine::open(home)?;
    for name in directory_names(quarantine.directory.as_raw_fd())? {
        if let Some(id) = name
            .to_str()
            .and_then(|name| name.strip_prefix(".promotion-"))
            && ulid::Ulid::from_string(id).is_ok_and(|parsed| parsed.to_string() == id)
        {
            remove_promotion_staging(home, id)?;
        }
    }
    Ok(())
}

impl RecoveryReport {
    fn failed(&mut self, proposal_id: Option<String>) {
        let diagnostic = RecoveryDiagnostic {
            proposal_id: proposal_id.filter(|id| valid_id(id)),
            code: DiagnosticCode::CleanupFailed,
        };
        if !self.diagnostics.contains(&diagnostic) {
            self.diagnostics.push(diagnostic);
        }
    }
}

/// Safe post-commit cleanup, also used by the live receipt worker under its lease.
/// `include_final` is true only for failed attempts without validated identity.
pub fn remove_receipt(home: &Path, id: &str, include_final: bool) -> io::Result<()> {
    Quarantine::open(home)?.remove(id, include_final)
}

/// Only a validated promotion operation may select this deterministic name.
/// Published store versions are deliberately outside this cleanup surface.
pub(crate) fn remove_promotion_staging(home: &Path, operation_id: &str) -> io::Result<()> {
    if !valid_id(operation_id) {
        return Err(io::Error::other("invalid promotion id"));
    }
    let quarantine = Quarantine::open(home)?;
    let name = CString::new(format!(".promotion-{operation_id}"))
        .map_err(|_| io::Error::other("invalid promotion id"))?;
    let result = remove_tree_at_mode(quarantine.directory.as_raw_fd(), &name, true);
    // SAFETY: quarantine retains this live owned directory descriptor.
    let synced = if unsafe { libc::fsync(quarantine.directory.as_raw_fd()) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    };
    result.and(synced)
}

struct Quarantine {
    directory: OwnedFd,
}
impl Quarantine {
    fn open(home: &Path) -> io::Result<Self> {
        let home: OwnedFd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(home)?
            .into();
        let extensions = open_directory(home.as_raw_fd(), c"extensions")?;
        let directory = open_directory(extensions.as_raw_fd(), c"quarantine")?;
        Ok(Self { directory })
    }
    fn remove(&self, id: &str, include_final: bool) -> io::Result<()> {
        if !valid_id(id) {
            return Err(io::Error::other("invalid proposal id"));
        }
        let temporary = CString::new(format!(".receipt-{id}"))
            .map_err(|_| io::Error::other("invalid proposal id"))?;
        let mut first_error = remove_tree_at(self.directory.as_raw_fd(), &temporary).err();
        if include_final {
            let final_name =
                CString::new(id).map_err(|_| io::Error::other("invalid proposal id"))?;
            if let Err(error) = remove_tree_at(self.directory.as_raw_fd(), &final_name) {
                first_error.get_or_insert(error);
            }
        }
        // Persist the removals from the quarantine parent. Partial cleanup stays
        // retryable and its durable proposal record is never rolled back.
        // SAFETY: this descriptor owns a live directory.
        if unsafe { libc::fsync(self.directory.as_raw_fd()) } == -1 {
            first_error.get_or_insert_with(io::Error::last_os_error);
        }
        first_error.map_or(Ok(()), Err)
    }
}

fn valid_id(id: &str) -> bool {
    id.parse::<ulid::Ulid>()
        .is_ok_and(|value| value.to_string() == id)
}
fn receipt_id(name: OsString) -> Option<String> {
    let name = name.to_str()?;
    let id = name.strip_prefix(".receipt-")?;
    valid_id(id).then(|| id.to_owned())
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn open_directory(parent: RawFd, name: &CStr) -> io::Result<OwnedFd> {
    // Linux openat2(2): BENEATH confines every component; NO_SYMLINKS implies
    // NO_MAGICLINKS; NO_XDEV rejects bind mounts as well as distinct filesystems.
    // No permissive fallback: all supported kernels provide openat2 (Linux 5.6+).
    const RESOLVE_NO_XDEV: u64 = 0x01;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV,
    };
    // SAFETY: name is NUL-terminated, how matches linux/openat2.h, and the parent
    // descriptor remains live for the syscall. Success returns a new owned fd.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            parent,
            name.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful syscall returned a fresh descriptor, owned here.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

struct DirectoryStream(*mut libc::DIR);
impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: fdopendir returned this stream and this is its sole owner.
        unsafe {
            libc::closedir(self.0);
        }
    }
}
fn directory_names(directory: RawFd) -> io::Result<Vec<OsString>> {
    // A separately opened file description prevents shared readdir offsets.
    let owned = open_directory(directory, c".")?;
    let fd = owned.into_raw_fd();
    // SAFETY: fd is an owned directory; fdopendir takes ownership on success.
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: fdopendir failed, so the descriptor is still ours to close.
        drop(unsafe { OwnedFd::from_raw_fd(fd) });
        return Err(error);
    }
    let stream = DirectoryStream(stream);
    let mut names = Vec::new();
    loop {
        // SAFETY: errno is thread-local; the stream remains valid until Drop.
        let entry = unsafe {
            *libc::__errno_location() = 0;
            libc::readdir(stream.0)
        };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(0) {
                Ok(names)
            } else {
                Err(error)
            };
        }
        // SAFETY: readdir returns a NUL-terminated name valid until the next call.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(OsString::from_vec(name.to_vec()));
        }
    }
}

fn unlink(parent: RawFd, name: &CStr, flags: i32) -> io::Result<()> {
    // SAFETY: name is NUL-terminated; relative names never contain slash or '..'.
    if unsafe { libc::unlinkat(parent, name.as_ptr(), flags) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(error)
    }
}
fn remove_tree_at(parent: RawFd, name: &CStr) -> io::Result<()> {
    remove_tree_at_mode(parent, name, false)
}

fn writable_staging_directory(directory: RawFd) -> io::Result<()> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: metadata is aligned writable storage for this live descriptor.
    if unsafe { libc::fstat(directory, metadata.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstat initialized metadata; geteuid has no preconditions.
    let metadata = unsafe { metadata.assume_init() };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || metadata.st_uid != unsafe { libc::geteuid() }
    {
        return Err(io::Error::other("unsafe promotion staging"));
    }
    // SAFETY: fchmod affects only the owned, NO_XDEV-pinned quarantine directory.
    if unsafe { libc::fchmod(directory, 0o700) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn remove_tree_at_mode(parent: RawFd, name: &CStr, writable: bool) -> io::Result<()> {
    // unlinkat never follows the last component: regular files, special files,
    // and symlinks are removed directly. A mount point fails with EBUSY.
    match unlink(parent, name, 0) {
        Ok(()) => return Ok(()),
        Err(error) if matches!(error.raw_os_error(), Some(libc::EISDIR | libc::EPERM)) => {}
        Err(error) => return Err(error),
    }
    struct Frame {
        directory: OwnedFd,
        name: CString,
        children: VecDeque<OsString>,
    }
    let directory = open_directory(parent, name)?;
    if writable {
        writable_staging_directory(directory.as_raw_fd())?;
    }
    let children = directory_names(directory.as_raw_fd())?.into();
    let mut stack = vec![Frame {
        directory,
        name: name.to_owned(),
        children,
    }];
    while let Some(frame) = stack.last_mut() {
        if let Some(child) = frame.children.pop_front() {
            let child =
                CString::new(child.as_bytes()).map_err(|_| io::Error::other("invalid entry"))?;
            match unlink(frame.directory.as_raw_fd(), &child, 0) {
                Ok(()) => {}
                Err(error) if matches!(error.raw_os_error(), Some(libc::EISDIR | libc::EPERM)) => {
                    let directory = open_directory(frame.directory.as_raw_fd(), &child)?;
                    if writable {
                        writable_staging_directory(directory.as_raw_fd())?;
                    }
                    let children = directory_names(directory.as_raw_fd())?.into();
                    stack.push(Frame {
                        directory,
                        name: child,
                        children,
                    });
                }
                Err(error) => return Err(error),
            }
        } else {
            // The frame was just observed as present; pop avoids any recursive
            // traversal stack even for malformed legacy temporary directories.
            let Some(frame) = stack.pop() else {
                return Err(io::Error::other("cleanup stack"));
            };
            let parent = stack.last().map_or(parent, |f| f.directory.as_raw_fd());
            // SAFETY: this descriptor remains live until after its subtree is
            // durably removed from its parent.
            if unsafe { libc::fsync(frame.directory.as_raw_fd()) } < 0 {
                return Err(io::Error::last_os_error());
            }
            unlink(parent, &frame.name, libc::AT_REMOVEDIR)?;
        }
    }
    Ok(())
}
