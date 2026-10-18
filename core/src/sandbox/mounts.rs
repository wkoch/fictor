//! ADR-042/044: pin original sources without magic links, classify their actual
//! filesystem, and compare bind aliases/submounts in filesystem coordinates.
use super::{SandboxError, plan::SourcePurpose};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, File},
    os::{fd::AsRawFd, unix::ffi::OsStringExt},
    path::{Component, Path, PathBuf},
};

fn invalid() -> SandboxError {
    SandboxError::Invalid("montagens não comprovam separação dos arquivos privados do core")
}

/// Resolve the original reference before ordinary canonicalization can erase
/// a kernel magic-link traversal. Ordinary symlinks remain supported.
pub(crate) fn canonicalize(path: &Path) -> Result<PathBuf, SandboxError> {
    Ok(resolve(path)?.0)
}

pub(crate) fn pin_home(home: &Path) -> Result<File, SandboxError> {
    let (_, file) = resolve(home)?;
    if !file.metadata()?.is_dir() {
        return Err(invalid());
    }
    Ok(file)
}

fn open_at(directory: i32, path: &Path, resolve: u64) -> Result<File, SandboxError> {
    use std::{
        ffi::CString,
        os::{fd::FromRawFd, unix::ffi::OsStrExt},
    };
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| invalid())?;
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve,
    };
    // SAFETY: live pathname and Linux open_how buffer. O_PATH never opens the
    // source for content reads, including FIFOs and pseudo-files.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory,
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful openat2 returned this fresh owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}

fn open(path: &Path) -> Result<File, SandboxError> {
    open_at(libc::AT_FDCWD, path, 0x04 | 0x02) // NO_SYMLINKS | NO_MAGICLINKS
}

fn resolve(path: &Path) -> Result<(PathBuf, File), SandboxError> {
    let file = open_at(libc::AT_FDCWD, path, 0x02)?; // NO_MAGICLINKS, symlinks allowed
    // This is our own pinned descriptor's name, not traversal of a supplied
    // magic link. Reopening below ties that name to the same live object.
    let canonical = fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
    if !canonical.is_absolute() || identity(&open(&canonical)?)? != identity(&file)? {
        return Err(invalid());
    }
    Ok((canonical, file))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    mount: u64,
    device: (u32, u32),
    inode: u64,
}

fn identity(file: &File) -> Result<Identity, SandboxError> {
    // SAFETY: statx fills this initialized Linux ABI buffer; the empty path
    // names the live descriptor and does not reinterpret the original pathname.
    let mut stat: libc::statx = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::statx(
            file.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_INO | libc::STATX_MNT_ID,
            &mut stat,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if stat.stx_mask & (libc::STATX_INO | libc::STATX_MNT_ID)
        != libc::STATX_INO | libc::STATX_MNT_ID
    {
        return Err(invalid());
    }
    Ok(Identity {
        mount: stat.stx_mnt_id,
        device: (stat.stx_dev_major, stat.stx_dev_minor),
        inode: stat.stx_ino,
    })
}

fn filesystem_magic(file: &File) -> Result<u64, SandboxError> {
    // SAFETY: fstatfs observes the same pinned O_PATH descriptor as statx.
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(stat.f_type as u32 as u64)
}

fn ordinary_filesystem(name: &str, magic: u64) -> bool {
    // Both fields are necessary: devtmpfs shares TMPFS_MAGIC. Names such as
    // fuse.ext4 or tmpfs.extra do not inherit another filesystem's admission.
    matches!(
        (name, magic),
        ("ext2" | "ext3" | "ext4", 0xef53)
            | ("btrfs", 0x9123_683e)
            | ("xfs", 0x5846_5342)
            | ("tmpfs", 0x0102_1994)
    )
}

fn fixed_base(path: &Path) -> bool {
    super::plan::BASES
        .iter()
        .any(|base| path == Path::new(base))
}

fn origin_error(path: &Path, filesystem: &str, rule: &'static str) -> SandboxError {
    SandboxError::Origin {
        resource: path.into(),
        filesystem: filesystem.into(),
        rule,
    }
}

#[derive(Debug, Clone)]
struct Origin {
    device: (u32, u32),
    path: PathBuf,
}

impl Origin {
    fn overlaps(&self, other: &Self) -> bool {
        self.device == other.device
            && (self.path.starts_with(&other.path) || other.path.starts_with(&self.path))
    }
}

#[derive(Debug)]
struct Mount {
    device: (u32, u32),
    root: PathBuf,
    point: PathBuf,
    private: bool,
    filesystem: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotEntry {
    pub relative: PathBuf,
    pub device: (u32, u32),
    pub inode: u64,
    pub filesystem: String,
    pub filesystem_magic: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceSnapshot {
    pub entries: Vec<SnapshotEntry>,
    pub private: bool,
}

#[derive(Default)]
pub(crate) struct MountProof {
    sources: BTreeMap<PathBuf, Option<SourceSnapshot>>,
    // CLOEXEC O_PATH anchors prevent inode reuse before the init attests.
    anchors: Vec<File>,
    roots: BTreeMap<PathBuf, (PathBuf, usize)>,
}

pub(super) struct ProvenSource {
    path: PathBuf,
    snapshot: SourceSnapshot,
    anchors: Vec<File>,
}

impl MountProof {
    pub(super) fn covers(
        &self,
        outer: &Path,
        inner: &Path,
        relative: &Path,
    ) -> Result<bool, SandboxError> {
        let inner_snapshot = self.source(inner)?;
        let (_, inner_index) = self.roots.get(inner).ok_or_else(invalid)?;
        self.covers_snapshot(outer, &self.anchors[*inner_index], inner_snapshot, relative)
    }

    fn covers_snapshot(
        &self,
        outer: &Path,
        inner_file: &File,
        inner: &SourceSnapshot,
        relative: &Path,
    ) -> Result<bool, SandboxError> {
        if relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(invalid());
        }
        let (_, outer_index) = self.roots.get(outer).ok_or_else(invalid)?;
        let outer_file = &self.anchors[*outer_index];
        let relative_file = if relative.as_os_str().is_empty() {
            outer_file.try_clone()?
        } else {
            open_at(outer_file.as_raw_fd(), relative, 0x08 | 0x02)? // BENEATH | NO_MAGICLINKS
        };
        let actual = identity(&relative_file)?;
        let expected = identity(inner_file)?;
        if (actual.device, actual.inode) != (expected.device, expected.inode)
            || filesystem_magic(&relative_file)? != filesystem_magic(inner_file)?
        {
            return Ok(false);
        }
        let outer = self.source(outer)?;
        let mut expected_children = BTreeMap::new();
        for entry in &outer.entries {
            if let Ok(suffix) = entry.relative.strip_prefix(relative) {
                let mut entry = entry.clone();
                entry.relative = suffix.into();
                expected_children.insert(entry.relative.clone(), entry);
            }
        }
        // A child that is not itself a mountpoint still has its own root inode.
        // The openat2 comparison above proves that root, while the parent
        // snapshot proves every visible submount below it.
        let root = inner.entries.first().ok_or_else(invalid)?;
        if !root.relative.as_os_str().is_empty() {
            return Err(invalid());
        }
        let covering = outer
            .entries
            .iter()
            .filter(|entry| relative.starts_with(&entry.relative))
            .max_by_key(|entry| entry.relative.components().count())
            .ok_or_else(invalid)?;
        if (root.filesystem.as_str(), root.filesystem_magic)
            != (covering.filesystem.as_str(), covering.filesystem_magic)
        {
            return Ok(false);
        }
        if expected_children
            .get(Path::new(""))
            .is_some_and(|entry| entry != root)
        {
            return Ok(false);
        }
        expected_children.insert(PathBuf::new(), root.clone());
        Ok(expected_children.values().eq(inner.entries.iter()))
    }

    pub(crate) fn source(&self, source: &Path) -> Result<&SourceSnapshot, SandboxError> {
        self.optional_source(source)?.ok_or_else(invalid)
    }
    pub(crate) fn optional_source(
        &self,
        source: &Path,
    ) -> Result<Option<&SourceSnapshot>, SandboxError> {
        self.sources
            .get(source)
            .map(Option::as_ref)
            .ok_or_else(invalid)
    }
    pub(super) fn record(
        &mut self,
        source: PathBuf,
        proven: Option<ProvenSource>,
    ) -> Result<(), SandboxError> {
        let snapshot = proven.as_ref().map(|proven| proven.snapshot.clone());
        if let Some(previous) = self.sources.get(&source) {
            if previous != &snapshot {
                return Err(invalid());
            }
        } else {
            self.sources.insert(source.clone(), snapshot);
            if let Some(proven) = proven {
                self.roots.insert(source, (proven.path, self.anchors.len()));
                self.anchors.extend(proven.anchors);
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn for_test(sources: BTreeMap<PathBuf, Option<SourceSnapshot>>) -> Self {
        Self {
            sources,
            anchors: Vec::new(),
            roots: BTreeMap::new(),
        }
    }
}

struct Observation {
    path: PathBuf,
    origin: Origin,
    identity: Identity,
    private: bool,
    filesystem: String,
    filesystem_magic: u64,
    anchor: File,
}

struct Table {
    bytes: Vec<u8>,
    mounts: BTreeMap<u64, Mount>,
}

impl Table {
    fn read() -> Result<Self, SandboxError> {
        Self::parse(fs::read("/proc/self/mountinfo")?)
    }

    fn parse(bytes: Vec<u8>) -> Result<Self, SandboxError> {
        let mut mounts = BTreeMap::new();
        for line in bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let fields: Vec<_> = line.split(|byte| *byte == b' ').collect();
            let separator = fields
                .iter()
                .position(|field| *field == b"-")
                .ok_or_else(invalid)?;
            if separator < 6 || fields.len() != separator + 4 {
                return Err(invalid());
            }
            let number = |field: &[u8]| -> Result<u64, SandboxError> {
                let text = std::str::from_utf8(field).map_err(|_| invalid())?;
                if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(invalid());
                }
                text.parse().map_err(|_| invalid())
            };
            let id = number(fields[0])?;
            number(fields[1])?;
            let colon = fields[2]
                .iter()
                .position(|byte| *byte == b':')
                .ok_or_else(invalid)?;
            let (major, minor) = (&fields[2][..colon], &fields[2][colon + 1..]);
            let device = (
                u32::try_from(number(major)?).map_err(|_| invalid())?,
                u32::try_from(number(minor)?).map_err(|_| invalid())?,
            );
            let mount = Mount {
                device,
                root: path(fields[3])?,
                filesystem: std::str::from_utf8(fields[separator + 1])
                    .map_err(|_| invalid())?
                    .to_owned(),
                point: path(fields[4])?,
                private: !fields[6..separator].iter().any(|field| {
                    field.starts_with(b"shared:")
                        || field.starts_with(b"master:")
                        || field.starts_with(b"propagate_from:")
                }),
            };
            if mounts.insert(id, mount).is_some() {
                return Err(invalid());
            }
        }
        if mounts.is_empty() {
            return Err(invalid());
        }
        Ok(Self { bytes, mounts })
    }

    fn locate(&self, source: &Path, file: &File) -> Result<(Identity, Origin), SandboxError> {
        let identity = identity(file)?;
        let mount = self.mounts.get(&identity.mount).ok_or_else(invalid)?;
        // Overlayfs can report a backing st_dev for non-directory inodes.
        // Keep mountinfo coordinates separate from dev/ino used by attestation.
        let relative = source.strip_prefix(&mount.point).map_err(|_| invalid())?;
        Ok((
            identity,
            Origin {
                device: mount.device,
                path: mount.root.join(relative),
            },
        ))
    }

    fn sources(&self, source: &Path) -> Result<Vec<Observation>, SandboxError> {
        let (source, file) = resolve(source)?;
        let source = source.as_path();
        let (visible, origin) = self.locate(source, &file)?;
        let private = self.mounts.get(&visible.mount).ok_or_else(invalid)?.private;
        let directory = file.metadata()?.is_dir();
        let mut result = vec![Observation {
            path: source.to_path_buf(),
            origin,
            identity: visible,
            private,
            filesystem: self.mounts[&visible.mount].filesystem.clone(),
            filesystem_magic: filesystem_magic(&file)?,
            anchor: file,
        }];
        if directory {
            for (id, mount) in &self.mounts {
                if mount.point != source && mount.point.starts_with(source) {
                    let file = open(&mount.point)?;
                    let (visible, origin) = self.locate(&mount.point, &file)?;
                    // A covered mount is not visible. Its covering mount is
                    // checked instead, using the mount ID of the pinned inode.
                    if visible.mount == *id {
                        result.push(Observation {
                            path: mount.point.clone(),
                            origin,
                            identity: visible,
                            private: mount.private,
                            filesystem: mount.filesystem.clone(),
                            filesystem_magic: filesystem_magic(&file)?,
                            anchor: file,
                        });
                    }
                }
            }
        }
        for observation in &result {
            if identity(&observation.anchor)? != observation.identity
                || filesystem_magic(&observation.anchor)? != observation.filesystem_magic
            {
                return Err(invalid());
            }
        }
        Ok(result)
    }
}

fn snapshot(observations: &[Observation]) -> Result<SourceSnapshot, SandboxError> {
    let source = &observations.first().ok_or_else(invalid)?.path;
    let mut entries = observations
        .iter()
        .map(|observation| {
            Ok(SnapshotEntry {
                relative: observation
                    .path
                    .strip_prefix(source)
                    .map_err(|_| invalid())?
                    .to_path_buf(),
                device: observation.identity.device,
                inode: observation.identity.inode,
                filesystem: observation.filesystem.clone(),
                filesystem_magic: observation.filesystem_magic,
            })
        })
        .collect::<Result<Vec<_>, SandboxError>>()?;
    entries.sort_by(|left, right| left.relative.cmp(&right.relative));
    Ok(SourceSnapshot {
        entries,
        private: observations.iter().all(|observation| observation.private),
    })
}

/// Observation only, for the private init after mounting; this does not
/// authorize a host source or replace Boundary::prove's validated snapshot.
pub(crate) fn observe_tree(target: &Path) -> Result<SourceSnapshot, SandboxError> {
    let table = Table::read()?;
    let observations = table.sources(target)?;
    let snapshot = snapshot(&observations)?;
    if fs::read("/proc/self/mountinfo")? != table.bytes {
        return Err(invalid());
    }
    Ok(snapshot)
}

fn path(encoded: &[u8]) -> Result<PathBuf, SandboxError> {
    let mut bytes = Vec::new();
    let mut offset = 0;
    while offset < encoded.len() {
        if encoded[offset] == b'\\' {
            let digits = encoded.get(offset + 1..offset + 4).ok_or_else(invalid)?;
            if !digits.iter().all(|byte| (b'0'..=b'7').contains(byte)) {
                return Err(invalid());
            }
            let value = (u16::from(digits[0] - b'0') * 64)
                + (u16::from(digits[1] - b'0') * 8)
                + u16::from(digits[2] - b'0');
            bytes.push(u8::try_from(value).map_err(|_| invalid())?);
            offset += 4;
        } else {
            bytes.push(encoded[offset]);
            offset += 1;
        }
    }
    if bytes.contains(&0) {
        return Err(invalid());
    }
    let path = PathBuf::from(OsString::from_vec(bytes));
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid());
    }
    Ok(path)
}

pub(super) struct Boundary<'a> {
    home: &'a Path,
    anchor: &'a File,
    table: Table,
    private: Vec<(PathBuf, Origin)>,
    sealed: Vec<Origin>,
    sealed_roots: Vec<(PathBuf, File)>,
    fixed_bases: RefCell<Vec<(PathBuf, File)>>,
}

impl<'a> Boundary<'a> {
    pub(super) fn new(home: &'a Path, anchor: &'a File) -> Result<Self, SandboxError> {
        let current = open(home)?;
        if identity(&current)? != identity(anchor)? {
            return Err(invalid());
        }
        let table = Table::read()?;
        table.locate(home, anchor)?;
        let private = table
            .sources(home)?
            .into_iter()
            .map(|observation| (observation.path, observation.origin))
            .collect();
        Ok(Self {
            home,
            anchor,
            table,
            private,
            sealed: Vec::new(),
            sealed_roots: Vec::new(),
            fixed_bases: RefCell::new(Vec::new()),
        })
    }

    /// Host preparation files never belong to an imported tree. Unlike the
    /// instance's data/bundle exceptions, no grant may expose this directory,
    /// its ancestors, descendants or bind aliases. `${tmp}` generates an empty
    /// namespace directory and does not import these host contents.
    pub(super) fn protect_temporary(
        &mut self,
        path: &Path,
        proof: &mut MountProof,
    ) -> Result<(), SandboxError> {
        for (index, observation) in self.table.sources(path)?.into_iter().enumerate() {
            if index == 0 {
                self.sealed_roots
                    .push((path.into(), observation.anchor.try_clone()?));
            }
            self.sealed.push(observation.origin);
            proof.anchors.push(observation.anchor);
        }
        Ok(())
    }

    pub(super) fn check(&self, source: &Path, exceptions: &[&Path]) -> Result<(), SandboxError> {
        self.prove(source, exceptions, SourcePurpose::Ordinary)
            .map(|_| ())
    }

    pub(super) fn prove(
        &self,
        source: &Path,
        exceptions: &[&Path],
        purpose: SourcePurpose,
    ) -> Result<ProvenSource, SandboxError> {
        self.prove_inner(source, exceptions, Some(purpose))
    }

    pub(super) fn prove_covered(
        &self,
        source: &Path,
        exceptions: &[&Path],
        outer: &Path,
        proof: &MountProof,
    ) -> Result<ProvenSource, SandboxError> {
        let proven = self.prove_inner(source, exceptions, None)?;
        let (outer_path, _) = proof.roots.get(outer).ok_or_else(invalid)?;
        let relative = proven
            .path
            .strip_prefix(outer_path)
            .map_err(|_| invalid())?;
        if !proof.covers_snapshot(outer, &proven.anchors[0], &proven.snapshot, relative)? {
            return Err(invalid());
        }
        Ok(proven)
    }

    fn prove_inner(
        &self,
        source: &Path,
        exceptions: &[&Path],
        purpose: Option<SourcePurpose>,
    ) -> Result<ProvenSource, SandboxError> {
        let observations = self.table.sources(source)?;
        if let Some(purpose) = purpose {
            self.classify(source, purpose, &observations)?;
        }
        for observation in &observations {
            let origin = &observation.origin;
            if self.sealed.iter().any(|sealed| origin.overlaps(sealed)) {
                return Err(origin_error(
                    &observation.path,
                    &observation.filesystem,
                    "import expõe temporário de preparação privado do core",
                ));
            }
            for (private_path, private_origin) in &self.private {
                if !origin.overlaps(private_origin) {
                    continue;
                }
                let exposed = if let Ok(relative) = origin.path.strip_prefix(&private_origin.path) {
                    private_path.join(relative)
                } else {
                    private_path.clone()
                };
                if !exceptions
                    .iter()
                    .any(|allowed| exposed.starts_with(allowed))
                {
                    return Err(invalid());
                }
            }
        }
        let snapshot = snapshot(&observations)?;
        if purpose == Some(SourcePurpose::SystemBase) {
            self.fixed_bases.borrow_mut().push((
                observations[0].path.clone(),
                observations[0].anchor.try_clone()?,
            ));
        }
        Ok(ProvenSource {
            path: observations[0].path.clone(),
            snapshot,
            anchors: observations
                .into_iter()
                .map(|observation| observation.anchor)
                .collect(),
        })
    }

    fn classify(
        &self,
        original: &Path,
        purpose: SourcePurpose,
        observations: &[Observation],
    ) -> Result<(), SandboxError> {
        let root = observations.first().ok_or_else(invalid)?;
        if purpose == SourcePurpose::SystemBase && !fixed_base(original) {
            return Err(origin_error(
                original,
                &root.filesystem,
                "função de base fora da lista fixa",
            ));
        }
        if purpose == SourcePurpose::SystemBase {
            let expected_file = [
                "/etc/localtime",
                "/etc/passwd",
                "/etc/group",
                "/etc/nsswitch.conf",
            ]
            .iter()
            .any(|path| original == Path::new(path));
            let metadata = root.anchor.metadata()?;
            if !(if expected_file {
                metadata.is_file()
            } else {
                metadata.is_dir()
            }) {
                return Err(origin_error(
                    original,
                    &root.filesystem,
                    "tipo da base fixa divergiu",
                ));
            }
            if root.path.starts_with("/run")
                && !(original == Path::new("/etc/localtime")
                    && root.path.starts_with("/run/host/usr/share/zoneinfo"))
            {
                return Err(origin_error(
                    original,
                    &root.filesystem,
                    "exceção nominal de timezone inválida",
                ));
            }
        }
        for (index, observation) in observations.iter().enumerate() {
            let kind = observation.anchor.metadata()?.file_type();
            let endpoint = purpose == SourcePurpose::Endpoint && index == 0;
            use std::os::unix::fs::FileTypeExt;
            if !(if endpoint {
                kind.is_socket()
            } else {
                kind.is_dir() || kind.is_file()
            }) {
                return Err(origin_error(
                    &observation.path,
                    &observation.filesystem,
                    "tipo de objeto não admitido",
                ));
            }
            if ordinary_filesystem(&observation.filesystem, observation.filesystem_magic) {
                // Btrfs getattr reports the subvolume's anon_dev, while
                // mountinfo describes the mounted superblock. Keep both:
                // statx's mount ID binds fstatfs/type to the right table row;
                // the unchanged FD dev/ino is still required at attestation.
                // https://raw.githubusercontent.com/torvalds/linux/master/fs/btrfs/inode.c
                // btrfs_getattr: stat->dev = BTRFS_I(inode)->root->anon_dev.
                if observation.filesystem != "btrfs"
                    && self.table.mounts[&observation.identity.mount].device
                        != observation.identity.device
                {
                    return Err(origin_error(
                        &observation.path,
                        &observation.filesystem,
                        "FD e montagem divergem",
                    ));
                }
                continue;
            }
            let overlay =
                observation.filesystem == "overlay" && observation.filesystem_magic == 0x794c_7630;
            let base_root = purpose == SourcePurpose::SystemBase && index == 0;
            let toolbox = purpose == SourcePurpose::SystemBase
                && original == Path::new("/usr")
                && observation.path == Path::new("/usr/bin/toolbox")
                && kind.is_file();
            let bootstrap = purpose == SourcePurpose::Bootstrap
                && index == 0
                && self.fixed_bases.borrow().iter().any(|(base, anchor)| {
                    let Ok(relative) = observation.path.strip_prefix(base) else {
                        return false;
                    };
                    let Ok(file) = open_at(
                        anchor.as_raw_fd(),
                        if relative.as_os_str().is_empty() {
                            Path::new(".")
                        } else {
                            relative
                        },
                        0x08 | 0x02,
                    ) else {
                        return false;
                    };
                    identity(&file).is_ok_and(|seen| seen == observation.identity)
                });
            if !overlay || !(base_root || toolbox || bootstrap) {
                return Err(origin_error(
                    &observation.path,
                    &observation.filesystem,
                    "origem fora da lista fechada ADR-044",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn finish(self) -> Result<(), SandboxError> {
        for (path, anchor) in &self.sealed_roots {
            if identity(&open(path)?)? != identity(anchor)? {
                return Err(invalid());
            }
        }
        if fs::read("/proc/self/mountinfo")? != self.table.bytes
            || identity(&open(self.home)?)? != identity(self.anchor)?
        {
            return Err(invalid());
        }
        Ok(())
    }
}

pub(crate) fn check_workspace(
    home: &Path,
    anchor: &File,
    workspace: &Path,
) -> Result<(), SandboxError> {
    let boundary = Boundary::new(home, anchor)?;
    boundary.check(workspace, &[])?;
    boundary.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filesystem_admission_requires_both_exact_mount_name_and_fd_magic() {
        for (name, magic) in [
            ("ext2", 0xef53),
            ("ext3", 0xef53),
            ("ext4", 0xef53),
            ("btrfs", 0x9123_683e),
            ("xfs", 0x5846_5342),
            ("tmpfs", 0x0102_1994),
        ] {
            assert!(ordinary_filesystem(name, magic), "{name}");
            assert!(
                !ordinary_filesystem(name, magic ^ 1),
                "{name}: mismatched FD"
            );
            assert!(!ordinary_filesystem(&format!("{name}.extra"), magic));
        }
        for (name, magic) in [
            ("devtmpfs", 0x0102_1994),
            ("proc", 0x9fa0),
            ("sysfs", 0x6265_6572),
            ("devpts", 0x1cd1),
            ("cgroup", 0x0027_e0eb),
            ("cgroup2", 0x6367_7270),
            ("fuse", 0x6573_5546),
            ("fuseblk", 0x6573_5546),
            ("fuse.ext4", 0xef53),
            ("fuse.tmpfs", 0x0102_1994),
            ("nfs", 0x6969),
            ("nfs4", 0x6969),
            ("overlay", 0x794c_7630),
            ("unknown", 0xef53),
            ("tmpfs", 0xef53),
            ("EXT4", 0xef53),
        ] {
            assert!(!ordinary_filesystem(name, magic), "{name}");
        }
    }

    #[test]
    fn redundant_reads_require_pinned_subtree_identity_and_topology() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("core");
        let data = root.path().join("data");
        let child = data.join("child");
        fs::create_dir(&home).unwrap();
        fs::create_dir_all(&child).unwrap();
        fs::write(child.join("input"), "fake input").unwrap();
        let anchor = pin_home(&home).unwrap();
        let boundary = Boundary::new(&home, &anchor).unwrap();
        let mut proof = MountProof::default();
        proof
            .record(
                data.clone(),
                Some(boundary.prove(&data, &[], SourcePurpose::Ordinary).unwrap()),
            )
            .unwrap();
        proof
            .record(
                child.clone(),
                Some(boundary.prove_covered(&child, &[], &data, &proof).unwrap()),
            )
            .unwrap();
        assert!(proof.covers(&data, &child, Path::new("child")).unwrap());
        let input = child.join("input");
        proof
            .record(
                input.clone(),
                Some(
                    boundary
                        .prove(&input, &[], SourcePurpose::Ordinary)
                        .unwrap(),
                ),
            )
            .unwrap();
        let repeated = boundary.prove_covered(&input, &[], &input, &proof).unwrap();
        assert_eq!(repeated.snapshot, *proof.source(&input).unwrap());
        assert!(proof.covers(&input, &input, Path::new("")).unwrap());
        assert!(
            !proof
                .covers(&data, &child, Path::new("child/input"))
                .unwrap()
        );
        fs::rename(&child, data.join("old")).unwrap();
        fs::create_dir(&child).unwrap();
        assert!(!proof.covers(&data, &child, Path::new("child")).unwrap());
        assert!(
            proof
                .covers(&data, &child, Path::new("../data/child"))
                .is_err()
        );
        boundary.finish().unwrap();
    }

    #[test]
    fn preparation_temporary_has_no_import_exception_and_retains_its_identity() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("core");
        let temporary = root.path().join("preparation/private");
        let sibling = root.path().join("data");
        for path in [&home, &temporary, &sibling] {
            fs::create_dir_all(path).unwrap();
        }
        let anchor = pin_home(&home).unwrap();
        let mut boundary = Boundary::new(&home, &anchor).unwrap();
        let mut proof = MountProof::default();
        boundary.protect_temporary(&temporary, &mut proof).unwrap();
        for path in [temporary.as_path(), temporary.parent().unwrap()] {
            assert!(
                boundary
                    .prove(path, &[path], SourcePurpose::Ordinary)
                    .is_err()
            );
        }
        boundary.check(&sibling, &[]).unwrap();
        fs::rename(&temporary, root.path().join("original-preparation")).unwrap();
        fs::create_dir(&temporary).unwrap();
        assert!(boundary.finish().is_err());
        assert!(proof.anchors.iter().all(|file| {
            // SAFETY: owned descriptors remain live for this metadata query.
            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
            flags >= 0 && flags & libc::FD_CLOEXEC != 0
        }));
    }

    #[test]
    fn separate_tree_and_system_base_have_no_private_home_overlap() {
        let home = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let anchor = pin_home(home.path()).unwrap();
        let boundary = Boundary::new(home.path(), &anchor).expect("home topology");
        boundary.check(other.path(), &[]).expect("separate tree");
        boundary
            .prove(Path::new("/usr"), &[], SourcePurpose::SystemBase)
            .expect("system base");
        boundary.finish().expect("unchanged topology");
    }

    #[test]
    fn mountinfo_decodes_paths_without_treating_escaped_separators_as_fields() {
        let table = Table::parse(b"10 1 8:1 /private\\040home /alias\\040home rw - ext4 /dev/test rw\n11 10 8:1 /private\\040home/config.toml /workspace/control rw shared:1 - ext4 /dev/test rw\n".to_vec()).unwrap();
        assert_eq!(table.mounts[&10].root, Path::new("/private home"));
        assert_eq!(table.mounts[&10].point, Path::new("/alias home"));
        assert_eq!(
            table.mounts[&11].root,
            Path::new("/private home/config.toml")
        );
        for invalid in [
            "",
            "10 1 8:1 / /alias rw\n",
            "10 1 8:1 / /alias rw - ext4 /dev/test\n",
            "10 1 8:1 / /alias\\xyz rw - ext4 /dev/test rw\n",
            "10 1 8:1 relative /alias rw - ext4 /dev/test rw\n",
            "10 1 8:1 / /alias rw - ext4 /dev/test rw\n10 1 8:1 / /second rw - ext4 /dev/test rw\n",
        ] {
            assert!(Table::parse(invalid.as_bytes().to_vec()).is_err());
        }
    }

    #[test]
    fn pinned_home_replacement_is_not_a_new_trusted_identity() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("core");
        fs::create_dir(&home).unwrap();
        let anchor = pin_home(&home).unwrap();
        fs::rename(&home, root.path().join("old")).unwrap();
        fs::create_dir(&home).unwrap();
        assert!(Boundary::new(&home, &anchor).is_err());
    }

    #[test]
    fn proof_pins_the_observed_inode_and_never_inherits_its_descriptors() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("core");
        fs::create_dir(&home).unwrap();
        let source = root.path().join("input");
        fs::write(&source, "original").unwrap();
        let anchor = pin_home(&home).unwrap();
        let boundary = Boundary::new(&home, &anchor).unwrap();
        let mut proof = MountProof::default();
        proof
            .record(
                source.clone(),
                Some(
                    boundary
                        .prove(&source, &[], SourcePurpose::Ordinary)
                        .unwrap(),
                ),
            )
            .unwrap();
        boundary.finish().unwrap();
        let expected = proof.source(&source).unwrap().entries[0].clone();
        fs::remove_file(&source).unwrap();
        fs::write(&source, "replacement").unwrap();
        let pinned = identity(&proof.anchors[0]).unwrap();
        assert_eq!(
            (pinned.device, pinned.inode),
            (expected.device, expected.inode)
        );
        assert_ne!(
            identity(&open(&source).unwrap()).unwrap().inode,
            expected.inode
        );
        for descriptor in proof.anchors.iter().chain(std::iter::once(&anchor)) {
            // SAFETY: each descriptor is owned and live throughout F_GETFD.
            let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
            assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
        }
    }

    #[test]
    fn optional_absence_is_recorded_and_never_confused_with_an_unproven_source() {
        let mut proof = MountProof::default();
        let absent = Path::new("/optional/absent");
        proof.record(absent.into(), None).unwrap();
        assert!(proof.optional_source(absent).unwrap().is_none());
        assert!(proof.source(absent).is_err());
        assert!(proof.optional_source(Path::new("/unproven")).is_err());
    }
}
