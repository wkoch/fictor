//! ADR-042: compare mount sources in filesystem coordinates, including bind
//! aliases and submounts. A pathname prefix alone cannot establish separation.
use super::SandboxError;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, File},
    os::{fd::AsRawFd, unix::ffi::OsStringExt},
    path::{Component, Path, PathBuf},
};

fn invalid() -> SandboxError {
    SandboxError::Invalid("montagens não comprovam separação dos arquivos privados do core")
}

pub(crate) fn pin_home(home: &Path) -> Result<File, SandboxError> {
    let home = home.canonicalize()?;
    let file = open(&home)?;
    if !file.metadata()?.is_dir() {
        return Err(invalid());
    }
    Ok(file)
}

fn open(path: &Path) -> Result<File, SandboxError> {
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
        flags: (libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: 0x04 | 0x02,
    }; // NO_SYMLINKS | NO_MAGICLINKS
    // SAFETY: this live path and Linux open_how buffer remain valid. Canonical
    // sources must not acquire a symlink in any component during validation.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful openat2 returned this fresh owned descriptor.
    let file = unsafe { File::from_raw_fd(fd as i32) };
    if file.metadata()?.file_type().is_symlink() {
        return Err(invalid());
    }
    Ok(file)
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotEntry {
    pub relative: PathBuf,
    pub device: (u32, u32),
    pub inode: u64,
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
}

pub(super) struct ProvenSource {
    snapshot: SourceSnapshot,
    anchors: Vec<File>,
}

impl MountProof {
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
            self.sources.insert(source, snapshot);
            if let Some(proven) = proven {
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
        }
    }
}

struct Observation {
    path: PathBuf,
    origin: Origin,
    identity: Identity,
    private: bool,
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
        let file = open(source)?;
        let (visible, origin) = self.locate(source, &file)?;
        let private = self.mounts.get(&visible.mount).ok_or_else(invalid)?.private;
        let directory = file.metadata()?.is_dir();
        let mut result = vec![Observation {
            path: source.to_path_buf(),
            origin,
            identity: visible,
            private,
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
                            anchor: file,
                        });
                    }
                }
            }
        }
        Ok(result)
    }
}

fn snapshot(source: &Path, observations: &[Observation]) -> Result<SourceSnapshot, SandboxError> {
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
    let snapshot = snapshot(target, &observations)?;
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
        })
    }

    pub(super) fn check(&self, source: &Path, exceptions: &[&Path]) -> Result<(), SandboxError> {
        self.prove(source, exceptions).map(|_| ())
    }

    pub(super) fn prove(
        &self,
        source: &Path,
        exceptions: &[&Path],
    ) -> Result<ProvenSource, SandboxError> {
        let observations = self.table.sources(source)?;
        for observation in &observations {
            let origin = &observation.origin;
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
        let snapshot = snapshot(source, &observations)?;
        Ok(ProvenSource {
            snapshot,
            anchors: observations
                .into_iter()
                .map(|observation| observation.anchor)
                .collect(),
        })
    }

    pub(super) fn finish(self) -> Result<(), SandboxError> {
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
    fn separate_tree_and_system_base_have_no_private_home_overlap() {
        let home = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let anchor = pin_home(home.path()).unwrap();
        let boundary = Boundary::new(home.path(), &anchor).expect("home topology");
        boundary.check(other.path(), &[]).expect("separate tree");
        boundary.check(Path::new("/usr"), &[]).expect("system base");
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
            .record(source.clone(), Some(boundary.prove(&source, &[]).unwrap()))
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
