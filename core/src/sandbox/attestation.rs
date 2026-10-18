//! Final mount verification by the trusted init before untrusted code runs.
//! This supplements, and cannot itself establish, pre-exec bootstrap trust.
use super::{SandboxError, mounts};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Write},
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Component, Path, PathBuf},
};

// Stay below Linux's per-argument limit. An oversized proof fails closed rather
// than being truncated or moved into an untrusted file/environment variable.
pub(super) const MAX_PROOF_BYTES: usize = 64 * 1024;

fn invalid() -> SandboxError {
    SandboxError::Invalid("atestação das montagens ausente, inválida ou divergente")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    device: (u32, u32),
    inode: u64,
    filesystem: String,
    filesystem_magic: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    // Raw Linux path bytes preserve non-UTF-8 names without normalization.
    destination: Vec<u8>,
    identity: Identity,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProof {
    roots: Vec<Vec<u8>>,
    entries: Vec<Entry>,
    aliases: Vec<(Vec<u8>, Vec<u8>)>,
}

#[derive(Default)]
pub(super) struct Attestation {
    roots: BTreeSet<PathBuf>,
    entries: BTreeMap<PathBuf, Identity>,
    aliases: BTreeMap<PathBuf, PathBuf>,
}
impl Attestation {
    pub(super) fn bind(
        &mut self,
        target: &Path,
        source: &mounts::SourceSnapshot,
    ) -> Result<(), SandboxError> {
        if !absolute(target) || source.entries.is_empty() {
            return Err(invalid());
        }
        let mut entries = BTreeMap::new();
        for entry in &source.entries {
            if entry.relative.is_absolute()
                || entry
                    .relative
                    .components()
                    .any(|part| !matches!(part, Component::Normal(_)))
            {
                return Err(invalid());
            }
            if entries
                .insert(
                    target.join(&entry.relative),
                    Identity {
                        device: entry.device,
                        inode: entry.inode,
                        filesystem: entry.filesystem.clone(),
                        filesystem_magic: entry.filesystem_magic,
                    },
                )
                .is_some()
            {
                return Err(invalid());
            }
        }
        if !entries.contains_key(target) {
            return Err(invalid());
        }
        // The normalized plan has no overrides. Refuse overlap again here so
        // mount order cannot silently change the meaning of its proof.
        if self
            .roots
            .iter()
            .any(|path| path.starts_with(target) || target.starts_with(path))
        {
            return Err(invalid());
        }
        self.roots.insert(target.to_owned());
        self.entries.extend(entries);
        Ok(())
    }

    pub(super) fn alias(&mut self, destination: &Path, target: &Path) -> Result<(), SandboxError> {
        if !absolute(destination)
            || !absolute(target)
            || self
                .aliases
                .insert(destination.into(), target.into())
                .is_some()
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub(super) fn encode(&self) -> Result<String, SandboxError> {
        if self.roots.is_empty() || self.entries.is_empty() {
            return Err(invalid());
        }
        let proof = WireProof {
            roots: self
                .roots
                .iter()
                .map(|path| path.as_os_str().as_bytes().to_vec())
                .collect(),
            entries: self
                .entries
                .iter()
                .map(|(path, identity)| Entry {
                    destination: path.as_os_str().as_bytes().to_vec(),
                    identity: identity.clone(),
                })
                .collect(),
            aliases: self
                .aliases
                .iter()
                .map(|(destination, target)| {
                    (
                        destination.as_os_str().as_bytes().to_vec(),
                        target.as_os_str().as_bytes().to_vec(),
                    )
                })
                .collect(),
        };
        let mut bytes = Bounded(Vec::new());
        serde_json::to_writer(&mut bytes, &proof).map_err(|_| invalid())?;
        String::from_utf8(bytes.0).map_err(|_| invalid())
    }

    pub(super) fn parse(bytes: &str) -> Result<Self, SandboxError> {
        if bytes.len() > MAX_PROOF_BYTES {
            return Err(invalid());
        }
        let wire: WireProof = serde_json::from_str(bytes).map_err(|_| invalid())?;
        let mut proof = Self::default();
        for (destination, target) in wire.aliases {
            proof.alias(
                &PathBuf::from(std::ffi::OsString::from_vec(destination)),
                &PathBuf::from(std::ffi::OsString::from_vec(target)),
            )?;
        }
        for bytes in wire.roots {
            let path = PathBuf::from(std::ffi::OsString::from_vec(bytes));
            if !absolute(&path) || !proof.roots.insert(path) {
                return Err(invalid());
            }
        }
        for entry in wire.entries {
            let path = PathBuf::from(std::ffi::OsString::from_vec(entry.destination));
            if !absolute(&path)
                || !proof.roots.iter().any(|root| path.starts_with(root))
                || proof.entries.insert(path, entry.identity).is_some()
            {
                return Err(invalid());
            }
        }
        if proof.roots.is_empty()
            || proof
                .roots
                .iter()
                .any(|root| !proof.entries.contains_key(root))
        {
            return Err(invalid());
        }
        Ok(proof)
    }

    pub(super) fn verify(&self) -> Result<(), SandboxError> {
        for (destination, expected) in &self.aliases {
            let link = std::fs::read_link(destination)?;
            let mut actual = if link.is_absolute() {
                PathBuf::new()
            } else {
                destination.parent().ok_or_else(invalid)?.to_owned()
            };
            for component in link.components() {
                match component {
                    Component::RootDir => actual.push("/"),
                    Component::Normal(part) => actual.push(part),
                    Component::CurDir => {}
                    Component::ParentDir if actual.pop() => {}
                    _ => return Err(invalid()),
                }
            }
            if &actual != expected {
                return Err(invalid());
            }
        }
        let mut actual = BTreeMap::new();
        let mut private = true;
        for root in &self.roots {
            let source = mounts::observe_tree(root)?;
            // Source trees must no longer receive propagated host submounts
            // after this check and before/during execution of the workload.
            private &= source.private;
            for entry in source.entries {
                let path = root.join(entry.relative);
                let identity = Identity {
                    device: entry.device,
                    inode: entry.inode,
                    filesystem: entry.filesystem,
                    filesystem_magic: entry.filesystem_magic,
                };
                if actual
                    .insert(path, identity.clone())
                    .is_some_and(|old| old != identity)
                {
                    return Err(invalid());
                }
            }
        }
        if actual != self.entries {
            return Err(SandboxError::Invalid(
                "atestação das identidades ou topologia das montagens divergiu",
            ));
        }
        if !private {
            return Err(SandboxError::Invalid(
                "atestação encontrou montagem que recebe propagação externa",
            ));
        }
        Ok(())
    }
}

fn absolute(path: &Path) -> bool {
    path.is_absolute()
        && !path.as_os_str().as_bytes().contains(&0)
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > MAX_PROOF_BYTES {
            return Err(io::Error::other("mount proof limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::mounts::{SnapshotEntry, SourceSnapshot};

    fn source(entries: &[(&str, u64)]) -> SourceSnapshot {
        SourceSnapshot {
            entries: entries
                .iter()
                .map(|(relative, inode)| SnapshotEntry {
                    relative: relative.into(),
                    device: (1, 2),
                    inode: *inode,
                    filesystem: "tmpfs".into(),
                    filesystem_magic: libc::TMPFS_MAGIC as u64,
                })
                .collect(),
            private: true,
        }
    }

    #[test]
    fn proof_rejects_nested_binds_instead_of_overlaying_an_earlier_proof() {
        let mut proof = Attestation::default();
        proof
            .bind(
                Path::new("/work"),
                &source(&[("", 1), ("nested", 2), ("nested/covered", 3)]),
            )
            .unwrap();
        assert!(
            proof
                .bind(Path::new("/work/nested"), &source(&[("", 4), ("new", 5)]))
                .is_err()
        );
        assert_eq!(proof.entries.len(), 3);
        assert_eq!(proof.entries[Path::new("/work/nested")].inode, 2);
        assert!(
            proof
                .entries
                .contains_key(Path::new("/work/nested/covered"))
        );
        let encoded = proof.encode().unwrap();
        assert_eq!(
            Attestation::parse(&encoded).unwrap().encode().unwrap(),
            encoded
        );
        assert!(proof.bind(Path::new("/work"), &source(&[("", 6)])).is_err());
        assert_eq!(proof.roots.len(), 1);
        assert_eq!(proof.entries.len(), 3);
        assert_eq!(proof.entries[Path::new("/work")].inode, 1);
    }

    #[test]
    fn malformed_duplicate_unbounded_or_unconfined_proofs_are_refused() {
        for encoded in [
            "",
            "{}",
            "null",
            "{\"roots\":[],\"entries\":[]}",
            "{\"roots\":[],\"entries\":[],\"extra\":true}",
        ] {
            assert!(Attestation::parse(encoded).is_err());
        }
        assert!(Attestation::parse(&" ".repeat(MAX_PROOF_BYTES + 1)).is_err());
        let mut proof = Attestation::default();
        assert!(
            proof
                .bind(Path::new("relative"), &source(&[("", 1)]))
                .is_err()
        );
        assert!(
            proof
                .bind(Path::new("/work"), &source(&[("../escape", 1)]))
                .is_err()
        );
        assert!(
            proof
                .bind(Path::new("/work"), &source(&[("", 1), ("", 2)]))
                .is_err()
        );
        proof.bind(Path::new("/work"), &source(&[("", 1)])).unwrap();
        let mut wire: serde_json::Value = serde_json::from_str(&proof.encode().unwrap()).unwrap();
        let duplicate = wire["roots"][0].clone();
        wire["roots"].as_array_mut().unwrap().push(duplicate);
        assert!(Attestation::parse(&wire.to_string()).is_err());
        let mut oversized = Attestation::default();
        oversized
            .bind(
                &PathBuf::from(format!("/{}", "a".repeat(MAX_PROOF_BYTES))),
                &source(&[("", 1)]),
            )
            .unwrap();
        assert!(oversized.encode().is_err());
    }
}
