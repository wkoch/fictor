use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
};

pub const MAX_BLOB_BYTES: usize = 256 * 1024 * 1024;

#[derive(Clone)]
pub struct BlobStore {
    root: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("hash de blob inválido")]
    InvalidHash,
    #[error("blob excede 256 MiB")]
    TooLarge,
    #[error("conteúdo do blob difere do hash")]
    Corrupt,
    #[error("erro de arquivo: {0}")]
    Io(#[from] std::io::Error),
}

impl BlobStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub(super) fn home(&self) -> Result<&std::path::Path, super::StoreError> {
        self.root
            .parent()
            .ok_or(super::StoreError::Invalid("diretório de blobs sem raiz"))
    }

    fn path(&self, hash: &str) -> Result<PathBuf, BlobError> {
        let hex = hash.strip_prefix("sha256:").ok_or(BlobError::InvalidHash)?;
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(BlobError::InvalidHash);
        }
        Ok(self.root.join(&hex[..2]).join(&hex[2..]))
    }

    pub fn put(&self, data: &[u8]) -> Result<String, BlobError> {
        if data.len() > MAX_BLOB_BYTES {
            return Err(BlobError::TooLarge);
        }
        let hash = hash_bytes(data);
        let path = self.path(&hash)?;
        // Prefix directory is always below the configured private blob root.
        let parent = path.parent().ok_or(BlobError::InvalidHash)?;
        crate::home::private_dir(parent)?;
        if path.exists() {
            self.verify(&hash)?;
            return Ok(hash);
        }
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary.write_all(data)?;
        temporary.as_file().sync_all()?;
        match temporary.persist_noclobber(&path) {
            Ok(_) => {
                fs::File::open(parent)?.sync_all()?;
            }
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.verify(&hash)?;
            }
            Err(error) => return Err(BlobError::Io(error.error)),
        }
        Ok(hash)
    }

    /// Validate references without allocating the entire (up to 256 MiB) blob.
    pub fn verify(&self, hash: &str) -> Result<(), BlobError> {
        let mut file = fs::File::open(self.path(hash)?)?;
        let mut digest = Sha256::new();
        let mut total = 0usize;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let count = match file.read(&mut buffer) {
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            if count == 0 {
                break;
            }
            total += count;
            if total > MAX_BLOB_BYTES {
                return Err(BlobError::TooLarge);
            }
            digest.update(&buffer[..count]);
        }
        let hex: String = digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        if hash != format!("sha256:{hex}") {
            return Err(BlobError::Corrupt);
        }
        Ok(())
    }

    pub fn get(&self, hash: &str) -> Result<Vec<u8>, BlobError> {
        let mut bytes = Vec::new();
        fs::File::open(self.path(hash)?)?
            .take(MAX_BLOB_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_BLOB_BYTES {
            return Err(BlobError::TooLarge);
        }
        if hash_bytes(&bytes) != hash {
            return Err(BlobError::Corrupt);
        }
        Ok(bytes)
    }
}

fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("sha256:{hex}")
}

/// Private, bounded stream capture. File writes finish before bytes are exposed.
/// Temporary captures are never mounted into extensions.
pub struct Capture {
    temporary: tempfile::NamedTempFile,
    digest: Sha256,
    length: usize,
}
impl Capture {
    pub fn len(&self) -> usize {
        self.length
    }
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
    pub fn append(&mut self, bytes: &[u8]) -> Result<(), BlobError> {
        if bytes.len() > MAX_BLOB_BYTES.saturating_sub(self.length) {
            return Err(BlobError::TooLarge);
        }
        let mut remaining = bytes;
        while !remaining.is_empty() {
            match self.temporary.write(remaining) {
                Ok(0) => {
                    return Err(BlobError::Io(std::io::Error::from(
                        std::io::ErrorKind::WriteZero,
                    )));
                }
                Ok(count) => {
                    self.digest.update(&remaining[..count]);
                    self.length += count;
                    remaining = &remaining[count..];
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}
impl BlobStore {
    pub fn begin_capture(&self) -> Result<Capture, BlobError> {
        crate::home::private_dir(&self.root)?;
        let temporary = tempfile::Builder::new()
            .prefix(".model-capture-")
            .tempfile_in(&self.root)?;
        Ok(Capture {
            temporary,
            digest: Sha256::new(),
            length: 0,
        })
    }
    pub fn finish_capture(&self, capture: Capture) -> Result<String, BlobError> {
        capture.temporary.as_file().sync_all()?;
        let digest = capture.digest.finalize();
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        let hash = format!("sha256:{hex}");
        let path = self.path(&hash)?;
        let parent = path.parent().ok_or(BlobError::InvalidHash)?;
        crate::home::private_dir(parent)?;
        match capture.temporary.persist_noclobber(&path) {
            Ok(_) => fs::File::open(parent)?.sync_all()?,
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.verify(&hash)?;
            }
            Err(error) => return Err(BlobError::Io(error.error)),
        }
        Ok(hash)
    }
    pub fn cleanup_captures(&self) -> Result<(), BlobError> {
        crate::home::private_dir(&self.root)?;
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(".model-capture-"))
            {
                // A previous core owns this private prefix; remove files, never recurse.
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod capture_tests {
    use super::*;
    #[test]
    fn capture_hashes_stream_bytes_and_cleans_orphans_without_touching_blobs() {
        let root = tempfile::tempdir().unwrap();
        let store = BlobStore::new(root.path().join("blobs"));
        let mut capture = store.begin_capture().unwrap();
        capture.append(b"first").unwrap();
        capture.append(b"second").unwrap();
        let hash = store.finish_capture(capture).unwrap();
        assert_eq!(store.get(&hash).unwrap(), b"firstsecond");
        std::fs::write(root.path().join("blobs/.model-capture-orphan"), b"partial").unwrap();
        store.cleanup_captures().unwrap();
        assert!(!root.path().join("blobs/.model-capture-orphan").exists());
        assert_eq!(store.get(&hash).unwrap(), b"firstsecond");
    }
}
