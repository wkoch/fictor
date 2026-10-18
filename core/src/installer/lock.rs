//! Schema-1 extension lock persistence. This module neither approves nor promotes.
pub use super::overrides::Overrides;
use crate::gateway::PinnedCatalog;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("invalid extension lock")]
    Invalid,
    #[error("unsafe extension lock path or permissions")]
    UnsafePath,
    #[error("another extension lock writer is active or left a temporary file")]
    Busy,
    #[error("extension lock I/O failed")]
    Io(#[source] std::io::Error),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lock {
    pub schema: u32,
    pub extensions: BTreeMap<String, LockedExtension>,
}
impl Default for Lock {
    fn default() -> Self {
        Self {
            schema: 1,
            extensions: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedExtension {
    pub enabled: bool,
    pub active: String,
    pub versions: BTreeMap<String, LockedVersion>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedVersion {
    pub version: String,
    pub hash: String,
    pub path: String,
    pub source: Value,
    pub approved: Approval,
    #[serde(default)]
    pub overrides: Overrides,
    pub privileges: Vec<String>,
    pub tools: Vec<Value>,
    pub tools_hash: String,
    pub packages: Vec<Package>,
    pub audit: Option<Value>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub by: String,
    pub at: String,
    pub approval_id: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

impl LockedVersion {
    /// Never trust a persisted tools_hash without revalidating the catalog.
    pub fn catalog(&self) -> Result<PinnedCatalog, LockError> {
        let catalog = PinnedCatalog::new(self.tools.clone()).map_err(|_| LockError::Invalid)?;
        if catalog.hash() != self.tools_hash {
            return Err(LockError::Invalid);
        }
        Ok(catalog)
    }
}

impl Lock {
    /// Missing lock means no extensions have been activated. Malformed existing
    /// state is an error, never an implicit empty catalog.
    pub fn load(home: &Path) -> Result<Self, LockError> {
        unix::load(home)
    }

    /// Only the installer writes the lock. Call after the immutable store entry
    /// exists; this operation does not perform approval, promotion or hot swap.
    #[allow(dead_code)] // Promotion is deliberately not wired in this milestone.
    pub(crate) fn write_atomic(&self, home: &Path) -> Result<(), LockError> {
        unix::write(self, home)
    }

    fn validate(&self) -> Result<(), LockError> {
        if self.schema != 1 {
            return Err(LockError::Invalid);
        }
        // Reuse the manifest's normative spelling instead of a second semver dialect.
        let manifest_schema: Value =
            serde_json::from_str(include_str!("../../../spec/schemas/extension.schema.json"))
                .map_err(|_| LockError::Invalid)?;
        let id_schema = &manifest_schema["properties"]["id"];
        let version_schema = &manifest_schema["properties"]["version"];
        let id_validator = jsonschema::options()
            .offline()
            .build(id_schema)
            .map_err(|_| LockError::Invalid)?;
        let version_validator = jsonschema::options()
            .offline()
            .build(version_schema)
            .map_err(|_| LockError::Invalid)?;
        let timestamp = jsonschema::options()
            .offline()
            .should_validate_formats(true)
            .build(&serde_json::json!({"type":"string","format":"date-time"}))
            .map_err(|_| LockError::Invalid)?;
        for (id, extension) in &self.extensions {
            if !id_validator.is_valid(&Value::String(id.clone()))
                || !extension.versions.contains_key(&extension.active)
            {
                return Err(LockError::Invalid);
            }
            for (key, version) in &extension.versions {
                if !version_validator.is_valid(&Value::String(version.version.clone()))
                    || !valid_hash(&version.hash)
                    || key != &format!("{}-{}", version.version, &version.hash[7..19])
                    || version.path != format!("store/{id}/{key}")
                    || !matches!(
                        version.source.get("kind").and_then(Value::as_str),
                        Some("local")
                    )
                    || !matches!(version.approved.by.as_str(), "user" | "auto:dev-profile")
                    || !timestamp.is_valid(&Value::String(version.approved.at.clone()))
                    || version
                        .approved
                        .approval_id
                        .as_ref()
                        .is_some_and(|id| id.is_empty())
                    || version
                        .privileges
                        .iter()
                        .any(|privilege| privilege != "structured_output_trust")
                    || version
                        .audit
                        .as_ref()
                        .is_some_and(|audit| !audit.is_object())
                    || version.packages.iter().any(|package| {
                        package.ecosystem.is_empty()
                            || package.name.is_empty()
                            || package.version.is_empty()
                    })
                {
                    return Err(LockError::Invalid);
                }
                let catalog = version.catalog()?;
                version
                    .overrides
                    .validate_catalog(&catalog, &version.approved.by)
                    .map_err(|_| LockError::Invalid)?;
            }
        }
        Ok(())
    }
}

fn valid_hash(hash: &str) -> bool {
    hash.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

mod unix {
    use super::*;
    use std::{
        ffi::{CStr, CString},
        fs::File,
        io::{Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::MetadataExt,
        },
    };

    fn directory(parent: &File, name: &CStr) -> Result<File, LockError> {
        open_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0).and_then(|file| {
            check_directory(&file)?;
            Ok(file)
        })
    }

    fn open_at(
        parent: &File,
        name: &CStr,
        flags: i32,
        mode: libc::c_uint,
    ) -> Result<File, LockError> {
        // SAFETY: parent owns a live descriptor and name is NUL-terminated; openat
        // returns a fresh descriptor, transferred exactly once into File below.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                mode,
            )
        };
        if fd < 0 {
            return Err(LockError::Io(std::io::Error::last_os_error()));
        }
        // SAFETY: fd was successfully opened above and has no other Rust owner.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn check_directory(file: &File) -> Result<(), LockError> {
        let metadata = file.metadata().map_err(LockError::Io)?;
        // SAFETY: geteuid has no arguments or memory preconditions.
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o022 != 0
        {
            return Err(LockError::UnsafePath);
        }
        Ok(())
    }

    fn check_lock(file: &File) -> Result<(), LockError> {
        let metadata = file.metadata().map_err(LockError::Io)?;
        // SAFETY: geteuid has no arguments or memory preconditions.
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(LockError::UnsafePath);
        }
        Ok(())
    }

    fn home_directory(home: &Path) -> Result<File, LockError> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(home)
            .map_err(LockError::Io)?;
        check_directory(&file)?;
        Ok(file)
    }

    fn bundles(lock: &Lock, extensions: &File) -> Result<(), LockError> {
        for (id, extension) in &lock.extensions {
            for key in extension.versions.keys() {
                // validate() has already excluded separators, traversal and NUL.
                let id = CString::new(id.as_str()).map_err(|_| LockError::Invalid)?;
                let key = CString::new(key.as_str()).map_err(|_| LockError::Invalid)?;
                let store = directory(extensions, c"store")?;
                let extension = directory(&store, &id)?;
                directory(&extension, &key)?;
            }
        }
        Ok(())
    }

    pub(super) fn load(home: &Path) -> Result<Lock, LockError> {
        let home = home_directory(home)?;
        let extensions = match directory(&home, c"extensions") {
            Err(LockError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Lock::default());
            }
            result => result?,
        };
        let mut file = match open_at(&extensions, c"lock.json", libc::O_RDONLY, 0) {
            Err(LockError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Lock::default());
            }
            result => result?,
        };
        check_lock(&file)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(LockError::Io)?;
        let lock: Lock = serde_json::from_slice(&bytes).map_err(|_| LockError::Invalid)?;
        lock.validate()?;
        bundles(&lock, &extensions)?;
        Ok(lock)
    }

    struct Pending<'a> {
        directory: &'a File,
        active: bool,
    }
    impl Drop for Pending<'_> {
        fn drop(&mut self) {
            if self.active {
                // SAFETY: the parent descriptor and static name remain live.
                let _ = unsafe {
                    libc::unlinkat(self.directory.as_raw_fd(), c"lock.json.tmp".as_ptr(), 0)
                };
            }
        }
    }

    pub(super) fn write(lock: &Lock, home: &Path) -> Result<(), LockError> {
        lock.validate()?;
        let home = home_directory(home)?;
        // SAFETY: home is live and the child name is static NUL-terminated.
        if unsafe { libc::mkdirat(home.as_raw_fd(), c"extensions".as_ptr(), 0o700) } < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(LockError::Io(error));
            }
        } else {
            home.sync_all().map_err(LockError::Io)?;
        }
        let extensions = directory(&home, c"extensions")?;
        // Serialize even separate processes without introducing another file format.
        // SAFETY: flock takes a live descriptor and no pointers.
        if unsafe { libc::flock(extensions.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
            let error = std::io::Error::last_os_error();
            return Err(if error.kind() == std::io::ErrorKind::WouldBlock {
                LockError::Busy
            } else {
                LockError::Io(error)
            });
        }
        bundles(lock, &extensions)?;
        match open_at(&extensions, c"lock.json", libc::O_RDONLY, 0) {
            Ok(file) => check_lock(&file)?,
            Err(LockError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let bytes = serde_json::to_vec_pretty(lock).map_err(|_| LockError::Invalid)?;
        let mut temporary = match open_at(
            &extensions,
            c"lock.json.tmp",
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        ) {
            Err(LockError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(LockError::Busy);
            }
            result => result?,
        };
        let mut pending = Pending {
            directory: &extensions,
            active: true,
        };
        check_lock(&temporary)?;
        temporary.write_all(&bytes).map_err(LockError::Io)?;
        temporary.sync_all().map_err(LockError::Io)?;
        // SAFETY: both directory descriptors and both static names remain live.
        if unsafe {
            libc::renameat(
                extensions.as_raw_fd(),
                c"lock.json.tmp".as_ptr(),
                extensions.as_raw_fd(),
                c"lock.json".as_ptr(),
            )
        } < 0
        {
            return Err(LockError::Io(std::io::Error::last_os_error()));
        }
        pending.active = false;
        extensions.sync_all().map_err(LockError::Io)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    fn fixture(home: &Path) -> Lock {
        let tools = vec![
            serde_json::json!({"name":"echo","description":"Pinned description","inputSchema":{"type":"object"}}),
        ];
        let tools_hash = PinnedCatalog::new(tools.clone()).unwrap().hash().to_owned();
        let key = "1.2.3-0123456789ab";
        fs::create_dir_all(home.join("extensions/store/example").join(key)).unwrap();
        Lock {
            schema: 1,
            extensions: BTreeMap::from([(
                "example".into(),
                LockedExtension {
                    enabled: true,
                    active: key.into(),
                    versions: BTreeMap::from([(
                        key.into(),
                        LockedVersion {
                            version: "1.2.3".into(),
                            hash: format!("sha256:{}", "0123456789ab".repeat(5) + "0123"),
                            path: format!("store/example/{key}"),
                            source: serde_json::json!({"kind":"local","path":"/local/source"}),
                            approved: Approval {
                                by: "user".into(),
                                at: "2026-10-17T18:00:00Z".into(),
                                approval_id: None,
                            },
                            overrides: Overrides::default(),
                            privileges: vec![],
                            tools,
                            tools_hash,
                            packages: vec![],
                            audit: None,
                        },
                    )]),
                },
            )]),
        }
    }

    fn save_json(home: &Path, value: &Value) {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(home.join("extensions/lock.json"))
            .unwrap();
        file.write_all(&serde_json::to_vec(value).unwrap()).unwrap();
    }

    #[test]
    fn schema_one_roundtrip_preserves_catalog_and_private_atomic_file() {
        let home = tempfile::tempdir().unwrap();
        assert!(Lock::load(home.path()).unwrap().extensions.is_empty());
        let lock = fixture(home.path());
        lock.write_atomic(home.path()).unwrap();
        let loaded = Lock::load(home.path()).unwrap();
        assert_eq!(
            serde_json::to_value(&loaded).unwrap(),
            serde_json::to_value(&lock).unwrap()
        );
        let version = loaded.extensions["example"]
            .versions
            .values()
            .next()
            .unwrap();
        assert_eq!(version.catalog().unwrap().hash(), version.tools_hash);
        assert_eq!(
            fs::metadata(home.path().join("extensions/lock.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
        assert!(!home.path().join("extensions/lock.json.tmp").exists());
        let mut replacement = loaded;
        replacement.extensions.get_mut("example").unwrap().enabled = false;
        replacement.write_atomic(home.path()).unwrap();
        assert!(!Lock::load(home.path()).unwrap().extensions["example"].enabled);
    }

    #[test]
    fn malformed_json_types_schema_hashes_paths_and_catalogs_fail_closed() {
        let home = tempfile::tempdir().unwrap();
        let lock = fixture(home.path());
        let original = serde_json::to_value(lock).unwrap();
        let key = "1.2.3-0123456789ab";
        let mutations: Vec<(String, Value)> = vec![
            ("/schema".into(), 2.into()),
            ("/schema".into(), "1".into()),
            ("/extensions/example/enabled".into(), "yes".into()),
            ("/extensions/example/active".into(), "missing".into()),
            (
                format!("/extensions/example/versions/{key}/hash"),
                "sha256:bad".into(),
            ),
            (
                format!("/extensions/example/versions/{key}/hash"),
                format!("sha256:{}", "f".repeat(64)).into(),
            ),
            (
                format!("/extensions/example/versions/{key}/version"),
                "9.9.9".into(),
            ),
            (
                format!("/extensions/example/versions/{key}/path"),
                "../outside".into(),
            ),
            (
                format!("/extensions/example/versions/{key}/source"),
                serde_json::json!({"kind":"git"}),
            ),
            (
                format!("/extensions/example/versions/{key}/approved/at"),
                "not-a-date".into(),
            ),
            (
                format!("/extensions/example/versions/{key}/approved/at"),
                "2026-02-30T18:00:00Z".into(),
            ),
            (
                format!("/extensions/example/versions/{key}/tools_hash"),
                format!("sha256:{}", "0".repeat(64)).into(),
            ),
            (
                format!("/extensions/example/versions/{key}/tools"),
                serde_json::json!([{"name":"echo","inputSchema":false}]),
            ),
            (
                format!("/extensions/example/versions/{key}/overrides/permissions"),
                Value::Null,
            ),
        ];
        for (pointer, value) in mutations {
            let mut candidate = original.clone();
            *candidate.pointer_mut(&pointer).unwrap() = value;
            save_json(home.path(), &candidate);
            assert!(
                matches!(Lock::load(home.path()), Err(LockError::Invalid)),
                "{pointer}"
            );
        }
        for path in [
            "/store/example/key",
            "store/example/../key",
            "store/example\\key",
            "store/example/1.2.3-0123456789ab/",
        ] {
            let mut candidate = original.clone();
            candidate["extensions"]["example"]["versions"][key]["path"] = path.into();
            save_json(home.path(), &candidate);
            assert!(Lock::load(home.path()).is_err(), "{path}");
        }
        let mut candidate = original;
        let extension = candidate["extensions"]
            .as_object_mut()
            .unwrap()
            .remove("example")
            .unwrap();
        candidate["extensions"]["../example"] = extension;
        save_json(home.path(), &candidate);
        assert!(Lock::load(home.path()).is_err());
    }

    #[test]
    fn tool_catalog_is_revalidated_even_after_loading() {
        let home = tempfile::tempdir().unwrap();
        let lock = fixture(home.path());
        lock.write_atomic(home.path()).unwrap();
        let mut loaded = Lock::load(home.path()).unwrap();
        let version = loaded
            .extensions
            .get_mut("example")
            .unwrap()
            .versions
            .values_mut()
            .next()
            .unwrap();
        version.tools[0]["description"] = "Changed after approval".into();
        assert!(version.catalog().is_err());
        assert!(loaded.write_atomic(home.path()).is_err());
        assert_eq!(
            Lock::load(home.path()).unwrap().extensions["example"]
                .versions
                .values()
                .next()
                .unwrap()
                .tools[0]["description"],
            "Pinned description"
        );
    }

    #[test]
    fn overrides_preserve_sparse_approved_json_and_accept_legacy_absence() {
        let home = tempfile::tempdir().unwrap();
        let mut lock = fixture(home.path());
        let extension = lock.extensions.get_mut("example").unwrap();
        let version = extension.versions.get_mut(&extension.active).unwrap();
        let patch = serde_json::json!({"tools":{"echo":{"model_visible":false}}});
        version.overrides = Overrides::from_value(patch.clone()).unwrap();
        lock.write_atomic(home.path()).unwrap();
        let loaded = Lock::load(home.path()).unwrap();
        let extension = &loaded.extensions["example"];
        assert_eq!(
            extension.versions[&extension.active].overrides.as_value(),
            &patch
        );
        let mut legacy = serde_json::to_value(loaded).unwrap();
        legacy["extensions"]["example"]["versions"]["1.2.3-0123456789ab"]
            .as_object_mut()
            .unwrap()
            .remove("overrides");
        save_json(home.path(), &legacy);
        let loaded = Lock::load(home.path()).unwrap();
        let extension = &loaded.extensions["example"];
        assert_eq!(
            extension.versions[&extension.active].overrides,
            Overrides::default()
        );
    }

    #[test]
    fn symlinks_in_lock_store_and_parent_and_insecure_file_are_rejected() {
        let home = tempfile::tempdir().unwrap();
        let lock = fixture(home.path());
        lock.write_atomic(home.path()).unwrap();
        let path = home.path().join("extensions/lock.json");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            Lock::load(home.path()),
            Err(LockError::UnsafePath)
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let real = home.path().join("real-lock");
        fs::rename(&path, &real).unwrap();
        symlink(&real, &path).unwrap();
        assert!(Lock::load(home.path()).is_err());
        assert!(lock.write_atomic(home.path()).is_err());
        fs::remove_file(&path).unwrap();
        fs::rename(&real, &path).unwrap();
        let store = home.path().join("extensions/store");
        let real_store = home.path().join("real-store");
        fs::rename(&store, &real_store).unwrap();
        symlink(&real_store, &store).unwrap();
        assert!(Lock::load(home.path()).is_err());
        fs::remove_file(&store).unwrap();
        fs::rename(real_store, store).unwrap();
        let extensions = home.path().join("extensions");
        let real_extensions = home.path().join("real-extensions");
        fs::rename(&extensions, &real_extensions).unwrap();
        symlink(&real_extensions, &extensions).unwrap();
        assert!(Lock::load(home.path()).is_err());
    }

    #[test]
    fn active_writer_and_existing_temporary_file_are_refused_without_mutation() {
        use std::os::fd::AsRawFd;
        let home = tempfile::tempdir().unwrap();
        let lock = fixture(home.path());
        lock.write_atomic(home.path()).unwrap();
        let path = home.path().join("extensions/lock.json");
        let original = fs::read(&path).unwrap();
        let directory = fs::File::open(home.path().join("extensions")).unwrap();
        // SAFETY: directory owns a live descriptor and flock has no pointers.
        assert_eq!(
            unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        assert!(matches!(
            lock.write_atomic(home.path()),
            Err(LockError::Busy)
        ));
        drop(directory);
        let temporary = home.path().join("extensions/lock.json.tmp");
        fs::write(&temporary, b"incomplete prior write").unwrap();
        assert!(matches!(
            lock.write_atomic(home.path()),
            Err(LockError::Busy)
        ));
        assert_eq!(fs::read(&temporary).unwrap(), b"incomplete prior write");
        assert_eq!(fs::read(path).unwrap(), original);
    }

    #[test]
    fn each_bundle_directory_and_home_reject_symlinks() {
        for relative in [
            "extensions/store/example",
            "extensions/store/example/1.2.3-0123456789ab",
        ] {
            let home = tempfile::tempdir().unwrap();
            let lock = fixture(home.path());
            lock.write_atomic(home.path()).unwrap();
            let path = home.path().join(relative);
            let real = home.path().join("real-directory");
            fs::rename(&path, &real).unwrap();
            symlink(&real, &path).unwrap();
            assert!(Lock::load(home.path()).is_err(), "{relative}");
            assert!(lock.write_atomic(home.path()).is_err(), "{relative}");
        }
        let parent = tempfile::tempdir().unwrap();
        let home = parent.path().join("home");
        let alias = parent.path().join("alias");
        fs::create_dir(&home).unwrap();
        symlink(&home, &alias).unwrap();
        assert!(Lock::load(&alias).is_err());
    }
}
