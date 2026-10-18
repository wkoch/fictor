//! Local bundle copying and the bytewise hash from spec/06, stages 1 and 4.
//! `.git` components are omitted as VCS metadata. No code is executed here.
//! ADR-024 fixes all resource ceilings. A shared budget starts before dependency
//! resolution so that post-dependency traversal uses the same 600-second clock.

use super::BundleError;
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

pub const MAX_BUNDLE_BYTES: u64 = 200 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleProfile {
    ReceiptAi,
    ReceiptLocal,
    PostDependencies,
}
#[derive(Clone, Copy)]
struct Limits {
    entries: usize,
    bytes: u64,
    file_size: u64,
    depth: usize,
    path_length: usize,
    time: Duration,
}
impl BundleProfile {
    const fn limits(self) -> Limits {
        let (entries, bytes, file_size, depth, path_length, seconds) = match self {
            Self::ReceiptAi => (500, 5 * 1024 * 1024, 5 * 1024 * 1024, 16, 512, 30),
            Self::ReceiptLocal => (5_000, 50 * 1024 * 1024, 50 * 1024 * 1024, 32, 1024, 60),
            Self::PostDependencies => (50_000, MAX_BUNDLE_BYTES, 100 * 1024 * 1024, 64, 1024, 600),
        };
        Limits {
            entries,
            bytes,
            file_size,
            depth,
            path_length,
            time: Duration::from_secs(seconds),
        }
    }
}
/// One monotonic budget for a whole stage, including dependency resolution.
/// Reusing it for copying and verification does not reset its deadline.
pub struct BundleBudget {
    profile: BundleProfile,
    limits: Limits,
    elapsed: Arc<dyn Fn() -> Duration + Send + Sync>,
}
impl BundleBudget {
    pub fn start(profile: BundleProfile) -> Self {
        let started = Instant::now();
        Self {
            profile,
            limits: profile.limits(),
            elapsed: Arc::new(move || started.elapsed()),
        }
    }
    pub fn profile(&self) -> BundleProfile {
        self.profile
    }
    pub fn check_time(&self) -> Result<(), BundleError> {
        if (self.elapsed)() > self.limits.time {
            Err(BundleError::Limit("time"))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct BundleFile {
    pub path: PathBuf,
    pub mode: u32,
    pub bytes: u64,
    /// Lowercase SHA-256 hex of this file's bytes, without the `sha256:` prefix.
    pub content_hash: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Inspection {
    pub bundle_hash: String,
    pub files: Vec<BundleFile>,
    pub total_bytes: u64,
    /// Scanned non-ignored entries, including empty directories, excluding the root.
    pub total_entries: usize,
    pub ignored: Vec<PathBuf>,
}

pub use unix::{copy_local, inspect};

mod unix {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::{
        collections::HashSet,
        ffi::{CStr, CString, OsStr, OsString},
        fs::{self, File, Metadata, OpenOptions},
        io::{Read, Write},
        mem::MaybeUninit,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{
                ffi::{OsStrExt, OsStringExt},
                fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            },
        },
        path::{Component, Path},
    };
    use unicode_normalization::UnicodeNormalization;

    #[derive(PartialEq, Eq)]
    struct Stamp {
        device: u64,
        inode: u64,
        mode: u32,
        bytes: u64,
        modified: (i64, i64),
        changed: (i64, i64),
    }
    impl Stamp {
        fn of(metadata: &Metadata) -> Self {
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                mode: metadata.mode(),
                bytes: metadata.len(),
                modified: (metadata.mtime(), metadata.mtime_nsec()),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
            }
        }
    }
    struct Frame {
        source: File,
        destination: Option<File>,
        relative: PathBuf,
        stamp: Stamp,
        names: std::vec::IntoIter<OsString>,
        retained: bool,
    }
    struct Cleanup(Option<PathBuf>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if let Some(path) = &self.0 {
                let _ = fs::remove_dir_all(path);
            }
        }
    }

    /// Inspect current source bytes. An earlier inspection never authorizes a
    /// later copy: `copy_local` traverses afresh and hashes the bytes it writes.
    pub fn inspect(source: &Path, budget: &BundleBudget) -> Result<Inspection, BundleError> {
        budget.check_time()?;
        let (source, _) = open_root(source)?;
        walk(source, None, budget)
    }

    /// Copy to a newly-created quarantine directory below a trusted private
    /// parent. Existing destinations are never replaced. Partial copies are
    /// removed on failure. The source is never executed or modified.
    pub fn copy_local(
        source: &Path,
        destination: &Path,
        budget: &BundleBudget,
    ) -> Result<Inspection, BundleError> {
        budget.check_time()?;
        let (source, source_path) = open_root(source)?;
        if !destination.is_absolute()
            || destination
                .components()
                .any(|part| matches!(part, Component::ParentDir))
        {
            return Err(BundleError::Invalid(
                "destino de quarentena deve ser absoluto, sem ..",
            ));
        }
        let parent_path = destination
            .parent()
            .ok_or(BundleError::Invalid("destino sem pai"))?;
        let (parent, parent_path) = open_root(parent_path)?;
        if parent.metadata()?.permissions().mode() & 0o077 != 0 {
            return Err(BundleError::Invalid("pai da quarentena deve ser privado"));
        }
        if parent_path.starts_with(&source_path) {
            return Err(BundleError::Invalid(
                "quarentena não pode ficar dentro da fonte",
            ));
        }
        let name = destination
            .file_name()
            .ok_or(BundleError::Invalid("destino sem nome"))?;
        validate_name(name)?;
        let destination_path = parent_path.join(name);
        let destination = create_directory(&parent, name)?;
        // The private core-owned parent is not accessible to extensions. Keep the
        // guard until both copying and independent source revalidation succeed.
        let mut cleanup = Cleanup(Some(destination_path));
        let root_stamp = Stamp::of(&source.metadata()?);
        let copied = walk(source.try_clone()?, Some(destination), budget)?;
        let checked = walk(source.try_clone()?, None, budget)?;
        if copied != checked || root_stamp != Stamp::of(&source.metadata()?) {
            return Err(BundleError::SourceChanged);
        }
        parent.sync_all()?;
        budget.check_time()?;
        cleanup.0 = None;
        Ok(copied)
    }

    fn open_root(path: &Path) -> Result<(File, PathBuf), BundleError> {
        if path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
        {
            return Err(BundleError::Invalid("fonte contém .."));
        }
        let initial = fs::symlink_metadata(path)?;
        if !initial.is_dir() || initial.file_type().is_symlink() {
            return Err(BundleError::Invalid(
                "raiz do bundle deve ser diretório, sem symlink",
            ));
        }
        let canonical = path.canonicalize()?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&canonical)?;
        if Stamp::of(&initial) != Stamp::of(&file.metadata()?) {
            return Err(BundleError::SourceChanged);
        }
        Ok((file, canonical))
    }

    fn walk(
        source: File,
        destination: Option<File>,
        budget: &BundleBudget,
    ) -> Result<Inspection, BundleError> {
        let mut result = Inspection {
            bundle_hash: String::new(),
            files: vec![],
            total_bytes: 0,
            total_entries: 0,
            ignored: vec![],
        };
        budget.check_time()?;
        let mut seen = HashSet::new();
        let mut stack = vec![frame(
            source,
            destination,
            PathBuf::new(),
            &mut result,
            budget,
            &mut seen,
        )?];
        while let Some(current) = stack.last_mut() {
            budget.check_time()?;
            let Some(name) = current.names.next() else {
                if current.stamp != Stamp::of(&current.source.metadata()?) {
                    return Err(BundleError::SourceChanged);
                }
                if let Some(destination) = &current.destination {
                    destination.sync_all()?;
                }
                let finished = stack.pop().ok_or(BundleError::SourceChanged)?;
                if let Some(parent) = stack.last_mut() {
                    if finished.retained {
                        parent.retained = true;
                    } else if let Some(destination) = &parent.destination {
                        remove_directory(
                            destination,
                            finished
                                .relative
                                .file_name()
                                .ok_or(BundleError::SourceChanged)?,
                        )?;
                    }
                }
                continue;
            };
            let relative = current.relative.join(&name);
            let child = open_entry(&current.source, &name)?;
            let metadata = child.metadata()?;
            if metadata.is_dir() {
                let destination = current
                    .destination
                    .as_ref()
                    .map(|directory| create_directory(directory, &name))
                    .transpose()?;
                stack.push(frame(
                    child,
                    destination,
                    relative,
                    &mut result,
                    budget,
                    &mut seen,
                )?);
            } else if metadata.is_file() {
                current.retained = true;
                let executable = metadata.mode() & 0o111 != 0;
                let destination = current
                    .destination
                    .as_ref()
                    .map(|directory| create_file(directory, &name, executable))
                    .transpose()?;
                let file = read_file(
                    child,
                    destination,
                    relative,
                    executable,
                    Stamp::of(&metadata),
                    &mut result,
                    budget,
                )?;
                result.files.push(file);
            } else {
                return Err(BundleError::Invalid("entrada especial no bundle"));
            }
        }
        budget.check_time()?;
        result.ignored.sort();
        result.files.sort_by(|left, right| {
            left.path
                .as_os_str()
                .as_bytes()
                .cmp(right.path.as_os_str().as_bytes())
        });
        let mut hash = Sha256::new();
        for file in &result.files {
            budget.check_time()?;
            hash.update(file.path.as_os_str().as_bytes());
            hash.update(b"\0");
            hash.update(if file.mode == 0o755 { b"755" } else { b"644" });
            hash.update(b"\0");
            hash.update(file.content_hash.as_bytes());
            hash.update(b"\n");
        }
        result.bundle_hash = format!("sha256:{}", hex(&hash.finalize()));
        budget.check_time()?;
        Ok(result)
    }

    fn frame(
        source: File,
        destination: Option<File>,
        relative: PathBuf,
        result: &mut Inspection,
        budget: &BundleBudget,
        seen: &mut HashSet<String>,
    ) -> Result<Frame, BundleError> {
        let stamp = Stamp::of(&source.metadata()?);
        let names = names(&source, &relative, result, budget, seen)?;
        Ok(Frame {
            source,
            destination,
            relative,
            stamp,
            names: names.into_iter(),
            retained: false,
        })
    }

    fn read_file(
        mut source: File,
        mut destination: Option<File>,
        path: PathBuf,
        executable: bool,
        initial: Stamp,
        result: &mut Inspection,
        budget: &BundleBudget,
    ) -> Result<BundleFile, BundleError> {
        let before = source.metadata()?;
        if initial != Stamp::of(&before) {
            return Err(BundleError::SourceChanged);
        }
        budget.check_time()?;
        if before.len() > budget.limits.file_size {
            return Err(BundleError::Limit("file_size"));
        }
        if before.len() > budget.limits.bytes.saturating_sub(result.total_bytes) {
            return Err(BundleError::Limit("bytes"));
        }
        let mut hash = Sha256::new();
        let mut bytes = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            budget.check_time()?;
            let count = match source.read(&mut buffer) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                count => count?,
            };
            if count == 0 {
                break;
            }
            if count as u64 > budget.limits.file_size.saturating_sub(bytes) {
                return Err(BundleError::Limit("file_size"));
            }
            if count as u64 > budget.limits.bytes.saturating_sub(result.total_bytes) {
                return Err(BundleError::Limit("bytes"));
            }
            if let Some(destination) = &mut destination {
                destination.write_all(&buffer[..count])?;
            }
            hash.update(&buffer[..count]);
            bytes += count as u64;
            result.total_bytes += count as u64;
        }
        if Stamp::of(&before) != Stamp::of(&source.metadata()?) || bytes != before.len() {
            return Err(BundleError::SourceChanged);
        }
        if let Some(destination) = destination {
            destination.sync_all()?;
        }
        Ok(BundleFile {
            path,
            mode: if executable { 0o755 } else { 0o644 },
            bytes,
            content_hash: hex(&hash.finalize()),
        })
    }

    fn validate_name(name: &OsStr) -> Result<(), BundleError> {
        let text = name
            .to_str()
            .ok_or(BundleError::Invalid("nome não UTF-8"))?;
        if text.chars().any(|c| c.is_control() || c == '\\') {
            return Err(BundleError::Invalid(
                "nome contém controle ou barra invertida",
            ));
        }
        let bytes = name.as_bytes();
        if bytes.is_empty()
            || bytes == b"."
            || bytes == b".."
            || bytes.contains(&b'/')
            || bytes.contains(&0)
        {
            return Err(BundleError::Invalid("caminho relativo inválido"));
        }
        Ok(())
    }
    fn c_name(name: &OsStr) -> Result<CString, BundleError> {
        validate_name(name)?;
        CString::new(name.as_bytes()).map_err(|_| BundleError::Invalid("nome contém NUL"))
    }
    fn open_entry(parent: &File, name: &OsStr) -> Result<File, BundleError> {
        let name = c_name(name)?;
        let metadata = entry_metadata(parent, OsStr::from_bytes(name.as_bytes()))?;
        let kind = metadata.st_mode & libc::S_IFMT;
        if kind != libc::S_IFDIR && kind != libc::S_IFREG {
            return Err(BundleError::Invalid(
                "symlink ou entrada especial no bundle",
            ));
        }
        let mut flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
        if kind == libc::S_IFDIR {
            flags |= libc::O_DIRECTORY;
        }
        // SAFETY: parent/name are valid. No symlink is followed, and FIFO replacement cannot block.
        let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: openat returned a fresh owned descriptor.
        let file = unsafe { File::from_raw_fd(descriptor) };
        let opened = file.metadata()?;
        if opened.dev() != metadata.st_dev
            || opened.ino() != metadata.st_ino
            || opened.mode() != metadata.st_mode
        {
            return Err(BundleError::SourceChanged);
        }
        Ok(file)
    }
    fn entry_metadata(parent: &File, name: &OsStr) -> Result<libc::stat, BundleError> {
        let name = c_name(name)?;
        let mut metadata = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: parent is live; the C string and output storage remain valid.
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: fstatat succeeded and initialized the stat structure.
        Ok(unsafe { metadata.assume_init() })
    }
    fn ignored_directory(name: &OsStr, root: bool, profile: BundleProfile) -> bool {
        name == ".git"
            || (profile != BundleProfile::PostDependencies
                && (name == "__pycache__"
                    || (root
                        && matches!(
                            name.to_str(),
                            Some("node_modules" | "vendor" | ".deno" | ".pydeps" | ".venv")
                        ))))
    }
    fn remove_directory(parent: &File, name: &OsStr) -> Result<(), BundleError> {
        let name = c_name(name)?;
        // SAFETY: only the freshly-created, empty destination directory is removed.
        if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
    fn create_directory(parent: &File, name: &OsStr) -> Result<File, BundleError> {
        let name = c_name(name)?;
        // SAFETY: mkdirat creates only this validated child name under a live directory.
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let result = (|| {
            let directory = open_entry(parent, OsStr::from_bytes(name.as_bytes()))?;
            directory.set_permissions(fs::Permissions::from_mode(0o700))?;
            Ok(directory)
        })();
        if result.is_err() {
            // SAFETY: mkdirat above created this name exclusively. If opening or
            // chmod failed (e.g. restrictive umask), it is still empty.
            unsafe {
                libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR);
            }
        }
        result
    }
    fn create_file(parent: &File, name: &OsStr, executable: bool) -> Result<File, BundleError> {
        let name = c_name(name)?;
        // SAFETY: parent/name are valid. O_EXCL and O_NOFOLLOW prevent replacement.
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                if executable { 0o755 } else { 0o644 },
            )
        };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: openat returned a fresh owned descriptor.
        let file = unsafe { File::from_raw_fd(descriptor) };
        file.set_permissions(fs::Permissions::from_mode(if executable {
            0o755
        } else {
            0o644
        }))?;
        Ok(file)
    }
    struct Directory(*mut libc::DIR);
    impl Drop for Directory {
        fn drop(&mut self) {
            // SAFETY: this guard uniquely owns the fdopendir stream.
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    fn names(
        directory: &File,
        relative: &Path,
        result: &mut Inspection,
        budget: &BundleBudget,
        seen: &mut HashSet<String>,
    ) -> Result<Vec<OsString>, BundleError> {
        // SAFETY: duplicate the live descriptor; fdopendir owns only the duplicate.
        let descriptor = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: descriptor is a fresh valid directory descriptor.
        let pointer = unsafe { libc::fdopendir(descriptor) };
        if pointer.is_null() {
            let error = std::io::Error::last_os_error();
            // SAFETY: fdopendir failed, so ownership remains with us.
            unsafe {
                libc::close(descriptor);
            }
            return Err(error.into());
        }
        let stream = Directory(pointer);
        // SAFETY: directory is live; reset the shared offset for independent revalidation.
        unsafe {
            libc::rewinddir(stream.0);
        }
        let mut names = Vec::new();
        loop {
            budget.check_time()?;
            set_errno(0);
            // SAFETY: the directory stream remains live throughout this loop.
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(0) {
                    return Err(error.into());
                }
                break;
            }
            // SAFETY: readdir returned a valid entry with a NUL-terminated name,
            // borrowed only until the next readdir call.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if matches!(name, b"." | b"..") {
                continue;
            }
            let name = OsString::from_vec(name.to_vec());
            validate_name(&name)?;
            let path = relative.join(&name);
            let metadata = entry_metadata(directory, &name)?;
            let kind = metadata.st_mode & libc::S_IFMT;
            if kind != libc::S_IFDIR && kind != libc::S_IFREG {
                return Err(BundleError::Invalid(
                    "symlink ou entrada especial no bundle",
                ));
            }
            if kind == libc::S_IFDIR
                && ignored_directory(&name, relative.as_os_str().is_empty(), budget.profile)
            {
                result.ignored.push(path);
                continue;
            }
            accept_path(&path, result, budget, seen)?;
            names.push(name);
        }
        Ok(names)
    }
    fn accept_path(
        path: &Path,
        result: &mut Inspection,
        budget: &BundleBudget,
        seen: &mut HashSet<String>,
    ) -> Result<(), BundleError> {
        result.total_entries += 1;
        if result.total_entries > budget.limits.entries {
            return Err(BundleError::Limit("entries"));
        }
        if path.components().count() > budget.limits.depth {
            return Err(BundleError::Limit("depth"));
        }
        let text = path
            .to_str()
            .ok_or(BundleError::Invalid("caminho não UTF-8"))?;
        if text.len() > budget.limits.path_length {
            return Err(BundleError::Limit("path_length"));
        }
        let key: String = text.nfc().flat_map(char::to_lowercase).collect();
        if !seen.insert(key) {
            return Err(BundleError::Invalid("colisão de caminho NFC/minúsculas"));
        }
        Ok(())
    }
    fn set_errno(value: i32) {
        // SAFETY: __errno_location returns this thread's writable errno storage.
        unsafe {
            *libc::__errno_location() = value;
        }
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::atomic::{AtomicU64, Ordering};

        fn budget() -> BundleBudget {
            BundleBudget::start(BundleProfile::ReceiptLocal)
        }
        fn sized(limits: Limits) -> BundleBudget {
            BundleBudget {
                profile: BundleProfile::ReceiptLocal,
                limits,
                elapsed: Arc::new(|| Duration::ZERO),
            }
        }
        fn directory(path: &Path) {
            fs::create_dir_all(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fn write(path: &Path, bytes: &[u8], mode: u32) {
            fs::write(path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
        fn blank() -> Inspection {
            Inspection {
                bundle_hash: String::new(),
                files: vec![],
                total_bytes: 0,
                total_entries: 0,
                ignored: vec![],
            }
        }
        fn fixture(source: &Path) {
            directory(&source.join("part"));
            directory(&source.join("vendor"));
            write(&source.join("a.sh"), b"echo ok\n", 0o701);
            write(&source.join("a.txt"), b"a", 0o600);
            write(&source.join("part.txt"), b"p", 0o644);
            write(&source.join("part/x"), b"x", 0o600);
            write(&source.join("vendor/pkg"), b"dependency", 0o644);
            write(&source.join("z.txt"), b"z", 0o666);
        }
        fn limit(error: Result<Inspection, BundleError>, reason: &str) {
            assert!(matches!(error, Err(BundleError::Limit(value)) if value == reason));
        }

        #[test]
        fn profiles_have_exact_adr024_constants() {
            for (profile, entries, mib, file_mib, depth, path_length, seconds) in [
                (BundleProfile::ReceiptAi, 500, 5, 5, 16, 512, 30),
                (BundleProfile::ReceiptLocal, 5_000, 50, 50, 32, 1024, 60),
                (
                    BundleProfile::PostDependencies,
                    50_000,
                    200,
                    100,
                    64,
                    1024,
                    600,
                ),
            ] {
                let limits = profile.limits();
                assert_eq!(
                    (
                        limits.entries,
                        limits.bytes,
                        limits.file_size,
                        limits.depth,
                        limits.path_length,
                        limits.time.as_secs()
                    ),
                    (
                        entries,
                        mib * 1024 * 1024,
                        file_mib * 1024 * 1024,
                        depth,
                        path_length,
                        seconds
                    )
                );
                assert_eq!(BundleBudget::start(profile).profile(), profile);
            }
        }

        #[test]
        fn fixed_hash_vector_is_global_bytewise_and_includes_post_dependency_files() {
            let temp = tempfile::tempdir().unwrap();
            fixture(temp.path());
            let post = BundleBudget::start(BundleProfile::PostDependencies);
            let first = inspect(temp.path(), &post).unwrap();
            assert_eq!(
                first.bundle_hash,
                "sha256:185f72ddef39b3d7bad65b590e570537e54755f9c327bbff16ff89a5c9b9c251"
            );
            assert_eq!(first.total_bytes, 22);
            assert_eq!(first.total_entries, 8);
            assert_eq!(
                first
                    .files
                    .iter()
                    .map(|f| f.path.to_str().unwrap())
                    .collect::<Vec<_>>(),
                ["a.sh", "a.txt", "part.txt", "part/x", "vendor/pkg", "z.txt"]
            );
            directory(&temp.path().join(".git"));
            write(&temp.path().join(".git/config"), b"metadata", 0o600);
            assert_eq!(
                inspect(temp.path(), &post).unwrap().bundle_hash,
                first.bundle_hash
            );
            fs::set_permissions(temp.path().join("a.txt"), fs::Permissions::from_mode(0o755))
                .unwrap();
            assert_ne!(
                inspect(temp.path(), &post).unwrap().bundle_hash,
                first.bundle_hash
            );
        }

        #[test]
        fn receipt_ignores_exact_directories_without_traversing_and_reports_them() {
            let temp = tempfile::tempdir().unwrap();
            for name in [
                ".git",
                "__pycache__",
                "node_modules",
                "vendor",
                ".deno",
                ".pydeps",
                ".venv",
            ] {
                directory(&temp.path().join(name));
                std::os::unix::fs::symlink("/never-read", temp.path().join(name).join("bad"))
                    .unwrap();
            }
            directory(&temp.path().join("nested/__pycache__"));
            std::os::unix::fs::symlink("/never-read", temp.path().join("nested/__pycache__/bad"))
                .unwrap();
            directory(&temp.path().join("nested/vendor"));
            write(&temp.path().join("nested/vendor/file"), b"yes", 0o600);
            let scanned = inspect(temp.path(), &budget()).unwrap();
            assert_eq!(scanned.ignored.len(), 8);
            assert_eq!(scanned.total_entries, 3);
            assert_eq!(scanned.total_bytes, 3);
            assert_eq!(scanned.files[0].path, Path::new("nested/vendor/file"));
            for name in [
                ".git",
                "__pycache__",
                "node_modules",
                "vendor",
                ".deno",
                ".pydeps",
                ".venv",
            ] {
                let isolated = tempfile::tempdir().unwrap();
                std::os::unix::fs::symlink("/never-read", isolated.path().join(name)).unwrap();
                assert!(matches!(
                    inspect(isolated.path(), &budget()),
                    Err(BundleError::Invalid(_))
                ));
            }
        }

        #[test]
        fn post_dependencies_keeps_vendor_and_pycache_but_omits_git() {
            let temp = tempfile::tempdir().unwrap();
            for name in ["vendor", "node_modules", ".pydeps", "__pycache__", ".git"] {
                directory(&temp.path().join(name));
                write(&temp.path().join(name).join("file"), b"x", 0o600);
            }
            let result = inspect(
                temp.path(),
                &BundleBudget::start(BundleProfile::PostDependencies),
            )
            .unwrap();
            assert_eq!(result.files.len(), 4);
            assert_eq!(result.total_bytes, 4);
            assert_eq!(result.ignored, [PathBuf::from(".git")]);
        }

        #[test]
        fn copy_discards_empty_directories_and_has_same_file_hash_as_destination() {
            let temp = tempfile::tempdir().unwrap();
            let source = temp.path().join("source");
            let parent = temp.path().join("quarantine");
            directory(&source);
            directory(&parent);
            fixture(&source);
            directory(&source.join("empty/child"));
            directory(&source.join("part/empty"));
            directory(&source.join(".git"));
            std::os::unix::fs::symlink("/never-read", source.join(".git/link")).unwrap();
            write(&source.join("a.sh"), b"echo ok\n", 0o6755);
            let destination = parent.join("receipt");
            let copied = copy_local(&source, &destination, &budget()).unwrap();
            let stored = inspect(&destination, &budget()).unwrap();
            assert_eq!(copied.files, stored.files);
            assert_eq!(copied.bundle_hash, stored.bundle_hash);
            assert_eq!(copied.total_bytes, stored.total_bytes);
            assert!(!destination.join("empty").exists());
            assert!(!destination.join("part/empty").exists());
            assert!(!destination.join("vendor").exists());
            assert!(!destination.join(".git").exists());
            assert_eq!(
                fs::metadata(&destination).unwrap().permissions().mode() & 0o7777,
                0o700
            );
            assert_eq!(
                fs::metadata(destination.join("a.sh"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o755
            );
            assert_eq!(
                fs::metadata(destination.join("a.txt"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o644
            );
        }

        #[test]
        fn entries_count_empty_directories_and_ai_allows_exactly_500_relative_entries() {
            let temp = tempfile::tempdir().unwrap();
            for n in 0..500 {
                directory(&temp.path().join(format!("d{n}")));
            }
            let ai = BundleBudget::start(BundleProfile::ReceiptAi);
            assert_eq!(inspect(temp.path(), &ai).unwrap().total_entries, 500);
            directory(&temp.path().join("overflow"));
            limit(inspect(temp.path(), &ai), "entries");
        }

        #[test]
        fn byte_and_file_limits_enforce_exact_boundary_and_cleanup_partial_destination() {
            let temp = tempfile::tempdir().unwrap();
            let source = temp.path().join("source");
            let parent = temp.path().join("quarantine");
            directory(&source);
            directory(&parent);
            write(&source.join("a"), b"aaa", 0o600);
            write(&source.join("b"), b"bb", 0o600);
            let mut limits = BundleProfile::ReceiptLocal.limits();
            limits.bytes = 5;
            limits.file_size = 3;
            assert!(inspect(&source, &sized(limits)).is_ok());
            limits.bytes = 4;
            limit(
                copy_local(&source, &parent.join("failed"), &sized(limits)),
                "bytes",
            );
            assert!(!parent.join("failed").exists());
            limits.bytes = 5;
            limits.file_size = 2;
            limit(inspect(&source, &sized(limits)), "file_size");
        }

        #[test]
        fn depth_and_utf8_path_byte_limits_have_exact_boundaries() {
            let temp = tempfile::tempdir().unwrap();
            directory(&temp.path().join("a"));
            write(&temp.path().join("a/é"), b"x", 0o600);
            let mut limits = BundleProfile::ReceiptLocal.limits();
            limits.depth = 2;
            limits.path_length = 4;
            assert!(inspect(temp.path(), &sized(limits)).is_ok());
            limits.path_length = 3;
            limit(inspect(temp.path(), &sized(limits)), "path_length");
            limits.path_length = 4;
            limits.depth = 1;
            limit(inspect(temp.path(), &sized(limits)), "depth");
        }

        #[test]
        fn rejects_invalid_names_and_nfc_lowercase_collisions_without_filesystem_assumptions() {
            for bytes in [
                b"bad\\name".as_slice(),
                b"line\nname",
                b"tab\t",
                b"bad\x7f",
                b"bad\xff",
                b"..",
                b"/absolute",
            ] {
                assert!(validate_name(OsStr::from_bytes(bytes)).is_err());
            }
            let budget = budget();
            let mut result = blank();
            let mut seen = HashSet::new();
            accept_path(Path::new("É.txt"), &mut result, &budget, &mut seen).unwrap();
            assert!(matches!(
                accept_path(Path::new("E\u{301}.TXT"), &mut result, &budget, &mut seen),
                Err(BundleError::Invalid(_))
            ));
            let mut seen = HashSet::new();
            accept_path(Path::new("Dir"), &mut result, &budget, &mut seen).unwrap();
            assert!(accept_path(Path::new("dir"), &mut result, &budget, &mut seen).is_err());
        }

        #[test]
        fn injected_clock_includes_prior_resolution_time_and_expires_during_copy() {
            let temp = tempfile::tempdir().unwrap();
            let source = temp.path().join("source");
            let parent = temp.path().join("quarantine");
            directory(&source);
            directory(&parent);
            write(&source.join("file"), b"x", 0o600);
            let seconds = Arc::new(AtomicU64::new(600));
            let clock = seconds.clone();
            let budget = BundleBudget {
                profile: BundleProfile::PostDependencies,
                limits: BundleProfile::PostDependencies.limits(),
                elapsed: Arc::new(move || Duration::from_secs(clock.load(Ordering::Relaxed))),
            };
            assert!(budget.check_time().is_ok());
            seconds.store(601, Ordering::Relaxed);
            limit(inspect(&source, &budget), "time");
            limit(
                copy_local(&source, &parent.join("expired"), &budget),
                "time",
            );
            assert!(!parent.join("expired").exists());
            let calls = Arc::new(AtomicU64::new(0));
            let mut limits = BundleProfile::ReceiptLocal.limits();
            limits.time = Duration::from_secs(10);
            let budget = BundleBudget {
                profile: BundleProfile::ReceiptLocal,
                limits,
                elapsed: Arc::new(move || {
                    Duration::from_secs(calls.fetch_add(1, Ordering::Relaxed))
                }),
            };
            limit(
                copy_local(&source, &parent.join("mid-copy"), &budget),
                "time",
            );
            assert!(!parent.join("mid-copy").exists());
        }

        #[test]
        fn rejects_special_entries_and_symlink_replaced_after_inspection() {
            let temp = tempfile::tempdir().unwrap();
            let source = temp.path().join("source");
            let parent = temp.path().join("quarantine");
            directory(&source);
            directory(&parent);
            write(&source.join("file"), b"safe", 0o600);
            inspect(&source, &budget()).unwrap();
            let outside = temp.path().join("outside");
            write(&outside, b"secret", 0o600);
            fs::remove_file(source.join("file")).unwrap();
            std::os::unix::fs::symlink(&outside, source.join("file")).unwrap();
            assert!(copy_local(&source, &parent.join("receipt"), &budget()).is_err());
            assert!(!parent.join("receipt").exists());
            fs::remove_file(source.join("file")).unwrap();
            let fifo = CString::new(source.join("fifo").as_os_str().as_bytes()).unwrap();
            // SAFETY: only this temporary fixture FIFO is created.
            assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
            assert!(inspect(&source, &budget()).is_err());
            fs::remove_file(source.join("fifo")).unwrap();
            let listener = std::os::unix::net::UnixListener::bind(source.join("socket")).unwrap();
            assert!(inspect(&source, &budget()).is_err());
            drop(listener);
        }

        #[test]
        fn root_is_anchored_and_existing_or_unsafe_destinations_are_rejected() {
            let temp = tempfile::tempdir().unwrap();
            let source = temp.path().join("source");
            let moved = temp.path().join("moved");
            let outside = temp.path().join("outside");
            let parent = temp.path().join("quarantine");
            directory(&source);
            directory(&outside);
            directory(&parent);
            write(&source.join("file"), b"safe", 0o600);
            write(&outside.join("file"), b"secret", 0o600);
            let (anchored, _) = open_root(&source).unwrap();
            fs::rename(&source, &moved).unwrap();
            std::os::unix::fs::symlink(&outside, &source).unwrap();
            assert_eq!(walk(anchored, None, &budget()).unwrap().total_bytes, 4);
            assert!(inspect(&source, &budget()).is_err());
            let destination = parent.join("existing");
            directory(&destination);
            write(&destination.join("marker"), b"keep", 0o600);
            assert!(copy_local(&moved, &destination, &budget()).is_err());
            assert_eq!(fs::read(destination.join("marker")).unwrap(), b"keep");
            assert!(copy_local(&moved, &moved.join("nested"), &budget()).is_err());
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(copy_local(&moved, &parent.join("other"), &budget()).is_err());
        }
    }
}
