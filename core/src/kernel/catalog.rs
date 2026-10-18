//! Phase-0 declarative catalog. Listing only inspects active immutable bundles;
//! no extension, command prompt, skill body or script is executed or returned.
use crate::{
    gateway::registry,
    installer::{
        bundle::{BundleBudget, BundleProfile, MAX_BUNDLE_BYTES},
        lock::Lock,
        manifest::parse_yaml_value,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CStr, CString},
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
};
use unicode_normalization::UnicodeNormalization;

use super::MAX_MESSAGE_BYTES;
// ADR-024 post-dependency ceilings. These are per bundle, as in the installer;
// only serialized output has the Kernel Protocol's cumulative 16-MiB ceiling.
const MAX_FILE_BYTES: usize = 100 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub(super) enum CatalogError {
    #[error("active catalog is invalid or unavailable")]
    Invalid,
    #[error("active catalog exceeds its resource limit")]
    TooLarge,
}
impl From<io::Error> for CatalogError {
    fn from(_: io::Error) -> Self {
        Self::Invalid
    }
}

/// Exact `catalog.list` wire shape from spec/03. Phase-1 fields remain empty.
#[derive(Default, Serialize)]
pub(super) struct Catalog {
    skills: Vec<Skill>,
    commands: Vec<Command>,
    surfaces: [(); 0],
    hooks: BTreeMap<String, Vec<String>>,
}
#[derive(Serialize)]
struct Skill {
    ext_id: String,
    name: String,
    description: String,
    path: PathBuf,
}
#[derive(Serialize)]
struct Command {
    ext_id: String,
    name: String,
    description: String,
    prompt_path: PathBuf,
}

pub(super) fn list(home: &Path) -> Result<Catalog, CatalogError> {
    list_bounded(home, MAX_MESSAGE_BYTES)
}

fn list_bounded(home: &Path, limit: usize) -> Result<Catalog, CatalogError> {
    let home = home.canonicalize()?;
    let lock = Lock::load(&home).map_err(|_| CatalogError::Invalid)?;
    let mut catalog = Catalog::default();
    let mut output = Budget { remaining: limit };
    serde_json::to_writer(&mut output, &catalog).map_err(|_| CatalogError::TooLarge)?;
    for (id, extension) in &lock.extensions {
        if !extension.enabled {
            continue;
        }
        let version = extension
            .versions
            .get(&extension.active)
            .ok_or(CatalogError::Invalid)?;
        let manifest =
            registry::active_manifest(&home, id, version).map_err(|_| CatalogError::Invalid)?;
        if manifest
            .hooks
            .as_ref()
            .is_some_and(|hooks| !hooks.is_empty())
            || !manifest.surfaces.is_empty()
        {
            // Discovery does not implement the Phase-1 fan-out or UI contract.
            return Err(CatalogError::Invalid);
        }
        let bundle_path = home.join("extensions").join(&version.path);
        let bundle = open_bundle(&home, id, &extension.active)?;
        let time = BundleBudget::start(BundleProfile::PostDependencies);
        let mut input = Budget {
            remaining: MAX_BUNDLE_BYTES as usize,
        };
        let mut entries = 50_000usize;
        let skills_path = manifest.skills.as_deref().unwrap_or("skills");
        let skills = match relative(&bundle, skills_path, true) {
            Ok(skills) => Some(skills),
            Err(error) if error.kind() == io::ErrorKind::NotFound && manifest.skills.is_none() => {
                None
            }
            Err(_) => return Err(CatalogError::Invalid),
        };
        let mut skill_names = BTreeSet::new();
        if let Some(skills) = skills {
            for name in names(&skills, &mut entries, &time)? {
                time.check_time().map_err(|_| CatalogError::TooLarge)?;
                let child = open_at(&skills, &name, false)?;
                let metadata = child.metadata()?;
                if metadata.is_file() {
                    immutable(&child, false)?;
                    continue; // A collection may also contain e.g. a README.
                }
                immutable(&child, true)?;
                let file = open_at(&child, c"SKILL.md", false)?;
                immutable(&file, false)?;
                let parent = name.to_str().map_err(|_| CatalogError::Invalid)?;
                let skill_path = Path::new(skills_path).join(parent).join("SKILL.md");
                if skill_path.as_os_str().as_encoded_bytes().len() > 1024
                    || skill_path.components().count() > 64
                {
                    return Err(CatalogError::Invalid);
                }
                let metadata = frontmatter(file, parent, &mut input, &time)?;
                if !skill_names.insert(metadata.name.clone()) {
                    return Err(CatalogError::Invalid);
                }
                let skill = Skill {
                    ext_id: id.clone(),
                    name: metadata.name,
                    description: metadata.description,
                    path: bundle_path.join(skill_path),
                };
                account(&mut output, &skill, !catalog.skills.is_empty())?;
                catalog.skills.push(skill);
            }
        }
        for command in manifest.commands {
            time.check_time().map_err(|_| CatalogError::TooLarge)?;
            let prompt = relative(&bundle, &command.prompt, false)?;
            immutable(&prompt, false)?;
            let command = Command {
                ext_id: id.clone(),
                name: command.name,
                description: command.description,
                prompt_path: bundle_path.join(command.prompt),
            };
            account(&mut output, &command, !catalog.commands.is_empty())?;
            catalog.commands.push(command);
        }
    }
    catalog
        .skills
        .sort_by(|a, b| (&a.ext_id, &a.name).cmp(&(&b.ext_id, &b.name)));
    catalog
        .commands
        .sort_by(|a, b| (&a.ext_id, &a.name).cmp(&(&b.ext_id, &b.name)));
    Ok(catalog)
}

struct Budget {
    remaining: usize,
}
impl Write for Budget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("catalog limit"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn account(budget: &mut Budget, value: &impl Serialize, comma: bool) -> Result<(), CatalogError> {
    if comma {
        budget.write_all(b",").map_err(|_| CatalogError::TooLarge)?;
    }
    // Count escaped UTF-8 JSON before retaining an item, without a second large
    // serialization buffer. Transport checks the complete JSON-RPC envelope.
    serde_json::to_writer(budget, value).map_err(|_| CatalogError::TooLarge)
}

// Agent Skills specification + reference validator, checked 2026-10-18:
// https://agentskills.io/specification
// https://github.com/agentskills/agentskills/tree/main/skills-ref
// Optional metadata is data only; `allowed-tools` never grants permissions.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SkillMetadata {
    name: String,
    description: String,
    #[serde(default, rename = "license")]
    _license: Option<String>,
    #[serde(default)]
    compatibility: Option<String>,
    #[serde(default, rename = "allowed-tools")]
    _allowed_tools: Option<String>,
    #[serde(default, rename = "metadata")]
    _metadata: Option<BTreeMap<String, String>>,
}
fn frontmatter(
    file: File,
    parent: &str,
    input: &mut Budget,
    time: &BundleBudget,
) -> Result<SkillMetadata, CatalogError> {
    // Consume only through the closing delimiter. Buffered I/O may prefetch a
    // suffix, but Markdown body bytes never enter YAML parsing or the response.
    let mut reader = BufReader::new(file).take(input.remaining.min(MAX_FILE_BYTES) as u64 + 1);
    let mut file_bytes = Budget {
        remaining: MAX_FILE_BYTES,
    };
    let mut line = Vec::new();
    reader.read_until(b'\n', &mut line)?;
    input.write_all(&line).map_err(|_| CatalogError::TooLarge)?;
    file_bytes
        .write_all(&line)
        .map_err(|_| CatalogError::TooLarge)?;
    if !delimiter(&line) {
        return Err(CatalogError::Invalid);
    }
    let mut yaml = Vec::new();
    loop {
        time.check_time().map_err(|_| CatalogError::TooLarge)?;
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            return Err(CatalogError::Invalid);
        }
        input.write_all(&line).map_err(|_| CatalogError::TooLarge)?;
        file_bytes
            .write_all(&line)
            .map_err(|_| CatalogError::TooLarge)?;
        if delimiter(&line) {
            break;
        }
        yaml.extend_from_slice(&line);
    }
    let yaml = std::str::from_utf8(&yaml).map_err(|_| CatalogError::Invalid)?;
    parse_yaml_value(yaml, MAX_FILE_BYTES).map_err(|_| CatalogError::Invalid)?;
    // Typed YAML strings preserve scalar text (including numeric skill names);
    // the first pass already bounded nesting/expansion and rejected duplicates.
    let mut metadata: SkillMetadata =
        serde_yaml_ng::from_str(yaml).map_err(|_| CatalogError::Invalid)?;
    metadata.name = metadata.name.trim().nfkc().collect();
    let normalized_parent: String = parent.nfkc().collect();
    if metadata.name.is_empty()
        || metadata.name.chars().count() > 64
        || metadata.name != normalized_parent
        || metadata.name.to_lowercase() != metadata.name
        || metadata.name.starts_with('-')
        || metadata.name.ends_with('-')
        || metadata.name.contains("--")
        || !metadata
            .name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-')
        || metadata.description.trim().is_empty()
        || metadata.description.chars().count() > 1024
        || metadata
            .compatibility
            .as_ref()
            .is_some_and(|value| value.chars().count() > 500)
    {
        return Err(CatalogError::Invalid);
    }
    metadata.description = metadata.description.trim().to_owned();
    Ok(metadata)
}
fn delimiter(line: &[u8]) -> bool {
    std::str::from_utf8(line).is_ok_and(|line| line.trim_end() == "---")
}

fn open_bundle(home: &Path, id: &str, key: &str) -> Result<File, CatalogError> {
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(home)?;
    for name in ["extensions", "store", id, key] {
        let name = CString::new(name).map_err(|_| CatalogError::Invalid)?;
        directory = open_at(&directory, &name, true)?;
    }
    immutable(&directory, true)?;
    Ok(directory)
}
fn relative(root: &File, path: &str, directory: bool) -> io::Result<File> {
    let parts: Vec<_> = Path::new(path).components().collect();
    if parts.is_empty()
        || parts.len() > 64
        || path.len() > 1024
        || parts
            .iter()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(io::Error::other("invalid catalog path"));
    }
    let mut parent = root.try_clone()?;
    for (position, part) in parts.iter().enumerate() {
        let Component::Normal(name) = part else {
            return Err(io::Error::other("invalid path"));
        };
        let name =
            CString::new(name.as_encoded_bytes()).map_err(|_| io::Error::other("invalid path"))?;
        let is_directory = directory || position + 1 < parts.len();
        parent = open_at(&parent, &name, is_directory)?;
        immutable(&parent, is_directory)?;
    }
    Ok(parent)
}
fn open_at(parent: &File, name: &CStr, directory: bool) -> io::Result<File> {
    let mut metadata = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent and name are live; metadata is aligned writable storage.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstatat initialized metadata. Reject links/devices/FIFOs
    // before opening them; immutable parents prevent extension-controlled swaps.
    let kind = unsafe { metadata.assume_init() }.st_mode & libc::S_IFMT;
    if !matches!(kind, libc::S_IFREG | libc::S_IFDIR) || (directory && kind != libc::S_IFDIR) {
        return Err(io::Error::other("invalid catalog entry type"));
    }
    let flags = libc::O_RDONLY
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | libc::O_CLOEXEC
        | if directory { libc::O_DIRECTORY } else { 0 };
    // SAFETY: parent descriptor and the NUL-terminated name remain live.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful openat transfers a fresh descriptor to this sole owner.
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn immutable(file: &File, directory: bool) -> io::Result<()> {
    let metadata = file.metadata()?;
    if (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
        || metadata.mode() & 0o222 != 0
        || (!directory && metadata.len() > MAX_FILE_BYTES as u64)
    {
        return Err(io::Error::other("mutable or invalid catalog entry"));
    }
    Ok(())
}

struct Entries(*mut libc::DIR);
impl Drop for Entries {
    fn drop(&mut self) {
        // SAFETY: fdopendir transferred its unique directory stream to Entries.
        unsafe {
            libc::closedir(self.0);
        }
    }
}
fn names(
    directory: &File,
    remaining: &mut usize,
    time: &BundleBudget,
) -> Result<Vec<CString>, CatalogError> {
    use std::os::fd::IntoRawFd;
    let fd = directory.try_clone()?.into_raw_fd();
    // SAFETY: fd is an owned open directory descriptor. fdopendir takes it only
    // on success; close it ourselves on failure.
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: fdopendir failed, so fd remains ours to close.
        unsafe {
            libc::close(fd);
        }
        return Err(error.into());
    }
    let stream = Entries(stream);
    let mut names = Vec::new();
    loop {
        time.check_time().map_err(|_| CatalogError::TooLarge)?;
        // SAFETY: Linux errno is thread-local; readdir uses a live owned stream.
        unsafe {
            *libc::__errno_location() = 0;
        }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(error.into());
            }
            break;
        }
        // SAFETY: readdir returns a NUL-terminated d_name valid until next call;
        // copy it before advancing or releasing the directory stream.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        *remaining = remaining.checked_sub(1).ok_or(CatalogError::TooLarge)?;
        let text = name.to_str().map_err(|_| CatalogError::Invalid)?;
        if text.chars().any(char::is_control) || text.contains('\\') {
            return Err(CatalogError::Invalid);
        }
        names.push(name.to_owned());
    }
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn metadata(text: &str, parent: &str) -> Result<SkillMetadata, CatalogError> {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(text.as_bytes()).unwrap();
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(0)).unwrap();
        frontmatter(
            file,
            parent,
            &mut Budget {
                remaining: MAX_BUNDLE_BYTES as usize,
            },
            &BundleBudget::start(BundleProfile::PostDependencies),
        )
    }
    #[test]
    fn standard_names_and_optional_metadata_do_not_grant_or_expose_skill_bodies() {
        for name in ["123", "日本語", "análise"] {
            let value = metadata(&format!("---\nname: {name}\ndescription: |\n  Useful advice\nlicense: MIT\ncompatibility: Linux\nallowed-tools: Bash(*)\nmetadata:\n  revision: 1\n---\nname: !!invalid body is never parsed"), name).unwrap();
            assert_eq!(value.name, name);
            assert_eq!(value.description, "Useful advice");
        }
        assert!(
            metadata(
                "---\nname: &name advice\ndescription: *name\n---\n",
                "advice"
            )
            .is_ok()
        );
        assert!(
            metadata(
                "---\nname: advice\ndescription: 'literal !!tag !text'\n---\n",
                "advice"
            )
            .is_ok()
        );
        for name in ["Upper", "a--b", "-a", "a-", "has space"] {
            assert!(
                metadata(
                    &format!("---\nname: {name}\ndescription: Advice\n---\n"),
                    name
                )
                .is_err()
            );
        }
    }
    #[test]
    fn optional_metadata_uses_bundle_limits_even_when_larger_than_the_wire_limit() {
        let text = format!(
            "---\nname: advice\ndescription: Advice\nlicense: {}\n---\n",
            "x".repeat(MAX_MESSAGE_BYTES + 1)
        );
        assert_eq!(metadata(&text, "advice").unwrap().description, "Advice");
    }
    #[test]
    fn response_budget_counts_escaped_strings_before_accumulation() {
        let value = Skill {
            ext_id: "a".into(),
            name: "skill".into(),
            description: "\"\n\\".repeat(30),
            path: "/store/SKILL.md".into(),
        };
        let length = serde_json::to_vec(&value).unwrap().len();
        assert!(account(&mut Budget { remaining: length }, &value, false).is_ok());
        assert!(matches!(
            account(
                &mut Budget {
                    remaining: length - 1
                },
                &value,
                false
            ),
            Err(CatalogError::TooLarge)
        ));
        assert!(matches!(
            account(&mut Budget { remaining: length }, &value, true),
            Err(CatalogError::TooLarge)
        ));
    }
}
