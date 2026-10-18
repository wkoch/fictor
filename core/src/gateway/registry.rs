//! Model-visible tools come from the active lock and immutable manifests, never
//! from a live process or MCP annotations. This module does not execute tools.
use crate::installer::{
    lock::{Lock, LockedVersion},
    manifest::{Effect, MAX_MANIFEST_BYTES, Manifest, RuntimeKind, Scope, Sensitivity},
    overrides::{self, EffectiveManifest},
};
use serde::Serialize;
use serde_json::Value;
use std::{
    fs::OpenOptions,
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("active tool registry is unavailable")]
    Unavailable,
    #[error("active tool manifest or catalog is invalid")]
    Invalid,
    #[error("active tool registry exceeds the protocol message limit")]
    TooLarge,
}

/// The wire shape of ToolDef in Kernel Protocol 1 (spec/03-kernel-protocol.md).
#[derive(Debug, Serialize)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub effect: Effect,
    pub sensitivity: Sensitivity,
}

/// Enumerate without launching extensions. Malformed active state is an error,
/// rather than a successful partial/empty catalog that hides a broken lock.
pub fn model_tools(home: &Path) -> Result<Vec<ToolDef>, RegistryError> {
    model_tools_bounded(home, crate::kernel::MAX_MESSAGE_BYTES)
}

fn model_tools_bounded(home: &Path, limit: usize) -> Result<Vec<ToolDef>, RegistryError> {
    let lock = Lock::load(home).map_err(|_| RegistryError::Unavailable)?;
    let mut tools = Vec::new();
    let mut budget = ResponseBudget {
        used: b"{\"tools\":[]}".len(),
        limit,
    };
    if budget.used > limit {
        return Err(RegistryError::TooLarge);
    }
    for (id, extension) in &lock.extensions {
        if !extension.enabled {
            continue;
        }
        let version = extension
            .versions
            .get(&extension.active)
            .ok_or(RegistryError::Invalid)?;
        let effective = active_manifest(home, id, version)?;
        let manifest = effective.manifest();
        let catalog = effective.catalog();
        if !manifest.mcp_enabled() && !catalog.tools().is_empty() {
            return Err(RegistryError::Invalid);
        }
        for tool in catalog.tools() {
            let name = tool["name"].as_str().ok_or(RegistryError::Invalid)?;
            let class = effective.tool_class(name).ok_or(RegistryError::Invalid)?;
            if !class.model_visible {
                continue;
            }
            let definition = ToolDef {
                name: format!("{id}__{name}"),
                description: match tool.get("description") {
                    Some(Value::String(description)) => description.clone(),
                    None => String::new(),
                    Some(_) => return Err(RegistryError::Invalid),
                },
                input_schema: tool["inputSchema"].clone(),
                effect: class.effect,
                sensitivity: class.sensitivity,
            };
            if !tools.is_empty() {
                budget
                    .write_all(b",")
                    .map_err(|_| RegistryError::TooLarge)?;
            }
            // Count escaped UTF-8 JSON as it is produced, without allocating a
            // second serialized catalog or accumulating an oversized response.
            serde_json::to_writer(&mut budget, &definition).map_err(|_| RegistryError::TooLarge)?;
            tools.push(definition);
        }
    }
    tools.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    Ok(tools)
}

struct ResponseBudget {
    used: usize,
    limit: usize,
}
impl Write for ResponseBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.used = self
            .used
            .checked_add(bytes.len())
            .filter(|used| *used <= self.limit)
            .ok_or_else(|| io::Error::other("tool response limit"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Shared active-state validation for tools and catalog. The caller has loaded
/// the enclosing Lock; consume one manifest at a time to bound retained memory.
pub(crate) fn active_manifest(
    home: &Path,
    id: &str,
    version: &LockedVersion,
) -> Result<EffectiveManifest, RegistryError> {
    let manifest = read_manifest(&home.join("extensions").join(&version.path))?;
    if manifest.id != id
        || manifest.version != version.version
        || (manifest.scope == Scope::Global && manifest.runtime.kind != RuntimeKind::None)
    {
        return Err(RegistryError::Invalid);
    }
    let catalog = version.catalog().map_err(|_| RegistryError::Invalid)?;
    overrides::resolve(
        &manifest,
        &catalog,
        &version.overrides,
        &version.approved.by,
        &crate::proxy::nat64::Nat64Prefixes::default(),
    )
    .map_err(|_| RegistryError::Invalid)
}

fn read_manifest(bundle: &Path) -> Result<Manifest, RegistryError> {
    // Lock::load has validated every private parent/store component. The final
    // file is opened without following links and cannot block on a FIFO.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(bundle.join("fictor.yaml"))
        .map_err(|_| RegistryError::Unavailable)?;
    let metadata = file.metadata().map_err(|_| RegistryError::Unavailable)?;
    if !metadata.is_file()
        || metadata.mode() & 0o222 != 0
        || metadata.len() > MAX_MANIFEST_BYTES as u64
    {
        return Err(RegistryError::Invalid);
    }
    let mut text = String::new();
    file.take(MAX_MANIFEST_BYTES as u64 + 1)
        .read_to_string(&mut text)
        .map_err(|_| RegistryError::Invalid)?;
    if text.len() > MAX_MANIFEST_BYTES {
        return Err(RegistryError::Invalid);
    }
    Manifest::parse(&text).map_err(|_| RegistryError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        gateway::PinnedCatalog,
        installer::lock::{Approval, LockedExtension, LockedVersion, Overrides},
    };
    use serde_json::json;
    use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt};

    fn fixture(home: &Path, classes: Value, tools: Vec<Value>) -> Lock {
        fs::set_permissions(home, fs::Permissions::from_mode(0o700)).unwrap();
        crate::home::prepare(home).unwrap();
        let hash = format!("sha256:{}", "a".repeat(64));
        let key = format!("1.0.0-{}", "a".repeat(12));
        let relative = format!("store/example/{key}");
        let bundle = home.join("extensions").join(&relative);
        fs::create_dir_all(&bundle).unwrap();
        let manifest = json!({
            "schema":1,"id":"example","version":"1.0.0","description":"Registry fixture","scope":"session",
            "runtime":{"kind":"binary","entry":"never-executed"},"tools":classes
        });
        assert!(Manifest::parse(&manifest.to_string()).is_ok());
        let path = bundle.join("fictor.yaml");
        fs::write(&path, manifest.to_string()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        let catalog = PinnedCatalog::new(tools.clone()).unwrap();
        let version = LockedVersion {
            version: "1.0.0".into(),
            hash,
            path: relative,
            source: json!({"kind":"local"}),
            approved: Approval {
                by: "user".into(),
                at: "2026-10-18T12:00:00Z".into(),
                approval_id: None,
            },
            overrides: Overrides::default(),
            privileges: vec![],
            tools,
            tools_hash: catalog.hash().into(),
            packages: vec![],
            audit: None,
        };
        let lock = Lock {
            schema: 1,
            extensions: BTreeMap::from([(
                "example".into(),
                LockedExtension {
                    enabled: true,
                    active: key.clone(),
                    versions: BTreeMap::from([(key, version)]),
                },
            )]),
        };
        lock.write_atomic(home).unwrap();
        lock
    }

    fn tool(name: &str) -> Value {
        json!({"name":name,"description":"Pinned definition","inputSchema":{"type":"object"},
            "annotations":{"readOnlyHint":true,"openWorldHint":false}})
    }

    #[test]
    fn active_pinned_tools_use_named_then_default_then_restrictive_classification() {
        let home = tempfile::tempdir().unwrap();
        fixture(
            home.path(),
            json!({"named":{"effect":"read","sensitivity":"public"},
            "default":{"effect":"write_local"}}),
            vec![tool("other"), tool("named")],
        );
        let tools = model_tools(home.path()).unwrap();
        assert_eq!(tools[0].name, "example__named");
        assert_eq!(tools[0].effect, Effect::Read);
        assert_eq!(tools[0].sensitivity, Sensitivity::Public);
        assert_eq!(tools[1].effect, Effect::WriteLocal);
        assert_eq!(tools[1].sensitivity, Sensitivity::Private);
        assert_eq!(
            serde_json::to_value(&tools[0]).unwrap(),
            json!({
                "name":"example__named","description":"Pinned definition",
                "input_schema":{"type":"object"},"effect":"read","sensitivity":"public"
            })
        );
        let other = tempfile::tempdir().unwrap();
        fixture(other.path(), json!({}), vec![tool("unclassified")]);
        let restrictive = model_tools(other.path()).unwrap();
        assert_eq!(restrictive[0].effect, Effect::External);
        assert_eq!(restrictive[0].sensitivity, Sensitivity::Private);
    }

    #[test]
    fn hooks_hidden_tools_and_disabled_extensions_do_not_appear() {
        let home = tempfile::tempdir().unwrap();
        let mut lock = fixture(
            home.path(),
            json!({"hidden":{"model_visible":false,"ui_callable":true}}),
            vec![tool("visible"), tool("hook_prompt.submit"), tool("hidden")],
        );
        let tools = model_tools(home.path()).unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "example__visible");
        lock.extensions.get_mut("example").unwrap().enabled = false;
        lock.write_atomic(home.path()).unwrap();
        assert!(model_tools(home.path()).unwrap().is_empty());
    }

    #[test]
    fn approved_override_hides_the_tool_without_ignoring_invalid_state() {
        let home = tempfile::tempdir().unwrap();
        let mut lock = fixture(home.path(), json!({}), vec![tool("echo")]);
        let extension = lock.extensions.get_mut("example").unwrap();
        let version = extension.versions.get_mut(&extension.active).unwrap();
        version.overrides = crate::installer::overrides::Overrides::from_value(
            json!({"tools":{"echo":{"model_visible":false}}}),
        )
        .unwrap();
        lock.write_atomic(home.path()).unwrap();
        assert!(model_tools(home.path()).unwrap().is_empty());
        let path = home.path().join("extensions/lock.json");
        fs::write(path, b"invalid lock").unwrap();
        assert!(matches!(
            model_tools(home.path()),
            Err(RegistryError::Unavailable)
        ));
    }

    #[test]
    fn invalid_pinned_description_is_not_silently_rewritten() {
        let home = tempfile::tempdir().unwrap();
        let mut invalid = tool("echo");
        invalid["description"] = json!(7);
        fixture(home.path(), json!({}), vec![invalid]);
        assert!(matches!(
            model_tools(home.path()),
            Err(RegistryError::Invalid)
        ));
    }

    #[test]
    fn cumulative_wire_limit_counts_escaped_utf8_before_accumulating_tools() {
        let home = tempfile::tempdir().unwrap();
        let mut escaped = tool("second");
        escaped["description"] = json!("quoted \"\\\té");
        fixture(home.path(), json!({}), vec![tool("first"), escaped]);
        let tools = model_tools(home.path()).unwrap();
        let size = serde_json::to_vec(&json!({"tools":tools})).unwrap().len();
        assert_eq!(model_tools_bounded(home.path(), size).unwrap().len(), 2);
        assert!(matches!(
            model_tools_bounded(home.path(), size - 1),
            Err(RegistryError::TooLarge)
        ));
    }

    #[test]
    fn manifest_identity_mutability_and_symlinks_are_rejected() {
        let home = tempfile::tempdir().unwrap();
        let lock = fixture(home.path(), json!({}), vec![tool("echo")]);
        let extension = &lock.extensions["example"];
        let path = home
            .path()
            .join("extensions")
            .join(&extension.versions[&extension.active].path)
            .join("fictor.yaml");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            model_tools(home.path()),
            Err(RegistryError::Invalid)
        ));
        let mut manifest: Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        manifest["id"] = "different".into();
        fs::write(&path, manifest.to_string()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(matches!(
            model_tools(home.path()),
            Err(RegistryError::Invalid)
        ));
        let target = home.path().join("private-manifest");
        fs::rename(&path, &target).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(matches!(
            model_tools(home.path()),
            Err(RegistryError::Unavailable)
        ));
    }
}
