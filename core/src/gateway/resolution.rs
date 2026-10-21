//! Offline steps 1–2 of `tools.call`: exact identity and pinned arguments.
//! Resolution is not authorization, approval, or admission. The trusted core
//! caller retains the home owner and must revalidate the selected version and
//! admission state before execution. This module starts no process and writes
//! no state. Hooks are never resolvable here.
//! It relies on store immutability established during promotion: path, mode,
//! manifest identity and catalog pin are checked, without rehashing the bundle.
use super::{GatewayError, registry};
use crate::{
    installer::{
        lock::{Lock, LockError},
        manifest::ToolClass,
        overrides::EffectiveManifest,
    },
    proxy::{allowlist::Allowlist, nat64::Nat64Prefixes},
};
use serde_json::Value;
use std::path::Path;

/// An immutable resolution snapshot, including the exact validated arguments.
/// Deliberately neither Debug nor Serialize: arguments may contain private data.
pub struct ResolvedTool {
    extension_id: String,
    key: String,
    raw_name: String,
    exposed_name: String,
    effective: EffectiveManifest,
    class: ToolClass,
    arguments: Value,
    nat64: Nat64Prefixes,
}

impl ResolvedTool {
    pub fn extension_id(&self) -> &str {
        &self.extension_id
    }
    pub fn key(&self) -> &str {
        &self.key
    }
    pub fn raw_name(&self) -> &str {
        &self.raw_name
    }
    pub fn exposed_name(&self) -> &str {
        &self.exposed_name
    }
    pub fn effective(&self) -> &EffectiveManifest {
        &self.effective
    }
    pub fn class(&self) -> &ToolClass {
        &self.class
    }
    pub fn arguments(&self) -> &Value {
        &self.arguments
    }
    pub fn nat64(&self) -> &Nat64Prefixes {
        &self.nat64
    }
}

/// Resolve an exact `<ext_id>__<raw_name>` using the approved active lock only.
/// `model_visible` filters discovery; it is not an authorization rule here.
/// The supplied NAT64 configuration is pinned into the returned snapshot and
/// revalidates effective network authority exactly as result provenance does.
pub fn resolve(
    home: &Path,
    exposed_name: &str,
    arguments: Value,
    nat64: &Nat64Prefixes,
) -> Result<ResolvedTool, GatewayError> {
    let (extension_id, raw_name) = exposed_name
        .split_once("__")
        .ok_or(GatewayError::NotFound)?;
    if extension_id.is_empty() || raw_name.is_empty() || raw_name.starts_with("hook_") {
        return Err(GatewayError::NotFound);
    }
    let lock = Lock::load_required(home).map_err(|error| match error {
        LockError::Invalid => GatewayError::InvalidCatalog,
        _ => GatewayError::Unavailable,
    })?;
    let extension = lock
        .extensions
        .get(extension_id)
        .ok_or(GatewayError::NotFound)?;
    if !extension.enabled {
        return Err(GatewayError::Unavailable);
    }
    let version = extension
        .versions
        .get(&extension.active)
        .ok_or(GatewayError::InvalidCatalog)?;
    let effective =
        registry::active_manifest(home, extension_id, version).map_err(|error| match error {
            registry::RegistryError::Invalid => GatewayError::InvalidCatalog,
            _ => GatewayError::Unavailable,
        })?;
    if !effective.manifest().mcp_enabled() && !effective.catalog().tools().is_empty() {
        return Err(GatewayError::InvalidCatalog);
    }
    Allowlist::new_with_nat64(&effective.manifest().permissions.net.allow, nat64)
        .map_err(|_| GatewayError::InvalidCatalog)?;
    effective
        .catalog()
        .validate_arguments(raw_name, &arguments)?;
    let class = effective
        .tool_class(raw_name)
        .cloned()
        .ok_or(GatewayError::InvalidCatalog)?;
    Ok(ResolvedTool {
        extension_id: extension_id.into(),
        key: extension.active.clone(),
        raw_name: raw_name.into(),
        exposed_name: exposed_name.into(),
        effective,
        class,
        arguments,
        nat64: nat64.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        gateway::PinnedCatalog,
        installer::{
            lock::{Approval, LockedExtension, LockedVersion},
            manifest::{Effect, Manifest, Sensitivity},
            overrides::Overrides,
        },
    };
    use serde_json::json;
    use std::{
        collections::BTreeMap,
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::PathBuf,
    };

    struct Fixture {
        root: tempfile::TempDir,
        home: PathBuf,
        bundle: PathBuf,
        lock: Lock,
        marker: PathBuf,
    }
    impl Fixture {
        fn new(classes: Value, tools: Vec<Value>, network: &[&str]) -> Self {
            let root = tempfile::Builder::new()
                .prefix("fx-resolution-")
                .tempdir_in("/tmp")
                .unwrap();
            let home = root.path().join("home");
            crate::home::prepare(&home).unwrap();
            let key = format!("1.0.0-{}", "a".repeat(12));
            let relative = format!("store/example/{key}");
            let bundle = home.join("extensions").join(&relative);
            fs::create_dir_all(&bundle).unwrap();
            let marker = root.path().join("must-not-execute");
            let manifest = json!({"schema":1,"id":"example","version":"1.0.0","description":"Offline resolver fixture","scope":"session","runtime":{"kind":"binary","entry":"never-executed"},"permissions":{"net":{"allow":network}},"tools":classes});
            assert!(Manifest::parse(&manifest.to_string()).is_ok());
            fs::write(bundle.join("fictor.yaml"), manifest.to_string()).unwrap();
            fs::set_permissions(
                bundle.join("fictor.yaml"),
                fs::Permissions::from_mode(0o444),
            )
            .unwrap();
            fs::write(
                bundle.join("never-executed"),
                format!("#!/bin/sh\nprintf executed > '{}'\n", marker.display()),
            )
            .unwrap();
            fs::set_permissions(
                bundle.join("never-executed"),
                fs::Permissions::from_mode(0o555),
            )
            .unwrap();
            let catalog = PinnedCatalog::new(tools.clone()).unwrap();
            let version = LockedVersion {
                version: "1.0.0".into(),
                hash: format!("sha256:{}", "a".repeat(64)),
                path: relative,
                source: json!({"kind":"local"}),
                approved: Approval {
                    by: "user".into(),
                    at: "2026-10-20T12:00:00Z".into(),
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
                runtimes: BTreeMap::new(),
                extensions: [(
                    "example".into(),
                    LockedExtension {
                        enabled: true,
                        active: key.clone(),
                        versions: [(key, version)].into(),
                    },
                )]
                .into(),
            };
            lock.write_atomic(&home).unwrap();
            Self {
                root,
                home,
                bundle,
                lock,
                marker,
            }
        }
        fn version(&mut self) -> &mut LockedVersion {
            let extension = self.lock.extensions.get_mut("example").unwrap();
            extension.versions.get_mut(&extension.active).unwrap()
        }
        fn save(&self) {
            self.lock.write_atomic(&self.home).unwrap();
        }
        fn manifest(&self, change: impl FnOnce(&mut Value)) {
            let path = self.bundle.join("fictor.yaml");
            let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            change(&mut value);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(&path, value.to_string()).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o444)).unwrap();
        }
    }
    fn tool(name: &str) -> Value {
        json!({"name":name,"description":"Pinned tool","inputSchema":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"],"additionalProperties":false},"annotations":{"readOnlyHint":true}})
    }
    fn snapshot(path: &Path) -> BTreeMap<PathBuf, (u32, Vec<u8>)> {
        fn visit(root: &Path, path: &Path, found: &mut BTreeMap<PathBuf, (u32, Vec<u8>)>) {
            for entry in fs::read_dir(path).unwrap() {
                let path = entry.unwrap().path();
                let metadata = fs::symlink_metadata(&path).unwrap();
                let bytes = if metadata.is_file() {
                    fs::read(&path).unwrap()
                } else {
                    vec![]
                };
                found.insert(
                    path.strip_prefix(root).unwrap().into(),
                    (metadata.permissions().mode(), bytes),
                );
                if metadata.is_dir() {
                    visit(root, &path, found);
                }
            }
        }
        let mut found = BTreeMap::new();
        visit(path, path, &mut found);
        found
    }

    #[test]
    fn exact_names_split_only_the_first_separator_and_never_become_paths() {
        let fixture = Fixture::new(json!({}), vec![tool("read"), tool("read__tail")], &[]);
        let before = snapshot(fixture.root.path());
        let resolved = resolve(
            &fixture.home,
            "example__read__tail",
            json!({"text":"private fixture"}),
            &Nat64Prefixes::default(),
        )
        .unwrap();
        assert_eq!(resolved.extension_id(), "example");
        assert_eq!(resolved.key(), format!("1.0.0-{}", "a".repeat(12)));
        assert_eq!(resolved.raw_name(), "read__tail");
        assert_eq!(resolved.exposed_name(), "example__read__tail");
        assert_eq!(resolved.arguments(), &json!({"text":"private fixture"}));
        for name in [
            "read",
            "example",
            "__read",
            "example__",
            "Example__read",
            "example__Read",
            "example____read",
            "example__read/../tail",
            "../../example__read",
            "example/../example__read",
            "example__read\0",
            "example__read ",
        ] {
            assert!(
                matches!(
                    resolve(
                        &fixture.home,
                        name,
                        json!({"text":"fixture"}),
                        &Nat64Prefixes::default()
                    ),
                    Err(GatewayError::NotFound)
                ),
                "{name:?}"
            );
        }
        assert_eq!(snapshot(fixture.root.path()), before);
        assert!(!fixture.marker.exists());
    }

    #[test]
    fn hidden_is_not_an_acl_and_hooks_are_always_rejected() {
        let fixture = Fixture::new(
            json!({"hidden":{"effect":"read","model_visible":false,"ui_callable":false},"hook_before":{"model_visible":true}}),
            vec![tool("hidden"), tool("hook_before")],
            &[],
        );
        let resolved = resolve(
            &fixture.home,
            "example__hidden",
            json!({"text":"fixture"}),
            &Nat64Prefixes::default(),
        )
        .unwrap();
        assert!(!resolved.class().model_visible);
        assert!(!resolved.class().ui_callable);
        assert_eq!(resolved.class().effect, Effect::Read);
        assert!(matches!(
            resolve(
                &fixture.home,
                "example__hook_before",
                json!({"text":"fixture"}),
                &Nat64Prefixes::default()
            ),
            Err(GatewayError::NotFound)
        ));
        assert!(!fixture.marker.exists());
    }

    #[test]
    fn disabled_unknown_and_missing_lock_fail_without_starting_a_process() {
        let mut fixture = Fixture::new(json!({}), vec![tool("read")], &[]);
        assert!(matches!(
            resolve(
                &fixture.home,
                "absent__read",
                json!({}),
                &Nat64Prefixes::default()
            ),
            Err(GatewayError::NotFound)
        ));
        assert!(matches!(
            resolve(
                &fixture.home,
                "example__absent",
                json!({}),
                &Nat64Prefixes::default()
            ),
            Err(GatewayError::NotFound)
        ));
        fixture.lock.extensions.get_mut("example").unwrap().enabled = false;
        fixture.save();
        assert!(matches!(
            resolve(
                &fixture.home,
                "example__read",
                json!({"text":"fixture"}),
                &Nat64Prefixes::default()
            ),
            Err(GatewayError::Unavailable)
        ));
        fs::remove_file(fixture.home.join("extensions/lock.json")).unwrap();
        assert!(matches!(
            resolve(
                &fixture.home,
                "example__read",
                json!({"text":"fixture"}),
                &Nat64Prefixes::default()
            ),
            Err(GatewayError::Unavailable)
        ));
        assert!(!fixture.home.join("extensions/lock.json").exists());
        assert!(!fixture.marker.exists());
    }

    #[test]
    fn approved_overrides_and_offline_input_schema_are_the_only_classification_sources() {
        let mut fixture = Fixture::new(
            json!({"default":{"effect":"external","sensitivity":"private","output_trust":"untrusted"}}),
            vec![tool("read")],
            &[],
        );
        fixture.version().overrides = Overrides::from_value(json!({"tools":{"read":{"effect":"read","sensitivity":"public","output_trust":"trusted","timeout_ms":1000}}})).unwrap();
        fixture.save();
        let resolved = resolve(
            &fixture.home,
            "example__read",
            json!({"text":"fixture"}),
            &Nat64Prefixes::default(),
        )
        .unwrap();
        assert_eq!(resolved.class().effect, Effect::Read);
        assert_eq!(resolved.class().sensitivity, Sensitivity::Public);
        assert_eq!(resolved.class().timeout_ms, 1000);
        for invalid in [
            json!(null),
            json!([]),
            json!({}),
            json!({"text":42}),
            json!({"text":"fixture","extra":true}),
        ] {
            assert!(matches!(
                resolve(
                    &fixture.home,
                    "example__read",
                    invalid,
                    &Nat64Prefixes::default()
                ),
                Err(GatewayError::InvalidArguments)
            ));
        }
        assert!(!fixture.marker.exists());
    }

    #[test]
    fn a_resolution_snapshot_keeps_its_arguments_version_and_effective_class_after_state_changes() {
        let mut fixture = Fixture::new(
            json!({"read":{"effect":"read","sensitivity":"public"}}),
            vec![tool("read")],
            &[],
        );
        let resolved = resolve(
            &fixture.home,
            "example__read",
            json!({"text":"original"}),
            &Nat64Prefixes::default(),
        )
        .unwrap();
        fixture.manifest(|manifest| {
            manifest["tools"]["read"]["effect"] = json!("external");
        });
        fixture.lock.extensions.get_mut("example").unwrap().enabled = false;
        fixture.save();
        assert_eq!(resolved.arguments(), &json!({"text":"original"}));
        assert_eq!(resolved.class().effect, Effect::Read);
        assert_eq!(resolved.effective().manifest().version, "1.0.0");
        assert!(matches!(
            resolve(
                &fixture.home,
                "example__read",
                json!({"text":"later"}),
                &Nat64Prefixes::default()
            ),
            Err(GatewayError::Unavailable)
        ));
        assert!(!fixture.marker.exists());
    }

    #[test]
    fn invalid_schema_forged_pin_or_changed_manifest_never_resolve_partially() {
        for defect in ["schema", "pin", "identity", "writable", "symlink", "global"] {
            let fixture = Fixture::new(json!({}), vec![tool("read")], &[]);
            match defect {
                "schema" | "pin" => {
                    let mut value = serde_json::to_value(&fixture.lock).unwrap();
                    let active = fixture.lock.extensions["example"].active.clone();
                    if defect == "schema" {
                        value["extensions"]["example"]["versions"][&active]["tools"][0]["inputSchema"] =
                            json!({"$ref":"http://127.0.0.1:9/never-fetch"});
                    } else {
                        value["extensions"]["example"]["versions"][&active]["tools_hash"] =
                            json!(format!("sha256:{}", "0".repeat(64)));
                    }
                    fs::write(
                        fixture.home.join("extensions/lock.json"),
                        serde_json::to_vec(&value).unwrap(),
                    )
                    .unwrap();
                }
                "identity" => fixture.manifest(|value| {
                    value["id"] = json!("different");
                }),
                "writable" => fs::set_permissions(
                    fixture.bundle.join("fictor.yaml"),
                    fs::Permissions::from_mode(0o644),
                )
                .unwrap(),
                "global" => fixture.manifest(|value| {
                    value["scope"] = json!("global");
                }),
                "symlink" => {
                    let outside = fixture.root.path().join("outside.yaml");
                    fs::rename(fixture.bundle.join("fictor.yaml"), &outside).unwrap();
                    symlink(outside, fixture.bundle.join("fictor.yaml")).unwrap();
                }
                _ => unreachable!(),
            }
            let before = snapshot(fixture.root.path());
            assert!(
                matches!(
                    resolve(
                        &fixture.home,
                        "example__read",
                        json!({"text":"fixture"}),
                        &Nat64Prefixes::default()
                    ),
                    Err(GatewayError::InvalidCatalog | GatewayError::Unavailable)
                ),
                "{defect}"
            );
            assert_eq!(snapshot(fixture.root.path()), before);
            assert!(!fixture.marker.exists());
        }
    }

    #[test]
    fn effective_network_authority_is_revalidated_under_the_pinned_nat64_configuration() {
        let fixture = Fixture::new(
            json!({"read":{"effect":"read"}}),
            vec![tool("read")],
            &["[2001:4860:64::a00:1]:443"],
        );
        let accepted = resolve(
            &fixture.home,
            "example__read",
            json!({"text":"fixture"}),
            &Nat64Prefixes::default(),
        )
        .unwrap();
        assert_eq!(accepted.class().effect, Effect::External);
        let configured = Nat64Prefixes::new(&["2001:4860:64::/96".into()]).unwrap();
        assert!(
            !accepted
                .nat64()
                .is_translation("2001:4860:64::a00:1".parse().unwrap())
        );
        assert!(configured.is_translation("2001:4860:64::a00:1".parse().unwrap()));
        assert!(matches!(
            resolve(
                &fixture.home,
                "example__read",
                json!({"text":"fixture"}),
                &configured
            ),
            Err(GatewayError::InvalidCatalog)
        ));
        assert!(!fixture.marker.exists());
    }
}
