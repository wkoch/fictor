//! ADR-037: one validated snapshot of human restrictions and tool classification.
use super::manifest::{Effect, Manifest, ToolClass};
use crate::{
    gateway::PinnedCatalog,
    proxy::{allowlist::Allowlist, nat64::Nat64Prefixes},
};
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::OnceLock,
};

const SCHEMA: &str = include_str!("../../../spec/schemas/overrides.schema.json");

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OverridesError {
    #[error("invalid human overrides")]
    Invalid,
    #[error("overrides require human approval")]
    NotHuman,
    #[error("overrides expand declared permissions")]
    Expansion,
    #[error("effective manifest is invalid")]
    Manifest,
    #[error("override schema unavailable")]
    Schema,
}

/// Preserve the approved object exactly, including absent sections and leaves.
/// Its private representation prevents unchecked mutation after validation.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Overrides(Value);

impl Default for Overrides {
    fn default() -> Self {
        Self(serde_json::json!({"permissions":{},"tools":{}}))
    }
}
impl fmt::Debug for Overrides {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Overrides")
            .field("adjusted", &!self.is_noop())
            .finish_non_exhaustive()
    }
}
impl<'de> Deserialize<'de> for Overrides {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = StrictValue::deserialize(deserializer)?.0;
        Self::from_value(value).map_err(de::Error::custom)
    }
}
impl Overrides {
    pub fn parse(text: &str) -> Result<Self, OverridesError> {
        serde_json::from_str(text).map_err(|_| OverridesError::Invalid)
    }

    pub fn from_value(value: Value) -> Result<Self, OverridesError> {
        static VALIDATOR: OnceLock<Result<jsonschema::Validator, OverridesError>> = OnceLock::new();
        let validator = VALIDATOR
            .get_or_init(|| {
                let schema: Value =
                    serde_json::from_str(SCHEMA).map_err(|_| OverridesError::Schema)?;
                jsonschema::options()
                    .offline()
                    .build(&schema)
                    .map_err(|_| OverridesError::Schema)
            })
            .as_ref()
            .map_err(|error| *error)?;
        if !validator.is_valid(&value)
            || object(&value, "tools").is_some_and(|tools| {
                tools.values().any(|patch| {
                    patch
                        .get("timeout_ms")
                        .is_some_and(|timeout| timeout.as_u64().is_none())
                })
            })
        {
            return Err(OverridesError::Invalid);
        }
        Ok(Self(value))
    }

    pub fn as_value(&self) -> &Value {
        &self.0
    }

    pub fn is_noop(&self) -> bool {
        let permissions = object(&self.0, "permissions").is_none_or(|patch| {
            patch.iter().all(|(key, value)| match key.as_str() {
                "fs" | "net" => value.as_object().is_some_and(Map::is_empty),
                // env:{} is an explicit removal, unlike a structural fs:{}.
                _ => false,
            })
        });
        let tools = object(&self.0, "tools").is_none_or(|patch| {
            patch
                .values()
                .all(|value| value.as_object().is_some_and(Map::is_empty))
        });
        permissions && tools
    }

    pub fn validate_catalog(
        &self,
        catalog: &PinnedCatalog,
        approved_by: &str,
    ) -> Result<(), OverridesError> {
        if !self.is_noop() && approved_by != "user" {
            return Err(OverridesError::NotHuman);
        }
        let names: BTreeSet<_> = catalog
            .tools()
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        if object(&self.0, "tools").is_some_and(|patch| {
            patch
                .keys()
                .any(|name| name != "default" && !names.contains(name.as_str()))
        }) {
            return Err(OverridesError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct EffectiveManifest {
    manifest: Manifest,
    catalog: PinnedCatalog,
    classes: BTreeMap<String, ToolClass>,
}
impl EffectiveManifest {
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn catalog(&self) -> &PinnedCatalog {
        &self.catalog
    }
    pub fn tool_class(&self, name: &str) -> Option<&ToolClass> {
        self.classes.get(name)
    }
}

pub fn resolve(
    original: &Manifest,
    catalog: &PinnedCatalog,
    patch: &Overrides,
    approved_by: &str,
    nat64: &Nat64Prefixes,
) -> Result<EffectiveManifest, OverridesError> {
    original
        .validate_with_nat64(nat64)
        .map_err(|_| OverridesError::Manifest)?;
    patch.validate_catalog(catalog, approved_by)?;
    let mut manifest = original.clone();
    if let Some(permissions) = object(&patch.0, "permissions") {
        if let Some(fs) = permissions.get("fs").and_then(Value::as_object) {
            replace(&mut manifest.permissions.fs.read, fs, "read")?;
            replace(&mut manifest.permissions.fs.write, fs, "write")?;
        }
        if let Some(net) = permissions.get("net").and_then(Value::as_object) {
            replace(&mut manifest.permissions.net.allow, net, "allow")?;
        }
        replace(&mut manifest.permissions.models, permissions, "models")?;
        replace(&mut manifest.permissions.spawn, permissions, "spawn")?;
        replace(&mut manifest.permissions.secrets, permissions, "secrets")?;
        replace(&mut manifest.permissions.env, permissions, "env")?;
    }
    let base = &original.permissions;
    let effective = &mut manifest.permissions;
    let readable: BTreeSet<_> = base.fs.read.iter().chain(&base.fs.write).collect();
    let secrets: BTreeSet<_> = base
        .secrets
        .iter()
        .map(|binding| (&binding.name, &binding.env))
        .collect();
    let base_net = Allowlist::new_with_nat64(&base.net.allow, nat64)
        .map_err(|_| OverridesError::Manifest)?
        .normalized_patterns();
    effective.net.allow = Allowlist::new_with_nat64(&effective.net.allow, nat64)
        .map_err(|_| OverridesError::Manifest)?
        .normalized_patterns();
    if !subset(&effective.fs.write, &base.fs.write)
        || effective
            .fs
            .read
            .iter()
            .any(|path| !readable.contains(path))
        || !subset(&effective.net.allow, &base_net)
        || !subset(&effective.models, &base.models)
        || (effective.spawn && !base.spawn)
        || effective
            .env
            .iter()
            .any(|(key, value)| base.env.get(key) != Some(value))
        || effective
            .secrets
            .iter()
            .any(|secret| !secrets.contains(&(&secret.name, &secret.env)))
    {
        return Err(OverridesError::Expansion);
    }
    manifest
        .validate_with_nat64(nat64)
        .map_err(|_| OverridesError::Manifest)?;
    let tools = object(&patch.0, "tools");
    let mut classes = BTreeMap::new();
    for tool in catalog.tools() {
        let name = tool["name"].as_str().ok_or(OverridesError::Invalid)?;
        let mut class = (name != "default")
            .then(|| original.tools.get(name))
            .flatten()
            .or_else(|| original.tools.get("default"))
            .cloned()
            .unwrap_or_default();
        if let Some(common) = tools.and_then(|tools| object_map(tools, "default")) {
            apply_class(&mut class, common)?;
        }
        if name != "default"
            && let Some(nominal) = tools.and_then(|tools| object_map(tools, name))
        {
            apply_class(&mut class, nominal)?;
        }
        // Static floors remain in force after human classification. Session
        // provenance and Rule of Two consume this base at their policy boundary.
        if !manifest.permissions.net.allow.is_empty() || !manifest.permissions.models.is_empty() {
            class.effect = Effect::External;
        }
        if name.starts_with("hook_") {
            class.model_visible = false;
        }
        classes.insert(name.to_owned(), class);
    }
    Ok(EffectiveManifest {
        manifest,
        catalog: catalog.clone(),
        classes,
    })
}

fn subset(values: &[String], original: &[String]) -> bool {
    let original: BTreeSet<_> = original.iter().collect();
    values.iter().all(|value| original.contains(value))
}
fn object<'a>(value: &'a Value, name: &str) -> Option<&'a Map<String, Value>> {
    value.get(name).and_then(Value::as_object)
}
fn object_map<'a>(value: &'a Map<String, Value>, name: &str) -> Option<&'a Map<String, Value>> {
    value.get(name).and_then(Value::as_object)
}
fn replace<T: de::DeserializeOwned>(
    target: &mut T,
    patch: &Map<String, Value>,
    name: &str,
) -> Result<(), OverridesError> {
    if let Some(value) = patch.get(name) {
        *target = serde_json::from_value(value.clone()).map_err(|_| OverridesError::Invalid)?;
    }
    Ok(())
}
fn apply_class(class: &mut ToolClass, patch: &Map<String, Value>) -> Result<(), OverridesError> {
    replace(&mut class.effect, patch, "effect")?;
    replace(&mut class.sensitivity, patch, "sensitivity")?;
    replace(&mut class.output_trust, patch, "output_trust")?;
    replace(&mut class.model_visible, patch, "model_visible")?;
    replace(&mut class.ui_callable, patch, "ui_callable")?;
    replace(&mut class.timeout_ms, patch, "timeout_ms")
}

// JSON Value's ordinary map deserializer overwrites duplicate keys. Overrides
// must reject them at every level, including env and nominal tool patches.
struct StrictValue(Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Strict;
        impl<'de> de::Visitor<'de> for Strict {
            type Value = StrictValue;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON without duplicate keys")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|value| StrictValue(Value::Number(value)))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                self.visit_unit()
            }
            fn visit_seq<A: de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(StrictValue(value)) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(StrictValue(Value::Array(values)))
            }
            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate override key"));
                    }
                    let StrictValue(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(Strict)
    }
}
