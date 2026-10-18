//! Manifest structure is governed by the embedded normative schema. Validation
//! performs no filesystem, network, runtime, or credential access.
use crate::proxy::{allowlist::Allowlist, nat64::Nat64Prefixes};
use serde::{
    Deserialize, Serialize,
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::OnceLock,
};

const SCHEMA: &str = include_str!("../../../spec/schemas/extension.schema.json");
// The local-receipt per-file ceiling is already fixed by ADR-024. Valid manifest
// structure is shallow; bound invalid YAML before allocating a recursive Value.
const MAX_MANIFEST_BYTES: usize = 50 * 1024 * 1024;
const MAX_PARSE_DEPTH: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest YAML inválido, duplicado ou com tags não suportadas")]
    Parse,
    #[error("manifest não corresponde ao schema normativo")]
    Schema,
    #[error("manifest excede os limites do parser")]
    Limit,
    #[error("manifest inválido: {0}")]
    Semantic(&'static str),
    #[error("runtime ou isolamento pertence a uma fase posterior")]
    UnsupportedPhase,
    #[error("schema interno do manifest indisponível")]
    InternalSchema,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: u32,
    pub id: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub description: String,
    #[serde(default)]
    pub role: Role,
    #[serde(default)]
    pub scope: Scope,
    pub runtime: Runtime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kernel: Vec<KernelScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hooks_api: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hooks: Option<Vec<Hook>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tools: BTreeMap<String, ToolClass>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub surfaces: Vec<Surface>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skills: Option<String>,
    #[serde(default)]
    pub commands: Vec<Command>,
    #[serde(default, skip_serializing_if = "Permissions::is_empty")]
    pub permissions: Permissions,
    #[serde(default)]
    pub isolation: Isolation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tests: Option<TestCommand>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evals: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    #[default]
    Extension,
    Harness,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    #[default]
    Global,
    Session,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Isolation {
    #[default]
    Os,
    Container,
    Vm,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeKind {
    Deno,
    Node,
    Python,
    Binary,
    Remote,
    None,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Runtime {
    pub kind: RuntimeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KernelScope {
    #[serde(rename = "events.read")]
    EventsRead,
    #[serde(rename = "events.write")]
    EventsWrite,
    #[serde(rename = "sessions")]
    Sessions,
    #[serde(rename = "sessions.input")]
    SessionsInput,
    #[serde(rename = "blobs")]
    Blobs,
    #[serde(rename = "kv")]
    Kv,
    #[serde(rename = "tools")]
    Tools,
    #[serde(rename = "hooks")]
    Hooks,
    #[serde(rename = "catalog")]
    Catalog,
    #[serde(rename = "ui")]
    Ui,
    #[serde(rename = "timers")]
    Timers,
    #[serde(rename = "ext.propose")]
    ExtPropose,
    #[serde(rename = "config")]
    Config,
    #[serde(rename = "approval")]
    Approval,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hook {
    pub point: String,
    #[serde(default = "hook_priority")]
    pub priority: u16,
    #[serde(default = "hook_timeout")]
    pub timeout_ms: u64,
}
fn hook_priority() -> u16 {
    100
}
fn hook_timeout() -> u64 {
    2000
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Read,
    WriteLocal,
    #[default]
    External,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Public,
    #[default]
    Private,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputTrust {
    Trusted,
    #[default]
    Untrusted,
    Workspace,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ToolClass {
    pub effect: Effect,
    pub sensitivity: Sensitivity,
    pub output_trust: OutputTrust,
    pub model_visible: bool,
    pub ui_callable: bool,
    pub timeout_ms: u64,
}
impl Default for ToolClass {
    fn default() -> Self {
        Self {
            effect: Effect::External,
            sensitivity: Sensitivity::Private,
            output_trust: OutputTrust::Untrusted,
            model_visible: true,
            ui_callable: false,
            timeout_ms: 120_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceSlot {
    Left,
    Right,
    Bottom,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Surface {
    pub id: String,
    pub slot: SurfaceSlot,
    pub resource: String,
    pub title: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub name: String,
    pub description: String,
    pub prompt: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestCommand {
    pub command: Vec<String>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Permissions {
    pub fs: FilesystemPermissions,
    pub net: NetworkPermissions,
    pub models: Vec<String>,
    pub spawn: bool,
    pub toolchains: bool,
    pub secrets: Vec<SecretBinding>,
    pub env: BTreeMap<String, String>,
}
impl Permissions {
    fn is_empty(&self) -> bool {
        self.fs.read.is_empty()
            && self.fs.write.is_empty()
            && self.net.allow.is_empty()
            && self.models.is_empty()
            && !self.spawn
            && !self.toolchains
            && self.secrets.is_empty()
            && self.env.is_empty()
    }
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilesystemPermissions {
    pub read: Vec<String>,
    pub write: Vec<String>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkPermissions {
    pub allow: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretBinding {
    pub name: String,
    pub env: String,
}

impl Manifest {
    pub fn parse(text: &str) -> Result<Self, ManifestError> {
        Self::parse_with_nat64(text, &Nat64Prefixes::default())
    }

    pub fn parse_with_nat64(text: &str, nat64: &Nat64Prefixes) -> Result<Self, ManifestError> {
        if text.len() > MAX_MANIFEST_BYTES {
            return Err(ManifestError::Limit);
        }
        let budget = ParseBudget {
            nodes: Cell::new(text.len().saturating_mul(2).max(1)),
            bytes: Cell::new(MAX_MANIFEST_BYTES),
        };
        let mut documents = serde_yaml_ng::Deserializer::from_str(text);
        let document = documents.next().ok_or(ManifestError::Parse)?;
        let value = JsonSeed {
            budget: &budget,
            depth: 0,
        }
        .deserialize(document)
        .map_err(|_| ManifestError::Parse)?;
        if documents.next().is_some() {
            return Err(ManifestError::Parse);
        }
        validate_schema(&value)?;
        let mut manifest: Self =
            serde_json::from_value(value).map_err(|_| ManifestError::Schema)?;
        let allowlist = Allowlist::new_with_nat64(&manifest.permissions.net.allow, nat64)
            .map_err(|_| ManifestError::Semantic("net.allow inválido"))?;
        manifest.permissions.net.allow = allowlist.normalized_patterns();
        manifest.validate_with_nat64(nat64)?;
        Ok(manifest)
    }

    /// Revalidate even manifests reconstructed from persistent or trusted typed data.
    pub fn validate(&self) -> Result<(), ManifestError> {
        self.validate_with_nat64(&Nat64Prefixes::default())
    }

    pub fn validate_with_nat64(&self, nat64: &Nat64Prefixes) -> Result<(), ManifestError> {
        // Raw input is checked before deserialization. Omit typed empty defaults
        // on revalidation: their original absence must not create forbidden fields.
        validate_schema(&serde_json::to_value(self).map_err(|_| ManifestError::Schema)?)?;
        if self.runtime.kind == RuntimeKind::None
            && (self.mcp_enabled()
                || self.role == Role::Harness
                || !self.kernel.is_empty()
                || self.hooks.is_some()
                || !self.surfaces.is_empty()
                || !self.tools.is_empty()
                || !self.permissions.is_empty())
        {
            return Err(ManifestError::Semantic(
                "bundle sem processo não aceita serviços",
            ));
        }
        if self.role == Role::Harness
            && (self.scope != Scope::Session
                || self.mcp != Some(false)
                || self.hooks.is_some()
                || !self.surfaces.is_empty()
                || !self.tools.is_empty())
        {
            return Err(ManifestError::Semantic(
                "harness exige sessão, kernel e ausência de MCP",
            ));
        }
        if !matches!(self.runtime.kind, RuntimeKind::None | RuntimeKind::Remote)
            && !self.mcp_enabled()
            && (self.kernel.is_empty()
                || self.hooks.is_some()
                || !self.surfaces.is_empty()
                || !self.tools.is_empty())
        {
            return Err(ManifestError::Semantic("processo sem MCP exige kernel"));
        }
        if self.runtime.kind == RuntimeKind::Remote
            || self.isolation != Isolation::Os
            || self.permissions.toolchains
        {
            return Err(ManifestError::UnsupportedPhase);
        }
        if self.kernel.iter().any(|scope| {
            matches!(
                scope,
                KernelScope::Tools | KernelScope::Hooks | KernelScope::Sessions
            )
        }) && self.scope != Scope::Session
            && self.role != Role::Harness
        {
            return Err(ManifestError::Semantic("escopo de kernel exige sessão"));
        }
        let mediated = self.role == Role::Harness || self.kernel.contains(&KernelScope::Tools);
        if mediated
            && (!self.permissions.net.allow.is_empty() || !self.permissions.secrets.is_empty())
        {
            return Err(ManifestError::Semantic(
                "I11 exige rede e segredos mediados pelo core",
            ));
        }
        for path in self
            .permissions
            .fs
            .read
            .iter()
            .chain(&self.permissions.fs.write)
        {
            validate_permission_path(path, self.scope, self.role, mediated)?;
        }
        for path in &self.permissions.fs.write {
            if path == "${ext_root}"
                || path.starts_with("${ext_root}/")
                || path == "${store}"
                || path.starts_with("${store}/")
            {
                return Err(ManifestError::Semantic(
                    "bundle e store são somente leitura",
                ));
            }
        }
        for path in self
            .runtime
            .entry
            .iter()
            .chain(&self.skills)
            .chain(&self.evals)
            .chain(self.commands.iter().map(|command| &command.prompt))
        {
            validate_relative_path(path)?;
        }
        Allowlist::new_with_nat64(&self.permissions.net.allow, nat64)
            .map_err(|_| ManifestError::Semantic("net.allow inválido"))?;
        if !self.permissions.secrets.is_empty()
            && (self.permissions.net.allow.is_empty()
                || self
                    .permissions
                    .net
                    .allow
                    .iter()
                    .any(|pattern| pattern.contains('*')))
        {
            return Err(ManifestError::Semantic(
                "segredos exigem destinos de rede explícitos sem curingas",
            ));
        }
        let mut environment = BTreeSet::new();
        for name in self
            .permissions
            .env
            .keys()
            .chain(self.permissions.secrets.iter().map(|binding| &binding.env))
        {
            if !valid_environment_name(name) || !environment.insert(name) {
                return Err(ManifestError::Semantic(
                    "variável reservada, inválida ou repetida",
                ));
            }
        }
        if self
            .permissions
            .env
            .values()
            .any(|value| value.contains('\0'))
            || self.runtime.args.iter().any(|value| value.contains('\0'))
        {
            return Err(ManifestError::Semantic("ambiente ou argumento contém NUL"));
        }
        let mut names = BTreeSet::new();
        if self
            .commands
            .iter()
            .any(|command| !names.insert(&command.name))
        {
            return Err(ManifestError::Semantic("nomes de comandos repetidos"));
        }
        let mut names = BTreeSet::new();
        if self
            .surfaces
            .iter()
            .any(|surface| !names.insert(&surface.id))
        {
            return Err(ManifestError::Semantic("ids de surfaces repetidos"));
        }
        Ok(())
    }

    pub fn mcp_enabled(&self) -> bool {
        self.mcp.unwrap_or(self.runtime.kind != RuntimeKind::None)
    }

    /// Provider credentials are never eligible for extension environment injection (I4).
    pub fn validate_provider_secrets(&self, names: &BTreeSet<String>) -> Result<(), ManifestError> {
        if self
            .permissions
            .secrets
            .iter()
            .any(|binding| names.contains(&binding.name))
        {
            return Err(ManifestError::Semantic(
                "segredo de provider não pode ser injetado em extensão",
            ));
        }
        Ok(())
    }
}

fn validate_schema(value: &Value) -> Result<(), ManifestError> {
    static VALIDATOR: OnceLock<Result<jsonschema::Validator, ManifestError>> = OnceLock::new();
    let validator = VALIDATOR
        .get_or_init(|| {
            let schema: Value =
                serde_json::from_str(SCHEMA).map_err(|_| ManifestError::InternalSchema)?;
            // Explicit deny-all retriever: .offline() blocks both HTTP and file retrieval,
            // independent of Cargo's additionally disabled default resolver features.
            jsonschema::options()
                .offline()
                .build(&schema)
                .map_err(|_| ManifestError::InternalSchema)
        })
        .as_ref()
        .map_err(|error| *error)?;
    if !validator.is_valid(value) {
        return Err(ManifestError::Schema);
    }
    Ok(())
}

fn clean_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && !path.split('/').any(|part| part == "..")
}
fn validate_relative_path(path: &str) -> Result<(), ManifestError> {
    if !clean_path(path) || path.starts_with('/') || path.starts_with('~') || path.contains("${") {
        return Err(ManifestError::Semantic("caminho do bundle inválido"));
    }
    Ok(())
}
fn validate_permission_path(
    path: &str,
    scope: Scope,
    role: Role,
    mediated: bool,
) -> Result<(), ManifestError> {
    if !clean_path(path) {
        return Err(ManifestError::Semantic("caminho de permissão inválido"));
    }
    if let Some(rest) = path.strip_prefix("${") {
        let (template, suffix) = rest
            .split_once('}')
            .ok_or(ManifestError::Semantic("template de caminho inválido"))?;
        if (!suffix.is_empty() && !suffix.starts_with('/')) || suffix.contains("${") {
            return Err(ManifestError::Semantic("template de caminho inválido"));
        }
        match template {
            "workspace" if scope == Scope::Session && !mediated => {}
            "store" if role == Role::Harness => {}
            "ext_root" | "ext_data" | "tmp" => {}
            _ => {
                return Err(ManifestError::Semantic(
                    "template indisponível para o escopo",
                ));
            }
        }
    } else if mediated || !(path.starts_with('/') || path.starts_with("~/")) || path.contains("${")
    {
        return Err(ManifestError::Semantic(
            "I11 ou formato do caminho de permissão inválido",
        ));
    }
    Ok(())
}

/// Shared second barrier for supervisor environment construction (ADR-019).
pub fn valid_environment_name(name: &str) -> bool {
    const PREFIXES: &[&str] = &["FICTOR_", "LC_", "LD_", "DYLD_", "DENO_", "BASH_FUNC_"];
    const RESERVED: &[&str] = &[
        "PATH",
        "HOME",
        "TMPDIR",
        "TMP",
        "TEMP",
        "LANG",
        "LANGUAGE",
        "USER",
        "LOGNAME",
        "SHELL",
        "PWD",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "NODE_USE_ENV_PROXY",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "NODE_EXTRA_CA_CERTS",
        "NODE_TLS_REJECT_UNAUTHORIZED",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "GIT_SSL_NO_VERIFY",
        "NODE_OPTIONS",
        "NODE_PATH",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
        "BASH_ENV",
        "ENV",
        "PROMPT_COMMAND",
        "PERL5OPT",
        "RUBYOPT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "SSH_AUTH_SOCK",
        "GPG_AGENT_INFO",
        "GNUPGHOME",
        "DOCKER_HOST",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "DISPLAY",
        "WAYLAND_DISPLAY",
    ];
    name.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        && !PREFIXES.iter().any(|prefix| name.starts_with(prefix))
        && !RESERVED.contains(&name)
}

struct ParseBudget {
    nodes: Cell<usize>,
    bytes: Cell<usize>,
}
#[derive(Clone, Copy)]
struct JsonSeed<'a> {
    budget: &'a ParseBudget,
    depth: usize,
}
impl JsonSeed<'_> {
    fn child(self) -> Self {
        Self {
            depth: self.depth + 1,
            ..self
        }
    }
    fn string<E: de::Error>(self, value: &str) -> Result<Value, E> {
        let remaining = self
            .budget
            .bytes
            .get()
            .checked_sub(value.len())
            .ok_or_else(|| E::custom("manifest limit"))?;
        self.budget.bytes.set(remaining);
        Ok(Value::String(value.into()))
    }
}
impl<'de> DeserializeSeed<'de> for JsonSeed<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        if self.depth > MAX_PARSE_DEPTH {
            return Err(de::Error::custom("manifest depth"));
        }
        let remaining = self
            .budget
            .nodes
            .get()
            .checked_sub(1)
            .ok_or_else(|| de::Error::custom("manifest nodes"))?;
        self.budget.nodes.set(remaining);
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for JsonSeed<'_> {
    type Value = Value;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON-compatible YAML")
    }
    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        self.string(value)
    }
    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
        self.string(&value)
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(self.child())? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut mapping: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = mapping.next_key_seed(self.child())? {
            let Value::String(key) = key else {
                return Err(de::Error::custom("non-string key"));
            };
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate key"));
            }
            values.insert(key, mapping.next_value_seed(self.child())?);
        }
        Ok(Value::Object(values))
    }
    fn visit_enum<A: de::EnumAccess<'de>>(self, _: A) -> Result<Value, A::Error> {
        Err(de::Error::custom("tagged value"))
    }
}
