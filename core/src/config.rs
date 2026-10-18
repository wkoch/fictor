use serde::{Deserialize, Serialize};
use std::os::unix::fs::OpenOptionsExt;
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
};

pub const DEFAULT_CONFIG: &str = include_str!("../config.example.toml");

// Extension configuration stays opaque; provider bodies and model formats never enter the core.
#[derive(Deserialize, Serialize)]
pub struct Config {
    pub server: Server,
    pub paths: Paths,
    pub runtimes: BTreeMap<String, RuntimeSource>,
    #[serde(default)]
    pub providers: BTreeMap<String, Provider>,
    pub policy: Policy,
    #[serde(default)]
    pub secrets: Secrets,
    #[serde(default)]
    pub egress: Egress,
    pub budget: Budget,
    pub harness: Harness,
    pub sandbox: Sandbox,
    pub installer: Installer,
    #[serde(default)]
    pub ext: BTreeMap<String, toml::Value>,
}

#[derive(Deserialize, Serialize)]
pub struct Server {
    pub listen: SocketAddr,
    pub surface_port: u16,
}
#[derive(Deserialize, Serialize)]
pub struct Paths {
    pub default_workspace: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "source", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RuntimeSource {
    Nodejs {
        channel: String,
    },
    GithubRelease {
        repo: String,
        asset: String,
        checksum: String,
        bin: String,
    },
}
#[derive(Clone, Deserialize, Serialize)]
pub struct Provider {
    pub base_url: String,
    pub auth_header: Option<String>,
    pub auth_prefix: Option<String>,
    pub secret: Option<String>,
    #[serde(default)]
    pub extra_headers: BTreeMap<String, String>,
}
#[derive(Deserialize, Serialize)]
pub struct Policy {
    pub default_mode: Mode,
    pub trusted_domains: Vec<String>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}
#[derive(Deserialize, Serialize)]
pub struct Rule {
    pub tool: String,
    pub decision: Decision,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Plan,
    Default,
    Auto,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Deny,
    Ask,
    Allow,
}
#[derive(Default, Deserialize, Serialize)]
pub struct Secrets {
    #[serde(default)]
    pub backend: crate::secrets::BackendKind,
}
#[derive(Default, Deserialize, Serialize)]
pub struct Egress {
    #[serde(default)]
    pub nat64_prefixes: Vec<String>,
}
#[derive(Clone, Deserialize, Serialize)]
pub struct Budget {
    pub max_model_requests_per_day: u64,
    pub max_model_requests_per_session: u64,
}
#[derive(Deserialize, Serialize)]
pub struct Harness {
    pub default: String,
    pub idle_timeout_min: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Sandbox {
    pub home_ro_files: Vec<String>,
}
#[derive(Deserialize, Serialize)]
pub struct Installer {
    pub registries: Vec<String>,
    pub trusted_packages: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("não foi possível acessar a configuração: {0}")]
    Io(#[from] std::io::Error),
    // Parser errors may contain the original line, including credentials.
    #[error("config.toml inválido; confira os tipos e campos obrigatórios")]
    Parse,
    #[error("configuração inválida: {0}")]
    Invalid(&'static str),
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text).map_err(|_| ConfigError::Parse)?;
        if config
            .runtimes
            .values()
            .any(|source| matches!(source, RuntimeSource::Nodejs { channel } if channel != "lts"))
        {
            return Err(ConfigError::Invalid("o canal Node deve ser lts"));
        }
        if config.server.listen.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
            return Err(ConfigError::Invalid("server.listen deve usar 127.0.0.1"));
        }
        if config.server.listen.port() == 0 || config.server.surface_port == 0 {
            return Err(ConfigError::Invalid(
                "as portas devem ser diferentes de zero",
            ));
        }
        if config.server.listen.port() == config.server.surface_port {
            return Err(ConfigError::Invalid(
                "shell e surfaces precisam de portas distintas",
            ));
        }
        crate::proxy::nat64::Nat64Prefixes::new(&config.egress.nat64_prefixes)
            .map_err(|_| ConfigError::Invalid("egress.nat64_prefixes exige prefixos IPv6 canônicos /32, /40, /48, /56, /64 ou /96"))?;
        for provider in config.providers.values() {
            crate::proxy::models::validate_provider(provider).map_err(|_| {
                ConfigError::Invalid(
                    "provider inválido; HTTPS obrigatório, HTTP só para 127.0.0.1 ou [::1]",
                )
            })?;
        }
        Ok(config)
    }

    pub fn load(home: &Path) -> Result<Self, ConfigError> {
        Self::parse(&fs::read_to_string(home.join("config.toml"))?)
    }

    /// The kernel supplies the authenticated extension id, never a caller-selected
    /// table name. Only this opaque section is reloaded; core settings await restart.
    pub fn extension(home: &Path, ext_id: &str) -> Result<toml::Table, ConfigError> {
        #[derive(Deserialize)]
        struct Reload {
            #[serde(default)]
            ext: BTreeMap<String, toml::Table>,
        }
        let mut config: Reload = toml::from_str(&fs::read_to_string(home.join("config.toml"))?)
            .map_err(|_| ConfigError::Parse)?;
        Ok(config.ext.remove(ext_id).unwrap_or_default())
    }

    pub fn create_if_missing(home: &Path) -> Result<Self, ConfigError> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        options.mode(0o600);
        match options.open(home.join("config.toml")) {
            Ok(mut file) => {
                file.write_all(DEFAULT_CONFIG.as_bytes())?;
                file.sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        Self::load(home)
    }
}

#[cfg(test)]
mod nat64_tests {
    use super::*;
    #[test]
    fn nat64_defaults_are_backward_compatible_and_bad_prefixes_block_startup() {
        let old=DEFAULT_CONFIG.replace("[egress]\nnat64_prefixes = []              # prefixos NAT64 específicos da rede, ex.: \"2001:db8:64::/96\"\n\n", "");
        assert!(!old.contains("[egress]"));
        assert!(
            Config::parse(&old)
                .unwrap()
                .egress
                .nat64_prefixes
                .is_empty()
        );
        let good = DEFAULT_CONFIG.replace(
            "nat64_prefixes = []",
            "nat64_prefixes = [\"2001:db8:64::/96\", \"2001:db8::/32\"]",
        );
        assert_eq!(Config::parse(&good).unwrap().egress.nat64_prefixes.len(), 2);
        for value in ["2001:db8::1/96", "2001:db8::/72", "invalid", "127.0.0.1/32"] {
            let text = DEFAULT_CONFIG.replace(
                "nat64_prefixes = []",
                &format!("nat64_prefixes = [{value:?}]"),
            );
            assert!(Config::parse(&text).is_err(), "{value}");
        }
    }
}
