use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use std::{ffi::OsString, path::PathBuf};

#[derive(Parser)]
#[command(version, about = "Runtime pessoal de agentes de IA")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Prepara configuração, diretórios e banco de dados.
    Init {
        /// Disponível quando o instalador do marco M0.5 estiver implementado.
        #[arg(long)]
        first_party: Option<PathBuf>,
    },
    /// Verifica configuração, sandbox, runtimes, keyring e portas.
    Doctor,
    /// Verifica bundles e controla extensões no lock.
    Ext {
        #[command(subcommand)]
        command: ExtCommand,
    },
    /// Gerencia segredos no backend configurado; valores só entram pelo TTY.
    Secrets {
        #[command(subcommand)]
        command: SecretCommand,
    },
    #[command(name = "__sandbox-init", hide = true)]
    SandboxInit {
        #[arg(long, hide = true)]
        mount_proof: String,
        #[arg(long, hide = true)]
        admission: bool,
        #[arg(last = true, required = true, allow_hyphen_values = true)]
        command: Vec<OsString>,
    },
}

#[derive(Subcommand)]
enum ExtCommand {
    /// Lista a configuração registrada, com ou sem core ativo.
    List,
    /// Valida, calcula hash e executa smoke isolado; não aprova nem promove.
    Check { path: PathBuf },
    /// Revisa e instala uma origem local pelo core ativo.
    Install {
        #[arg(required_unless_present = "resume", conflicts_with = "resume")]
        path: Option<PathBuf>,
        #[arg(long, conflicts_with = "resume")]
        yes: bool,
        #[arg(long, conflicts_with_all = ["path", "yes"])]
        resume: Option<String>,
    },
    /// Habilita uma extensão no lock com o core parado.
    Enable { id: String },
    /// Desabilita uma extensão no lock com o core parado.
    Disable { id: String },
    /// Limpa a recuperação selecionada, sem habilitar ou iniciar processos.
    ResetCrashes {
        id: String,
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        session: Option<String>,
    },
}

#[derive(Subcommand)]
enum SecretCommand {
    Set { name: String },
    List,
    Rm { name: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let redactor = fictor::secrets::Redactor::default();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(redactor.clone().make_writer(std::io::stderr))
        .init();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        // A misplaced credential in argv must not be echoed by clap's diagnostics.
        Err(error) if error.use_stderr() => bail!("argumentos inválidos; use fictor --help"),
        Err(error) => error.exit(),
    };
    if let Command::SandboxInit {
        command,
        mount_proof,
        admission,
    } = cli.command
    {
        let status = if admission {
            fictor::sandbox::init::run_with_admission(command, &mount_proof).await?
        } else {
            fictor::sandbox::init::run(command, &mount_proof).await?
        };
        std::process::exit(status);
    }
    let home = fictor::home::resolve().context("resolver FICTOR_HOME")?;
    match cli.command {
        Command::Init { first_party } => {
            if first_party.is_some() {
                bail!(
                    "instalação first-party depende do pipeline de sandbox e verificação (M0.5); use init sem --first-party para preparar o core"
                );
            }
            fictor::initialize(&home)
                .await
                .context("inicializar Fictor")?;
            println!("Core inicializado em {}", home.display());
        }
        Command::Doctor => {
            let report = fictor::doctor::inspect(&home);
            for check in &report {
                println!("[{}] {}: {}", check.status, check.name, check.detail);
            }
            if report
                .iter()
                .any(|c| c.status == fictor::doctor::Status::Fail)
            {
                bail!("doctor encontrou requisitos ausentes");
            }
        }
        Command::Ext {
            command: ExtCommand::List,
        } => {
            let snapshot = fictor::installer::listing::list(&home).await?;
            print!("{}", snapshot.human()?);
        }
        Command::Ext {
            command: ExtCommand::Check { path },
        } => {
            use std::sync::Arc;
            let owner = fictor::ownership::HomeLease::acquire(&home)?;
            let home = owner.home().to_path_buf();
            let config = Arc::new(fictor::config::Config::load(&home)?);
            let nat64 = fictor::proxy::nat64::Nat64Prefixes::new(&config.egress.nat64_prefixes)?;
            let store = Arc::new(fictor::store::Store::open_with_lease(owner).await?);
            let secrets = Arc::new(fictor::secrets::SecretStore::open_with_lease(
                store.owner().clone(),
                config.secrets.backend,
                redactor,
            )?);
            let proxy = fictor::proxy::EgressProxy::bind_unix_with_nat64(
                home.join("run/check-proxy.sock"),
                store.clone(),
                vec![],
                nat64.clone(),
            )
            .await?;
            let real_home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .context("HOME ausente")?;
            let provider_secrets = config
                .providers
                .values()
                .filter_map(|p| p.secret.clone())
                .collect();
            let dependency_resolver =
                Arc::new(fictor::installer::dependencies::DependencyResolver::new(
                    config.clone(),
                    real_home.clone(),
                    std::env::current_exe().context("resolver executável do core")?,
                ));
            let supervisor = Arc::new(fictor::supervisor::Supervisor::new(
                &home,
                real_home,
                config,
                secrets,
                store.clone(),
                Arc::new(proxy),
            )?);
            let checker = fictor::installer::local::LocalChecker::new(
                home.clone(),
                nat64,
                store,
                supervisor,
                provider_secrets,
            )
            .with_dependency_resolver(dependency_resolver);
            let result = checker.check_local(&path).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "proposal_id":result.proposal.id,"ext_id":result.proposal.ext_id,
                    "state":result.proposal.state,"bundle_hash":result.proposal.hash,
                    "tools_hash":result.catalog.hash(),"tools":result.catalog.tools().len(),
                    "ignored":result.ignored,"checks":result.proposal.checks,"activated":false
                }))?
            );
        }
        Command::Ext {
            command: ExtCommand::Enable { id },
        } => set_extension_enabled(&home, &id, true, redactor).await?,
        Command::Ext {
            command: ExtCommand::Install { path, yes, resume },
        } => {
            fictor::installer::cli::install(&home, path, yes, resume).await?;
        }
        Command::Ext {
            command: ExtCommand::Disable { id },
        } => set_extension_enabled(&home, &id, false, redactor).await?,
        Command::Ext {
            command: ExtCommand::ResetCrashes { id, key, session },
        } => {
            let mut params = serde_json::json!({"ext_id":id});
            if let Some(key) = key {
                params["key"] = key.into();
            }
            if let Some(session) = session {
                params["session_id"] = session.into();
            }
            let result = human_operation(&home, "ext.reset_crashes", &params, redactor).await?;
            let ack: ResetAck = serde_json::from_value(result.clone())
                .context("resposta não confirmada; não repita a mutação automaticamente")?;
            validate_key(&id, &ack.key)?;
            if ack.schema != 1
                || ack.ext_id != id
                || ack.session_id.as_deref()
                    != params.get("session_id").and_then(serde_json::Value::as_str)
                || params
                    .get("key")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|key| key != ack.key)
            {
                bail!("resposta não confirmada; não repita a mutação automaticamente");
            }
            if ack.cleared == 0 {
                println!("Nenhuma recuperação a limpar.");
            } else {
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
        }
        Command::Secrets { command } => {
            match command {
                SecretCommand::Set { name } => {
                    if name.is_empty()
                        || !name.bytes().all(|byte| {
                            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                        })
                    {
                        return Err(fictor::secrets::SecretError::InvalidName.into());
                    }
                    // Never accept a credential in argv, environment or redirected stdin.
                    let value = rpassword::prompt_password_with_config(
                        "Segredo: ",
                        rpassword::ConfigBuilder::new()
                            .input_file_path("/dev/tty")
                            .output_file_path("/dev/tty")
                            .password_feedback_hide()
                            .build(),
                    )
                    .context("ler segredo no TTY sem eco")?;
                    let result = human_operation(
                        &home,
                        "secrets.set",
                        &serde_json::json!({"name":name,"value":value}),
                        redactor,
                    )
                    .await?;
                    let ack: SecretAck = serde_json::from_value(result)
                        .context("resposta não confirmada; não repita a mutação automaticamente")?;
                    if ack.schema != 1 || ack.name != name {
                        bail!("resposta não confirmada; não repita a mutação automaticamente");
                    }
                    println!("Segredo salvo no backend configurado.");
                }
                SecretCommand::List => {
                    let result =
                        human_operation(&home, "secrets.list", &serde_json::json!({}), redactor)
                            .await?;
                    let ack: SecretNames = serde_json::from_value(result)
                        .context("resposta administrativa inválida")?;
                    if ack.schema != 1
                        || ack.names.windows(2).any(|pair| pair[0] >= pair[1])
                        || ack.names.iter().any(|name| !valid_secret_name(name))
                    {
                        bail!("resposta administrativa inválida");
                    }
                    for name in ack.names {
                        println!("{name}");
                    }
                }
                SecretCommand::Rm { name } => {
                    let result = human_operation(
                        &home,
                        "secrets.rm",
                        &serde_json::json!({"name":name}),
                        redactor,
                    )
                    .await?;
                    let ack: SecretRemoved = serde_json::from_value(result)
                        .context("resposta não confirmada; não repita a mutação automaticamente")?;
                    if ack.schema != 1 || ack.name != name {
                        bail!("resposta não confirmada; não repita a mutação automaticamente");
                    }
                    println!(
                        "{}",
                        if ack.removed {
                            "Segredo removido do backend configurado."
                        } else {
                            "Segredo já ausente."
                        }
                    );
                }
            }
        }
        Command::SandboxInit { .. } => bail!("sandbox init já tratado"),
    }
    Ok(())
}

async fn set_extension_enabled(
    home: &std::path::Path,
    id: &str,
    enabled: bool,
    redactor: fictor::secrets::Redactor,
) -> anyhow::Result<()> {
    let result = human_operation(
        home,
        "ext.set_enabled",
        &serde_json::json!({"ext_id":id,"enabled":enabled}),
        redactor,
    )
    .await?;
    let ack: EnabledAck = serde_json::from_value(result.clone())
        .context("resposta não confirmada; não repita a mutação automaticamente")?;
    validate_key(id, &ack.key)?;
    if ack.schema != 1 || ack.ext_id != id || ack.enabled != enabled {
        bail!("resposta não confirmada; não repita a mutação automaticamente");
    }
    println!(
        "{}",
        serde_json::to_string_pretty(
            &serde_json::json!({"schema":ack.schema,"ext_id":ack.ext_id,"key":ack.key,"enabled":ack.enabled,"changed":ack.changed})
        )?
    );
    Ok(())
}

async fn human_operation(
    home: &std::path::Path,
    method: &str,
    params: &serde_json::Value,
    redactor: fictor::secrets::Redactor,
) -> anyhow::Result<serde_json::Value> {
    use fictor::ownership::{HomeLease, OwnershipError};
    match HomeLease::acquire(home) {
        Ok(owner) => Ok(fictor::installer::controls::OfflineContext::open(owner, redactor).await?.call(method, params).await?),
        Err(OwnershipError::Busy) => fictor::admin::request_method(home, method, params).await.context("FICTOR_HOME ocupado; operação administrativa não confirmada, sem fallback offline ou repetição automática"),
        Err(error) => Err(error.into()),
    }
}

fn valid_secret_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
fn validate_key(id: &str, key: &str) -> anyhow::Result<()> {
    let (version, _) = key
        .rsplit_once('-')
        .context("resposta administrativa inválida")?;
    fictor::installer::listing::Snapshot {
        schema: 1,
        extensions: vec![fictor::installer::listing::Extension {
            id: id.into(),
            active: key.into(),
            version: version.into(),
            enabled: false,
        }],
    }
    .human()
    .context("resposta administrativa inválida")?;
    Ok(())
}
fn nullable<'de, D: serde::Deserializer<'de>, T: serde::Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    serde::Deserialize::deserialize(deserializer)
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EnabledAck {
    schema: u32,
    ext_id: String,
    key: String,
    enabled: bool,
    changed: bool,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ResetAck {
    schema: u32,
    ext_id: String,
    key: String,
    #[serde(deserialize_with = "nullable")]
    session_id: Option<String>,
    cleared: u64,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretAck {
    schema: u32,
    name: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretRemoved {
    schema: u32,
    name: String,
    removed: bool,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretNames {
    schema: u32,
    names: Vec<String>,
}
