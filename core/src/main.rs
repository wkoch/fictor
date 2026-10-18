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
    /// Recebe e verifica bundles locais em quarentena, sem ativá-los.
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
        #[arg(last = true, required = true, allow_hyphen_values = true)]
        command: Vec<OsString>,
    },
}

#[derive(Subcommand)]
enum ExtCommand {
    /// Valida, calcula hash e executa smoke isolado; não aprova nem promove.
    Check { path: PathBuf },
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
    if let Command::SandboxInit { command } = cli.command {
        let status = fictor::sandbox::init::run(command).await?;
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
            command: ExtCommand::Check { path },
        } => {
            use std::sync::Arc;
            let config = Arc::new(fictor::config::Config::load(&home)?);
            let nat64 = fictor::proxy::nat64::Nat64Prefixes::new(&config.egress.nat64_prefixes)?;
            let store = Arc::new(fictor::store::Store::open(&home).await?);
            let secrets = Arc::new(fictor::secrets::SecretStore::open(
                &home,
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
            );
            let result = checker.check_local(&path).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "proposal_id":result.proposal.id,"ext_id":result.proposal.ext_id,
                    "state":result.proposal.state,"bundle_hash":result.proposal.hash,
                    "tools_hash":result.catalog.hash(),"tools":result.catalog.tools().len(),
                    "ignored":result.ignored,"activated":false
                }))?
            );
        }
        Command::Secrets { command } => {
            let config = fictor::config::Config::load(&home)?;
            let secrets =
                fictor::secrets::SecretStore::open(&home, config.secrets.backend, redactor)?;
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
                    let value = rpassword::prompt_password("Segredo: ")
                        .context("ler segredo no TTY sem eco")?;
                    secrets.set(&name, &value)?;
                    println!("Segredo salvo no backend configurado.");
                }
                SecretCommand::List => {
                    for name in secrets.list()? {
                        println!("{name}");
                    }
                }
                SecretCommand::Rm { name } => {
                    secrets.remove(&name)?;
                    println!("Segredo removido do backend configurado.");
                }
            }
        }
        Command::SandboxInit { .. } => bail!("sandbox init já tratado"),
    }
    Ok(())
}
