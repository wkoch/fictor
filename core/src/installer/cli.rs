//! Trusted ADR-045 client. Mutations are never retried after an uncertain reply.
use super::online::{InstallStatus, Review};
use crate::{admin, store::ProposalState};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    future::Future,
    io::{Read, Write},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf},
    pin::Pin,
    time::Duration,
};
use tokio::{io::unix::AsyncFd, time::Instant};

type Interrupt = Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepared {
    schema: u32,
    proposal_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    schema: u32,
    proposal_id: String,
    state: ProposalState,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Promotion {
    schema: u32,
    proposal_id: String,
    operation_id: String,
}

/// This client never opens the source, Store, lock or an offline fallback.
pub async fn install(
    home: &Path,
    path: Option<PathBuf>,
    yes: bool,
    resume: Option<String>,
) -> Result<()> {
    if path.is_some() == resume.is_some() || resume.is_some() && yes {
        bail!("use um caminho [--yes] ou --resume <proposal_id>");
    }
    let resuming = resume.is_some();
    let mut interrupt: Interrupt = Box::pin(tokio::signal::ctrl_c());
    let id = match resume {
        Some(id) if valid_id(&id) => id,
        Some(_) => bail!("proposal_id inválido"),
        None => {
            let path = std::path::absolute(path.context("caminho ausente")?)
                .context("não foi possível resolver o caminho local")?;
            let path = path.to_str().context("o caminho deve ser UTF-8")?;
            let value = request(
                home,
                "ext.install.prepare",
                &json!({"path":path}),
                &mut interrupt,
                None,
            )
            .await?;
            let ack: Prepared =
                serde_json::from_value(value).map_err(|_| invalid_response(None))?;
            if ack.schema != 1 || !valid_id(&ack.proposal_id) {
                return Err(invalid_response(None));
            }
            ack.proposal_id
        }
    };
    output(&format!("Proposta: {id}\n"))?;
    let mut next_poll = Instant::now();
    let mut first_status = true;
    let mut retry_aborted = false;
    let mut approved_here = false;
    let mut operation = None;
    loop {
        tokio::select! {
            biased;
            _ = interrupt.as_mut() => return Err(interrupted(Some(&id))),
            _ = tokio::time::sleep_until(next_poll) => {}
        }
        next_poll = Instant::now() + Duration::from_secs(1);
        let Some(value) = status_request(home, &id, &mut interrupt).await? else {
            continue;
        };
        let status = InstallStatus::parse(value, &id).map_err(|_| invalid_response(Some(&id)))?;
        if first_status {
            retry_aborted = resuming
                && status.state == ProposalState::Approved
                && status
                    .promotion
                    .as_ref()
                    .is_some_and(|p| p.state == "aborted");
            first_status = false;
        }
        if let Some(promotion) = &status.promotion {
            if operation
                .as_ref()
                .is_some_and(|id| id != &promotion.operation_id)
            {
                return Err(invalid_response(Some(&id)));
            }
            match promotion.state.as_str() {
                "prepared" if status.state == ProposalState::Approved => {
                    retry_aborted = false;
                    continue;
                }
                "committed" if status.state == ProposalState::Promoted => {
                    output(&format!(
                        "Instalação concluída. Proposta: {id}; operação: {}\n",
                        promotion.operation_id
                    ))?;
                    return Ok(());
                }
                "aborted" if retry_aborted => {}
                "aborted" => bail!(
                    "Promoção abortada. Proposta: {id}. Uma nova tentativa exige --resume {id} e confirmação humana."
                ),
                _ => return Err(invalid_response(Some(&id))),
            }
        }
        match status.state {
            ProposalState::Received | ProposalState::Checking => continue,
            ProposalState::Failed => bail!(
                "Verificação falhou ({}). Proposta: {id}. Inicie uma nova instalação.",
                ascii(&serde_json::to_string(
                    status.reason.as_deref().unwrap_or("check:failed")
                )?)
            ),
            ProposalState::Rejected => {
                bail!("Proposta rejeitada: {id}. Inicie uma nova instalação.")
            }
            ProposalState::Checked => {
                let review = status.review.as_ref().context("revisão completa ausente")?;
                show_review(review)?;
                let approve = if yes && !resuming {
                    true
                } else {
                    confirm(&mut interrupt, &id).await?
                };
                let nonce = status.nonce.as_ref().context("nonce ausente")?;
                let hash = status
                    .review_hash
                    .as_ref()
                    .context("hash da revisão ausente")?;
                let value = request(home, "ext.install.decision", &json!({"proposal_id":id,"nonce":nonce,"review_hash":hash,"decision":if approve { "approve" } else { "reject" },"overrides":review.overrides}), &mut interrupt, Some(&id)).await?;
                let ack: Decision =
                    serde_json::from_value(value).map_err(|_| invalid_response(Some(&id)))?;
                if ack.schema != 1
                    || ack.proposal_id != id
                    || ack.state
                        != if approve {
                            ProposalState::Approved
                        } else {
                            ProposalState::Rejected
                        }
                {
                    return Err(invalid_response(Some(&id)));
                }
                if !approve {
                    output(&format!("Proposta rejeitada: {id}\n"))?;
                    return Ok(());
                }
                approved_here = true;
            }
            ProposalState::Approved => {
                if operation.is_some() {
                    return Err(invalid_response(Some(&id)));
                }
                if !approved_here {
                    // A previous invocation's approval is not consent for a new
                    // promotion attempt, including one whose journal aborted.
                    let review = status
                        .review
                        .as_ref()
                        .ok_or_else(|| invalid_response(Some(&id)))?;
                    show_review(review)?;
                    if !confirm(&mut interrupt, &id).await? {
                        bail!("Promoção cancelada. Proposta: {id}");
                    }
                }
                let value = request(
                    home,
                    "ext.install.promote",
                    &json!({"proposal_id":id}),
                    &mut interrupt,
                    Some(&id),
                )
                .await?;
                let ack: Promotion =
                    serde_json::from_value(value).map_err(|_| invalid_response(Some(&id)))?;
                if ack.schema != 1 || ack.proposal_id != id || !valid_id(&ack.operation_id) {
                    return Err(invalid_response(Some(&id)));
                }
                output(&format!("Promoção admitida: {}\n", ack.operation_id))?;
                operation = Some(ack.operation_id);
                retry_aborted = false;
            }
            ProposalState::Promoted
                if resuming && operation.is_none() && status.promotion.is_none() =>
            {
                output(&format!(
                    "Proposta legada já promovida: {id}. Sem operação de promoção registrada.\n"
                ))?;
                return Ok(());
            }
            ProposalState::Promoted => return Err(invalid_response(Some(&id))),
        }
    }
}

fn valid_id(value: &str) -> bool {
    value
        .parse::<ulid::Ulid>()
        .is_ok_and(|id| id.to_string() == value)
}
fn recovery(id: Option<&str>) -> String {
    match id {
        Some(id) => format!("Proposta: {id}. Retome explicitamente com fictor ext install --resume {id}; nenhuma operação será reenviada automaticamente."),
        None => "ID da proposta desconhecido. Não repita a preparação automaticamente: pode existir um receipt já recebido.".into(),
    }
}
fn invalid_response(id: Option<&str>) -> anyhow::Error {
    anyhow::anyhow!("Resposta administrativa inválida. {}", recovery(id))
}
fn interrupted(id: Option<&str>) -> anyhow::Error {
    anyhow::anyhow!(
        "Instalação interrompida; uma operação enviada pode continuar no core. {}",
        recovery(id)
    )
}
async fn request(
    home: &Path,
    method: &str,
    params: &Value,
    interrupt: &mut Interrupt,
    id: Option<&str>,
) -> Result<Value> {
    tokio::select! {
        biased;
        _ = interrupt.as_mut() => Err(interrupted(id)),
        result = admin::request_method(home,method,params) => result.map_err(|error| anyhow::anyhow!("Falha em {method}: {error}. {}",recovery(id))),
    }
}

async fn status_request(home: &Path, id: &str, interrupt: &mut Interrupt) -> Result<Option<Value>> {
    // Only this read can report a transient publication barrier. No transport
    // error or mutation response, even Busy/None, enters an automatic retry.
    let params = json!({"proposal_id":id});
    tokio::select! {
        biased;
        _ = interrupt.as_mut() => Err(interrupted(Some(id))),
        result = admin::request_method(home,"ext.install.status",&params) => match result {
            Ok(value) => Ok(Some(value)),
            Err(admin::AdminClientError::Domain(admin::AdminMutationError {reason:admin::MutationReason::Busy,effect:admin::Effect::None})) => Ok(None),
            Err(error) => Err(anyhow::anyhow!("Falha em ext.install.status: {error}. {}",recovery(Some(id)))),
        },
    }
}

fn output(text: &str) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(text.as_bytes())
        .context("não foi possível exibir a revisão")?;
    stdout.flush().context("não foi possível exibir a revisão")
}
fn ascii(text: &str) -> String {
    let mut result = String::new();
    for character in text.chars() {
        if character == '\n' || character == ' ' || character.is_ascii_graphic() {
            result.push(character);
        } else {
            result.extend(character.escape_default());
        }
    }
    result
}
fn show_review(review: &Review) -> Result<()> {
    let manifest = super::manifest::Manifest::parse(&review.manifest.to_string())?;
    let catalog = crate::gateway::PinnedCatalog::new(review.tools.clone())?;
    let effective = super::overrides::resolve(
        &manifest,
        &catalog,
        &review.overrides,
        "user",
        &crate::proxy::nat64::Nat64Prefixes::default(),
    )?;
    let tools = catalog.tools().iter().map(|tool| {
        let name = tool["name"].as_str().context("nome de ferramenta ausente")?;
        Ok(json!({"name":name,"classification":effective.tool_class(name),"visible":effective.catalog().tools().iter().any(|tool| tool["name"] == name)}))
    }).collect::<Result<Vec<_>>>()?;
    let previous = review.base.as_ref().and_then(|base| base.get("version"));
    let candidate = json!({"version":review.manifest.get("version"),"hash":review.bundle_hash,"tools":review.tools,"tools_hash":review.tools_hash,"packages":review.packages,"overrides":review.overrides});
    let mut differences = serde_json::Map::new();
    if let Some(candidate) = candidate.as_object() {
        for (key, after) in candidate {
            let before = previous
                .and_then(|base| base.get(key))
                .unwrap_or(&Value::Null);
            if before != after {
                differences.insert(key.clone(), json!({"before":before,"after":after}));
            }
        }
    }
    // JSON escapes string control bytes; ASCII conversion also removes Unicode
    // terminal controls/bidi. Only the formatter's own newlines remain literal.
    let complete = json!({"review":review,"differences":differences,"effective":{"permissions":effective.manifest().permissions,"tools":tools}});
    output(&format!(
        "Revisão completa e diferenças da base:\n{}\n",
        ascii(&serde_json::to_string_pretty(&complete)?)
    ))
}

async fn confirm(interrupt: &mut Interrupt, id: &str) -> Result<bool> {
    tokio::select! {
        biased;
        _ = interrupt.as_mut() => Err(interrupted(Some(id))),
        result = confirmation() => result.with_context(|| format!("Nenhuma decisão enviada. {}",recovery(Some(id)))),
    }
}
async fn confirmation() -> Result<bool> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/dev/tty")
        .context("TTY controlador indisponível")?;
    // SAFETY: isatty only inspects the live descriptor; no terminal state changes.
    if unsafe { libc::isatty(file.as_raw_fd()) } != 1 {
        bail!("TTY controlador indisponível");
    }
    let tty = AsyncFd::new(file).context("TTY controlador indisponível")?;
    let mut prompt = b"Confirmar esta revisao e promover? [sim/NAO] ".as_slice();
    while !prompt.is_empty() {
        let mut ready = tty.writable().await?;
        match ready.try_io(|inner| {
            let mut file = inner.get_ref();
            file.write(prompt)
        }) {
            Ok(Ok(0)) => bail!("TTY encerrado"),
            Ok(Ok(count)) => prompt = &prompt[count..],
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => {}
        }
    }
    let mut answer = Vec::new();
    loop {
        let mut ready = tty.readable().await?;
        let mut byte = [0u8];
        match ready.try_io(|inner| {
            let mut file = inner.get_ref();
            file.read(&mut byte)
        }) {
            Ok(Ok(0)) => bail!("TTY encerrado antes da decisão"),
            Ok(Ok(_)) if byte[0] == b'\n' => break,
            Ok(Ok(_)) if answer.len() < 64 => answer.push(byte[0]),
            Ok(Ok(_)) => bail!("confirmação inválida"),
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => {}
        }
    }
    Ok(matches!(answer.as_slice(), b"sim" | b"s" | b"yes" | b"y"))
}
