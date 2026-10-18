# Verificação da implementação

## Estado da entrega Linux x86-64

Data: 2026-10-17. Alvo único: **Linux x86-64**, validado no **Fedora COSMIC Atomic**
([ADR-030](../spec/11-decisions.md)). Nenhum build nativo ou teste em Linux
foi executado nesta máquina durante a migração. Resultados históricos obtidos fora
do alvo não constituem evidência para a plataforma atual. A checagem de formatação
é estática e também não satisfaz o gate.

| Ambiente | Execução nesta entrega | Papel |
|---|---|---|
| Máquina Fedora COSMIC Atomic do usuário | Pendente | Gate obrigatório de release: todos os critérios de aceitação. |
| CI Ubuntu 22.04 x86-64 | Configurada, execução remota pendente | Build, formatação, Clippy e suíte completa, com sandbox real. |
| CI container Fedora 44 x86-64 | Configurada, execução remota pendente | Build de todos os testes; execução das suítes sem sandbox real. |

Fedora 44 corresponde à [release estável oficial do COSMIC Atomic](https://fedoraproject.org/atomic-desktops/cosmic/download/)
consultada em 2026-10-17. O container não reproduz o desktop Atomic nem SELinux do
host e não substitui o gate. Ao continuar, conferir a versão instalada do usuário
e manter a imagem da CI alinhada ao alvo.

Os testes usam segredos falsos, diretórios temporários e endpoints locais, sem
rede externa. As fixtures `core/tests/fixtures/model-*` são certificado e chave
exclusivos para testes; sua confiança não é instalada no sistema.

## Diagnóstico antes da migração

- `cargo fmt --check`: passou.
- `cargo check --locked --offline --target x86_64-unknown-linux-gnu --all-targets`:
  passou por compilação cruzada, incluindo o código e os alvos de teste Linux.
- `cargo clippy --locked --offline --target x86_64-unknown-linux-gnu --all-targets -- -D warnings`:
  passou por compilação cruzada, sem avisos.

Zig foi usado somente como compilador C cruzado para as dependências. Os helpers
ficaram fora do repositório e não são requisito do app ou do desenvolvimento no
Fedora. Nenhum binário Linux foi executado. Estes diagnósticos não contam como
execução na CI, no desktop nem como gate de release.

## Execução no Fedora COSMIC Atomic

Registrar data, saída de `cat /etc/os-release`, `uname -m`, `rpm-ostree status`,
`getenforce`, `rustc --version`, `cargo --version` e `git rev-parse HEAD` junto aos
resultados. Manter SELinux enforcing e as políticas de namespaces intactas.
Executar no terminal do host:

```sh
cd core
cargo fetch --locked
cargo fmt --all -- --check
cargo clippy --all-targets --locked --offline -- -D warnings
cargo test --locked --offline
```

A obtenção de dependências é separada dos testes. A execução dos testes não exige
contas de provider, credenciais reais ou internet. Uma falha de isolamento precisa
ser corrigida na implementação ou no ambiente suportado, preservando as proteções.

O job Fedora executa `--lib` e as suítes `bootstrap`, `budget`, `kernel`,
`local_checker`, `manifest`, `model_tls`, `models`, `proposals`, `proxy` e `store`.
Ele exclui explicitamente somente o teste de bootstrap
`doctor_reports_missing_runtime_without_modifying_config`, que chama o probe real
de sandbox. As suítes `sandbox`, `sandbox_init` e `supervisor` também dependem de
namespaces reais e ficam na execução completa do Ubuntu e do desktop. Nenhum teste
é marcado como ignorado para contornar isolamento; o Ubuntu não tem skips.

## Testes por invariante

São testes presentes no código; **sua execução em Linux ainda precisa ser registrada**.

| Invariante | Cobertura implementada | Restante para o gate |
|---|---|---|
| I1 | Launcher e supervisor criam processos externos; MCP por stdio. | Harness completo e execução no Fedora. |
| I2 | Suítes `sandbox`, `sandbox_init`, `supervisor`; caminhos sensíveis e argumentos bwrap. | Confinamento real, caminhos Atomic e contenção adversarial da árvore. |
| I3 | Gateway verifica argumentos, catálogo e pin; chamada sem pin falha. | Política/aprovação em M0.6 e teste de ponta a ponta. |
| I4 | Model proxy opaco, TLS inválido recusado; ambiente limpo e logs mascarados. | Extensão adversarial e providers no harness. |
| I5 | Migrações iguais ao spec; UPDATE/DELETE de eventos recusados. | Reexecutar no Fedora e na CI. |
| I6 | Reabertura preserva histórico e flags cumulativas. | Matar/reiniciar harness durante uma conversa. |
| I7 | Recebimento limitado; smoke isolado; lock e catálogo validados; check mantém quarentena. | Resolvers, promoção e ativação real pelo lock. |
| I8 | Propostas exigem nonce humano com CAS e rotação; Kernel não decide aprovações. | Aprovações de tools em M0.6 e UI confiável. |
| I9 | Corpos opacos no model proxy e configuração de extensão opaca. | Harness e adapters completos. |
| I10 | Regra de manutenção do core. | Revisão do diff por marco. |
| I11 | Taint de rede, KV/ext_data por sessão e cutoff dos forks no Kernel. | Gateway/política, flags do workspace e harness; globais só na Fase 1 (ADR-025). |

## Limites e próximos gates

- `serve`, política/aprovações, shell e harness ainda não estão integrados.
- M0.5 parcial: resolvers, promoção/ativação, hot swap, recuperação de propostas e
  backoff de crashes pendentes. Kernel `log` ainda precisa do sink do supervisor.
- ARQ-001–018 foram resolvidas arquiteturalmente. Isso não representa conclusão
  das adaptações ou dos critérios de aceitação dos ADRs 025–031.
- O encerramento do ADR-029 exige confirmar a saída do bwrap antes de liberar
  recursos; fork duplo, `setsid()` e morte do core com SIGKILL exigem prova no Linux.
- A v0.1 também exige toolchains no sandbox, compactação, guarda de migração com
  backup, login, rollback e roteiro de desenvolvimento de dentro do Fictor.
- Esta entrega não constitui aprovação de release v0.1 nem v1.0.

## Verificação arquitetural do ADR-035 — 2026-10-18

Base: `80e04ab71da8f272231a92c407e79323db1aa53e`, com alterações locais.
Execução no Toolbx `fictor-dev`, Fedora Linux 44, SQLite 3.51.2, sobre host
Bazzite `44.20261012.0` (Kinoite). É diagnóstico da especificação, não evidência
do gate no Fedora COSMIC Atomic nem execução de CI.

- SQL de `spec/schemas/0003_proposal_receipts.sql` executado via Python/SQLite
  em bancos descartáveis na memória, após as migrações 0001/0002.
- Passou: preservação de todos os valores em propostas dos sete estados,
  incluindo nonces, e preservação de eventos e sessões; 28 combinações de
  identidade/estado; índice `proposals_state`, foreign keys, integridade, FTS e
  triggers que proíbem UPDATE/DELETE de eventos.
- Uma falha injetada depois da reconstrução da tabela confirmou rollback
  integral da transação, conservando o schema e os registros da versão 2.
- Passaram 106 links/âncoras locais dos documentos revisados, numeração dos
  37 critérios da Fase 0 e `git diff --check`. As migrações 0001/0002 não mudaram.
- Revisão arquitetural independente não encontrou bloqueios. ARQ-019 resolvida
  pelo ADR-035; código do recebimento/recuperação e testes dos critérios 35–37
  continuam pendentes para o implementador. Nenhuma suíte Rust ou teste de
  aceitação foi executado nesta revisão de arquitetura.
