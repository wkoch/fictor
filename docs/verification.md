# Verificação da implementação

## Integração na main — 2026-10-18

Código validado: `de9a82f47008a1c1a1a212f104592b6cb2e809f3`.
Merge local de `codex/m05-proposal-receipts` com os quatro commits de arquitetura
que já estavam na `main`. A branch de implementação foi removida após confirmar
que seu histórico estava integralmente alcançável pela `main`.

O conteúdo de `spec/` permaneceu idêntico a `a753e69`, último commit do Arquiteto:
as mudanças normativas da branch eram as mesmas já presentes no ADR-035 da main.
O código em `core/` e `dev/` permaneceu idêntico ao da branch em `59a9d11`.
Os conflitos documentais foram conciliados preservando os diagnósticos e as
resoluções arquiteturais; ARQ-020–026 estão resolvidas, e ARQ-027 continua aberta.
Os contratos dos ADRs 036–042 ainda exigem implementação e testes.

Execução no computador do usuário, **Bazzite 44.20261012.0 (Kinoite), x86-64,
SELinux Enforcing**, dentro do **Toolbx `fictor-dev`, Fedora 44**, com as mesmas
ferramentas e imagem registradas abaixo. Cargo usou `--locked --offline` e caches
do workspace. Nenhuma instalação no host ou global no `$HOME`.

| Verificação | Resultado |
|---|---|
| `cargo fmt --all -- --check` | Passou. |
| `cargo clippy --all-targets --locked --offline -- -D warnings` | Passou, sem avisos. |
| `cargo test --locked --offline --no-fail-fast` | **326 passaram, 0 falharam, 0 ignorados.** |
| `cargo build --release --locked --offline` | Passou. |
| `trail build` / `trail build --check` | Grafo estrutural atualizado e consistente. |
| Conferência do roadmap e da matriz | 75 critérios ativos: 56 + 10 + 4 + 5; 26 referências exatas de testes conferidas. |
| `git diff --check` | Passou. |

Logs: `.fictor/logs/main-integration-{fmt,clippy,test,release,trail-build,trail-check}.log`
e `main-integration-code-head.log`. O hash de `AGENTS.md` confirmou a preservação
da alteração local preexistente; ela e o cache `.trail/` ficaram fora dos commits.
O [fluxo de Git](implementation.md#fluxo-de-git) registra a orientação do usuário:
trabalho integrável diretamente na `main`, operações Git pelo agente principal
e edição da arquitetura pelo Arquiteto. O [caminho até a v1.0](release-path.md)
foi alinhado ao roadmap integrado.

A suíte usou dados falsos e endpoints locais, sem chaves reais nem rede externa,
incluindo sandbox real e npm/uv. Não há workspace TypeScript/`vp` nesta base.
A CI remota não foi executada e o gate no Fedora COSMIC Atomic permanece pendente.
Esta integração não declara M0.5 ou qualquer release concluídos.

## Provas de isolamento no Bazzite — 2026-10-18

Código validado: `6f39449cf4bd91824ce6c9b918b6e6bb98c7899e`.
Execução no computador do usuário, **Bazzite 44.20261012.0 (Kinoite), x86-64,
SELinux Enforcing**, dentro do **Toolbx `fictor-dev`, Fedora 44**. Mesma imagem
e versões das ferramentas registradas abaixo. Cargo usou `--locked --offline`
e caches do workspace. Nada foi instalado no host ou globalmente no `$HOME`.

| Verificação | Resultado |
|---|---|
| `cargo fmt --all -- --check` | Passou. |
| `cargo clippy --all-targets --locked --offline -- -D warnings` | Passou, sem avisos. |
| `cargo test --locked --offline --no-fail-fast` | **326 passaram, 0 falharam, 0 ignorados.** |
| `cargo build --release --locked --offline` | Passou. |
| `trail build` / `trail build --check` | Grafo estrutural atualizado e consistente. |
| `git diff --check` | Passou. |

Dois testes de integração cobrem cenários já previstos na Fase 0:

- **Critério 5 / I4:** uma extensão nativa faz uma requisição ao provider HTTP
  local por meio do model proxy. O upstream confirma a chave falsa aleatória
  injetada pelo core; a extensão recebe somente o payload público. O host procura
  a chave nas observações de ambiente, arquivos de fixture legíveis, descritores
  regulares e memória do processo. Controles distintos comprovam cada captura,
  incluindo um canário criado em heap durante a execução e um arquivo
  desvinculado mantido em FD 128. Na execução dirigida final, foram capturadas
  21 regiões e 2.871.296 bytes de memória, seis arquivos e um FD regular;
  três caminhos privados existentes no host ficaram inacessíveis. Dois mapas
  VVAR e uma região sem leitura foram contabilizados. O probe falha em erro
  inesperado ou limite excedido, sem varrer os próprios dumps. Essa fixture não
  atesta todos os runtimes, instantes, codificações ou arquivos do host.
- **Critério 16:** duas instâncias simultâneas da mesma extensão, em sessões
  diferentes, gravam a mesma chave KV e o mesmo nome de arquivo com valores
  distintos. As chamadas passam pelo Kernel TCP real de cada sandbox. B começa
  sem os dados de A e não lê seu caminho absoluto; depois de B sair, A conserva
  ambos os valores e também não lê os dados de B. A única concessão de
  filesystem é `${ext_data}` da instância. O alvo `supervisor` passou com 29 testes.

A primeira suíte completa teve 325 testes passando e uma falha no teste existente
de cancelamento da recuperação. Um diagnóstico manteve `BEGIN IMMEDIATE` sem
`ROLLBACK` e observou `DatabaseBusy`, proposta ainda `received` e lease novamente
disponível: o bloqueio SQLite não garantia trabalho pendente. O teste agora usa
uma barreira confirmada no writer, com liberação antes das asserções e durante
unwind. `proposal_recovery` passou com sete testes e a suíte completa foi repetida
após essa correção. A implementação produtiva não foi alterada nesta rodada.

A revisão adicional do instalador, do gateway e das fronteiras de autenticação,
escopo e linhagem do Kernel não demonstrou outro defeito nesse recorte. A
**ARQ-027** registra separadamente uma requisição válida no limite de 16 MiB que
recebe erro com `id: null`, perdendo a correlação com seu ID conhecido. A reprodução
local falhou na asserção de correlação; o teste temporário foi removido. Teto de
ID ou encerramento de transporte exigem ADR, conforme `AGENTS.md`; nenhum desses
contratos foi implementado nem o limite de mensagem foi relaxado.

Logs diretos: `.fictor/logs/m05-isolation-{fmt,clippy,test,release,trail-build,trail-check}.log`,
`m05-isolation-code-head.log`, `i4-provider-secret-probe-direct.log` e
`m05-recovery-sqlite-diagnostic.log`. A primeira suíte e seu commit foram preservados
em `m05-isolation-test-before.log` e `m05-isolation-code-head-before.log`.
`kernel-large-id-before-transcript.log` é um transcript reconstruído das saídas
capturadas, identificado como tal. Os 26 links de testes do
[mapa de invariantes](invariants.md) foram conferidos por identificador e linha.

Os testes usaram dados falsos e serviços locais, sem chaves reais nem rede externa,
incluindo sandbox real e npm/uv no Toolbx. Não há workspace TypeScript/`vp`
nesta base. A CI remota não foi executada.

**Este diagnóstico no Bazzite não satisfaz o gate de release no COSMIC Atomic.**
M0.5 permanece parcial nas partes dependentes das ARQ-020–027; não houve ativação,
alteração de formatos persistidos ou avanço para os marcos seguintes.

## Prazos MCP com fila e escrita bloqueadas no Bazzite — 2026-10-18

Código validado: `df71e27d2ca584ff62f7d5d710d2502ffd02b286`.
Execução no computador do usuário, **Bazzite 44.20261012.0 (Kinoite), x86-64,
SELinux Enforcing**, dentro do **Toolbx `fictor-dev`, Fedora 44**. Mesma imagem
e versões das ferramentas registradas abaixo. Cargo usou `--locked --offline`
e caches do workspace. Nada foi instalado no host ou globalmente no `$HOME`.

| Verificação | Resultado |
|---|---|
| `cargo fmt --all -- --check` | Passou. |
| `cargo clippy --all-targets --locked --offline -- -D warnings` | Passou, sem avisos. |
| `cargo test --locked --offline --no-fail-fast` | **324 passaram, 0 falharam, 0 ignorados.** |
| `cargo build --release --locked --offline` | Passou. |
| `trail build` / `trail build --check` | Grafo estrutural atualizado e consistente. |
| `git diff --check` | Passou. |

Três regressões novas reproduziram bloqueios no caminho de chamadas MCP:

- Com a escrita da requisição e da notificação bloqueadas, o timeout do SDK
  ficava esperando a confirmação do cancelamento. O watchdog de um segundo
  falhou antes da correção. Agora a chamada retorna `Timeout`; ao liberar o
  transporte, o servidor recebe a chamada e um cancelamento com o mesmo ID.
- Cancelamento explícito de uma chamada em andamento também ficava preso no
  ACK da notificação. A reprodução anterior falhou no mesmo watchdog. Agora
  retorna `Cancelled` após uma tentativa limitada; liberar a escrita confirma
  a notificação correspondente, sem segundo timer de cancelamento do SDK.
- Com as 1024 vagas da fila ocupadas, a chamada continuava pendente mesmo após
  cancelamento. O teste também inicia uma chamada com prazo positivo nessa
  condição, aguarda seu vencimento e confirma `Timeout`, sem emissão tardia
  de `tools/call` ou cancelamento ao drenar a fila.

Os sete unitários do gateway passaram, preservando os testes de catálogo, de
cancelamento anterior ao envio e de timeout com transporte livre. A revisão
do roadmap não identificou outra entrega funcional de M0.5 liberada dos ADRs
pendentes. O [mapa de invariantes](invariants.md) relaciona I1–I11 a 26 referências
de testes e registra os limites dessa cobertura, incluindo fluxos ainda ausentes.

Logs de execução direta: `.fictor/logs/m05-mcp-deadline-{fmt,clippy,test,release,trail-build,trail-check}.log`,
`m05-mcp-deadline-code-head.log` e `gateway-backpressure-after-direct.log`.
`gateway-backpressure-before-transcript.log` é uma reconstrução das saídas
capturadas das reproduções anteriores à correção, não um log de execução direta.
Os testes usaram dados falsos e serviços locais, sem chaves reais nem rede externa,
incluindo sandbox real e npm/uv no Toolbx. Não há workspace TypeScript/`vp`
nesta base. A CI remota não foi executada.

**Este diagnóstico no Bazzite não satisfaz o gate de release no COSMIC Atomic.**
M0.5 permanece parcial nas partes dependentes das ARQ-020–026. Não houve ativação,
mudança de formatos persistidos ou implementação de contratos bloqueados.

## Cancelamento e arquivos de controle no Bazzite — 2026-10-18

Código validado: `447e42bf6b3741f340e15c5e95398107477d79c9`.
Execução no computador do usuário, **Bazzite 44.20261012.0 (Kinoite), x86-64,
SELinux Enforcing**, dentro do **Toolbx `fictor-dev`, Fedora 44**. Mesma imagem
e versões das ferramentas já registradas abaixo. Cargo usou `--locked --offline`
e caches do workspace. Nada foi instalado no host ou globalmente no `$HOME`.

| Verificação | Resultado |
|---|---|
| `cargo fmt --all -- --check` | Passou. |
| `cargo clippy --all-targets --locked --offline -- -D warnings` | Passou, sem avisos. |
| `cargo test --locked --offline --no-fail-fast` | **321 passaram, 0 falharam, 0 ignorados.** |
| `cargo build --release --locked --offline` | Passou. |
| `trail build` / `trail build --check` | Grafo estrutural atualizado e consistente. |
| `git diff --check` | Passou. |

Cinco testes novos cobrem três falhas reproduzidas antes das correções:

- Cancelar o future de conexão MCP, mantendo `ManagedInstance` vivo, deixava o
  processo com pipes consumidos e canais ativos. Os dois casos (descoberta e
  pin explícito) falharam esperando reap antes da correção. Agora verificam saída
  do namespace, remoção de PID/socket, revogação do proxy, retenção do owner até
  `wait` e exatamente um `ext.stopped`, sem crash ou mudança de catálogo falsa.
  O alvo `supervisor` passou com 27 testes reais.
- Uma chamada já cancelada ainda enviava `tools/call`. A regressão observou essa
  requisição antes da barreira ordenada `resources/list`. Agora não há chamada
  nem notificação de cancelamento para uma operação nunca emitida, inclusive
  quando o dono do canal foi descartado. O mesmo teste confirma cancelamento
  de uma chamada em andamento com o ID correto. Os quatro unitários do gateway
  passaram, incluindo o timeout que continua enviando cancelamento MCP.
- FIFO em leitura de configuração podia prender o worker e o encerramento do
  runtime. A reprodução isolada precisou terminar o filho após cinco segundos,
  sem pendurar o Cargo. Agora pipes diretos/indiretos, dispositivos e diretórios
  são recusados; links para arquivos regulares continuam recarregando instruções
  e somente a tabela da própria extensão. `kernel_read_limits` passou com seis
  testes, `kernel_catalog` com cinco e `bootstrap` com 13.

A revisão adicional de smoke e resolução não identificou outro defeito concreto:
foram inspecionados grants omitidos, estado/credenciais descartáveis, prazos,
retenção de owner/lease e criação dos destinos. Não foram adicionados testes
redundantes nem código nessa frente. A nova ARQ-026 separa da correção de I/O a
política pendente para links de arquivos globais apontando a destinos graváveis
por extensões; tipo regular não estabelece autoria humana.

Logs locais: `.fictor/logs/m05-io-cancellation-{fmt,clippy,test,release,trail-build,trail-check}.log`
e `m05-io-cancellation-code-head.log`; regressão do gateway em
`m05-cancel-{before,after,clippy}.log`. A suíte usou dados falsos e endpoints locais,
sem chaves reais nem rede externa, incluindo sandbox real e npm/uv no Toolbx.
Não há workspace TypeScript/`vp` nesta base. A CI remota não foi executada.

**Este diagnóstico no Bazzite não satisfaz o gate de release no COSMIC Atomic.**
M0.5 continua parcial nas partes dependentes das ARQ-020–026; não houve ativação,
mudança de formatos persistidos ou implementação de contratos bloqueados.

## Limites de leitura e integridade do M0.5 no Bazzite — 2026-10-18

Código validado: `0ec1e418d2d5883cc4138219121f161dc105d8b4`.
Execução no computador do usuário, **Bazzite 44.20261012.0 (Kinoite), x86-64,
SELinux Enforcing**, dentro do **Toolbx `fictor-dev`, Fedora 44**. Mesma imagem
e versões das ferramentas registradas abaixo. Cargo usou `--locked --offline`,
com cache no workspace. Nenhuma instalação no host ou ferramenta global no
`$HOME` foi necessária nesta continuação.

| Verificação | Resultado |
|---|---|
| `cargo fmt --all -- --check` | Passou. |
| `cargo clippy --all-targets --locked --offline -- -D warnings` | Passou, sem avisos. |
| `cargo test --locked --offline --no-fail-fast` | **316 passaram, 0 falharam, 0 ignorados.** |
| `cargo build --release --locked --offline` | Passou. |
| `trail build` / `trail build --check` | Grafo estrutural atualizado e consistente. |
| `git diff --check` | Passou. |

São 15 testes novos desde os 301 do diagnóstico seguinte:

- KV e eventos têm orçamento cumulativo de JSON escapado antes da retenção de
  cada entrada. A regressão usa chaves cujo tamanho cru cabe, mas a representação
  escapada ultrapassa 16 MiB, seguidas de uma linha SQLite malformada: o Kernel
  retorna `TOO_LARGE` antes de tentar decodificá-la. Uma leitura geral do Store
  encontra essa linha, demonstrando que o teste distingue interrupção antecipada
  de uma checagem posterior. Autorização, ordem, truncamento, resultados pequenos
  e os limites exatos de wrappers/booleanos também foram verificados.
- `blobs.get` limita bytes antes de carregar/base64. Testes preservam acesso
  geral do Store, tamanho exato, conteúdo vazio e verificação do hash; um arquivo
  esparso acima de 256 MiB é recusado. Instruções locais grandes são recusadas
  antes da decodificação, enquanto ausência, Unicode e erro UTF-8 pequeno
  conservam o comportamento esperado. `kernel_read_limits` passou com quatro
  testes e entrou na seleção Fedora da CI sem namespaces.
- A materialização revalida o inventário aprovado na cópia privada. Duas
  regressões falharam antes da correção: pacote físico omitido e versão aprovada
  divergente eram publicados apesar de hash correto e checks completos. Também
  é recusada a árvore npm física sem declaração de dependências. Candidato npm
  íntegro continua materializando sem resolução, rede ou execução de código.
  O alvo `promotion` passou com nove testes; `dependencies`, com 12.
- A invalidação terminal MCP chega à task dona da instância. As duas regressões
  iniciais falharam antes da correção: fechar o MCP deixava um servidor hostil
  dormindo no namespace. Agora mismatch inicial ou em runtime encerra processos,
  kernel e proxy e produz um único `ext.tools_changed` antes de `ext.stopped`.
  Com o writer bloqueado, o reap e a revogação ocorrem antes da auditoria; PID e
  owner externo permanecem retidos. A falha forçada da auditoria é reportada como
  erro, sem declarar persistência concluída. Notificação idêntica conserva a
  instância; trocar pin ou fixar depois de uma conexão sem pin é recusado, e o
  mesmo pin permite reutilização. O alvo `supervisor` passou com 25 testes reais.

Logs locais: `.fictor/logs/m05-integrity-{fmt,clippy,test,release,trail-build,trail-check}.log`
e `m05-integrity-code-head.log`; testes dirigidos adicionais em
`m05-bounded-reads-{kernel,blobs}.log`. Toda a suíte usa dados falsos, sem chaves
reais nem rede externa. npm/uv e sandbox rodaram no Toolbx real. Não há workspace
TypeScript/`vp` nesta base; a CI remota não foi executada nesta entrega.

**Este diagnóstico no Bazzite não satisfaz o gate de release no COSMIC Atomic.**
Não houve ativação, mudança de formatos persistidos, avanço ao M0.6 ou conclusão
integral do critério 13: lock e gerenciador ainda precisam de integração. As
ARQ-020–024 continuam abertas. A nova ARQ-025 registra a contradição de
disponibilidade offline de `ext list`; o comando não foi exposto presumindo um
contrato administrativo ou uma exceção ao spec.

## Catálogo e correções de integração no Bazzite — 2026-10-18

Código validado: `b629fe03c8fead863a915979cf61d7faf6c0f340`.
Execução no computador do usuário, **Bazzite 44.20261012.0 (Kinoite), x86-64,
SELinux Enforcing**, dentro do **Toolbx `fictor-dev`, Fedora 44**. Mesmas versões
de ferramentas e imagem registradas no diagnóstico seguinte. Dependências em
cache no workspace; Cargo usou `--locked --offline`. Nada foi instalado no host
ou globalmente no `$HOME` nesta continuação.

| Verificação | Resultado |
|---|---|
| `cargo fmt --all -- --check` | Passou. |
| `cargo clippy --all-targets --locked --offline -- -D warnings` | Passou, sem avisos. |
| `cargo test --locked --offline --no-fail-fast` | **301 passaram, 0 falharam, 0 ignorados.** |
| `cargo build --release --locked --offline` | Passou. |
| `trail build` / `trail build --check` | Grafo atualizado e consistente. |
| `git diff --check` | Passou. |

Foram acrescentados 16 testes desde os 285 registrados abaixo. A suíte final
incluiu sandbox real, o model proxy com streaming de 256 MiB, npm/uv reais e a
CLI real, sempre com dados falsos e endpoints locais, sem rede externa nem chaves
reais. Os casos novos cobrem:

- `catalog.list`: contrato da resposta, escopo, própria sessão e parâmetros
  exatos; versões ativas/habilitadas e extensões globais declarativas; metadados
  Agent Skills e comandos, caminhos absolutos, sem executar código ou interpretar
  o corpo. Symlinks, FIFO, conteúdo gravável, identidade inválida, overrides
  indefinidos e declarações da Fase 1 são recusados. O limite conta JSON escapado;
  metadados opcionais acima de 16 MiB continuam usando os limites do bundle.
- npm: pacote físico sem entrada no hidden lock impede `checked`, inclusive sem
  `package.json`. Bundled/scoped/nested legítimos passam; fixtures comuns não
  entram no inventário. Python aceita headers de identidade válidos sem diferença
  de case, com whitespace ou continuação, e recusa duplicatas de identidade.
  `dependencies` passou com 12 testes e `local_checker` com 14 no Toolbx real.
- Supervisor: sessão inexistente/arquivada e workspace divergente são recusados
  antes de efeitos, inclusive sem canal kernel; alias canonicalizado é aceito
  com processo real. O alvo `supervisor` passou com 19 testes.
- Capturas: reabrir o store durante streaming não remove temporários vivos;
  duas capturas mantêm leases independentes até a última liberação. Limpeza de
  órfãos continua preservando blobs publicados. Os três testes de captura e os
  15 testes de `models` passaram também na rodada isolada.

A primeira rodada completa revelou uma falha intermitente em `extension_control`
(300 passaram, 1 falhou): `Admission/WouldBlock` em uma segunda operação do mesmo
teste. Reproduzida em 7/30 rodadas paralelas, desapareceu em 20/20 rodadas seriais
e em 20/20 paralelas sem os dois casos que iniciam a CLI. Conforme
[flock(2)](https://man7.org/linux/man-pages/man2/flock.2.html), descritores herdados
por fork compartilham o lock até o fechamento. A correção serializa somente os
fixtures desse alvo e conserva as assertions e a produção; não adiciona retries.
Depois dela, 30/30 rodadas paralelas do alvo passaram, seguidas da suíte completa
acima. A regressão de captura também foi executada antes da correção e falhou.

Logs locais: `.fictor/logs/m05-catalog-{fmt,clippy,test-final,release,trail-build,trail-check}.log`,
`m05-catalog-test.log` (primeira rodada), `m05-control-{isolation,serialized}.log`
e `m05-live-capture-{before,after,models,clippy}.log`. O commit validado está também
em `m05-catalog-code-head.log`. Não há workspace TypeScript/`vp` nesta base.
`kernel_catalog` entrou na seleção Fedora sem namespaces; a CI remota não foi
executada nesta entrega.

**Este diagnóstico no Bazzite não satisfaz o gate de release no COSMIC Atomic.**
M0.5 continua parcial nas partes que dependem das ARQ-020–024; não houve ativação
de extensões, implementação de contratos indefinidos ou avanço à Fase 1.

## Continuação do M0.5 no Bazzite — 2026-10-18

Código validado: `d8b8401879add2324409981b44683999ead3ecdc`.
Execução no computador do usuário, **Bazzite 44.20261012.0 (Kinoite), x86-64,
SELinux Enforcing**, dentro do **Toolbx `fictor-dev`, Fedora 44**. Dependências
Cargo em cache; lint, testes e release usaram `--locked --offline`. As versões das
ferramentas estão registradas abaixo. Nenhum pacote ou ferramenta global foi
instalado no host.

| Verificação | Resultado |
|---|---|
| `cargo fmt --all -- --check` | Passou. |
| `cargo clippy --all-targets --locked --offline -- -D warnings` | Passou, sem avisos. |
| `cargo test --locked --offline --no-fail-fast` | **285 passaram, 0 falharam, 0 ignorados.** |
| `cargo build --release --locked --offline` | Passou. |
| `trail build` / `trail build --check` | Grafo estrutural atualizado e consistente. |
| `git diff --check` | Passou. |
| Imagem `dev/Containerfile` com uv | Reconstruída; versões verificadas em container temporário sem rede nem montagens. |

Foram acrescentados 35 testes desde o diagnóstico de 250 abaixo. A suíte incluiu
sandbox real, npm/uv reais contra registros HTTP locais e o binário real da CLI:

- Resolução npm sem scripts ou symlinks `.bin`; hashes adulterados, destinos fora
  da allowlist e wildcards recusados. uv instala wheel com hash e recusa requisitos
  sem hash e builds de fontes. O inventário vem dos metadados efetivamente instalados.
- Pipeline npm → importação do pacote em MCP → `checked`, também pela CLI
  `ext check`: pacotes e hash final persistidos, origem intacta e sem ativação.
  Oito testes em `dependencies`; seis cenários de execução requerem o Toolbx real.
  Neste ambiente esses seis rodaram. O ramo de recusa fora do Toolbx não foi
  exercitado aqui; o teste de planejamento é independente desse bootstrap.
- Materialização exige aprovação humana, checks completos, manifest e hash
  iguais; publica arquivos/diretórios imutáveis. Repetição, alteração da quarentena,
  symlinks, colisão e saída gravável são cobertos sem alterar o último lock.
- `tools.list` lê o pin sem executar processos, respeita sessão/escopo,
  classificações e visibilidade, recusa estado inválido e aplica limite cumulativo
  de JSON escapado. Notificações `log` autenticadas compartilham redator e rotação;
  testes incluem TCP 3129 real, segredo multiline/Unicode e falha do sink.
- `ext enable/disable` pela CLI preserva todos os outros metadados e versões.
  No-op conserva bytes e inode; lease ocupado, lock inválido, temporário existente,
  symlink em `run` e qualquer entrada administrativa impedem a operação.
- Falha de auditoria após spawn e cancelamento durante o handshake mantêm os
  recursos externos até o reap confirmado do bwrap. A janela é sincronizada pela
  task de escrita, com processo real; a falha de escrita do PID também é coberta.

uv 0.12.24 foi instalado somente no Toolbx em uso. A imagem reproduzível
`localhost/fictor-dev:44` foi reconstruída de `dev/Containerfile` e tem ID
`1271d4c2dee09ae465bf835da93c4fa173174177cf5c57bc7c484ea162389654`.
Versões verificadas: Rust/Cargo 1.99.0, Node 24.18.0 LTS, npm 11.16.0,
uv 0.12.24, Python 3.14.8 e bubblewrap 0.12.0. A suíte rodou no Toolbx já em uso;
a reconstrução da imagem e sua checagem de versões foram verificações separadas.

Todos os testes usaram dados falsos e endpoints locais, sem chaves reais ou rede
externa. Nenhum workspace TypeScript/`vp` existe nesta base. Logs completos locais:
`.fictor/logs/m05-continuation-{fmt,clippy,test,release,trail-build,trail-check}.log`,
`m05-container-build.log` e `m05-container-versions.log`.

CI: `kernel_tools`, `promotion` e `extension_control` entraram na seleção Fedora
sem namespaces. Planejamento e recusa de execução de dependências fora do Toolbx
têm filtros explícitos separados. No Ubuntu nativo, casos de Node verificam
indisponibilidade do bootstrap quando aplicável; a execução real de npm/uv desta
entrega foi no Toolbx. A CI remota continua sem execução registrada.

**Estes resultados são diagnóstico no Bazzite e não satisfazem o gate no COSMIC Atomic.**
M0.5 ainda depende das ARQ-020–024 para ativação/recuperação de promoção, overrides,
limpeza geral de instâncias no boot, crash loop e sintaxe de registros. Integração
first-party e gerenciador de runtimes continuam nos marcos definidos no roadmap.

## Implementação do ADR-035 no Bazzite — 2026-10-18

Código validado: `225e3e96a090916abdf0f2c2901e26fca695dbb6`.
Execução dentro do Toolbx **`fictor-dev`, Fedora 44 x86-64**, sobre o computador
do usuário com **Bazzite 44.20261012.0 (Kinoite), SELinux Enforcing**. Mesma imagem
e versões de ferramentas do diagnóstico abaixo; caches restritos ao workspace.
Nenhum pacote foi instalado no host ou globalmente no `$HOME`.

| Verificação | Resultado |
|---|---|
| `cargo fmt --all -- --check` | Passou. |
| `cargo clippy --all-targets --locked --offline -- -D warnings` | Passou, sem avisos. |
| `cargo test --locked --offline --no-fail-fast` | **250 passaram, 0 falharam, 0 ignorados.** |
| `cargo build --release --locked --offline` | Passou. |
| `trail build` / `trail build --check` | Grafo estrutural atualizado e consistente. |
| `git diff --check` | Passou. |

A suíte completa inclui sandbox e supervisor reais. Os testes novos cobrem:

- Persistência anterior a qualquer abertura da origem, identidade inicialmente
  nula, vinculação imutável, checks e eventos atômicos, falhas de auditoria com
  rollback e erros da CLI que informam ID sem expor conteúdo ou caminhos privados.
- Limites, origem indisponível, symlinks, FIFO, nomes inválidos, manifest ausente,
  YAML inválido, tags explícitas/diretivas e schema inválido. Texto semelhante a
  tags em strings, comentários e blocos continua aceito.
- Cancelamento do chamador, retenção dos bytes quando a transição terminal falha,
  exclusão entre donos do instalador e recuperação idempotente das janelas de
  interrupção. Reconciliação do banco precede a limpeza e bloqueia admissão se falhar.
- Preservação de candidatas identificadas e estados terminais, diagnóstico de órfãos,
  limpeza ancorada em descritores sem seguir links ou atravessar bind mounts,
  nova tentativa após falha de limpeza e quarentena original inacessível no smoke.
- Migração 0003 literal do spec, preservação dos sete estados legados e de nonces,
  eventos, índices, FTS e restrições. Backup inclui commits no WAL; falha no backup
  bloqueia a migração. Recusa de schema futuro preserva banco e WAL deixado por
  subprocesso interrompido; retenção conserva o backup atual mesmo com relógio
  regressivo ou timestamps futuros.

Não houve rede externa nem chaves reais nos testes. Não há workspace TypeScript,
shell ou extensões first-party nesta base, portanto não há suítes `vp` a executar.
Logs locais: `.fictor/logs/m05-{fmt,clippy,test,release,trail-build,trail-check}.log`.
O job Fedora passou a incluir `migrations` e `proposal_recovery`; a execução remota
da CI permanece pendente.

**Este é diagnóstico no Bazzite, sem satisfazer o gate de release no COSMIC Atomic.**
M0.5 continua parcial: resolvers, promoção/ativação, sink de log, backoff e integração
first-party permanecem pendentes. A recuperação dos recebimentos não encerra a
limpeza geral de diretórios de instância no boot.

## Diagnóstico inicial do ambiente no Bazzite — 2026-10-18

Executado no computador do usuário: **Bazzite 44.20261012.0 (Kinoite), x86-64**,
SELinux **Enforcing**, Podman rootless 5.8.7 e Toolbx 0.3. Todas as ferramentas,
builds e suítes rodaram **dentro do `fictor-dev`, Fedora 44**, criado de
`dev/Containerfile`; nenhum pacote foi instalado no host nem como ferramenta
global no `$HOME`.

Base do código: `80e04ab71da8f272231a92c407e79323db1aa53e`, com as alterações
locais desta entrega ainda não commitadas. Imagem construída:
`65e9e051ef66b1905fbe70de87d8f9f6ebe52662e90a424d5ed2457299a45b2b`.

| Ferramenta | Versão |
|---|---|
| Rust / Cargo | 1.99.0, pacotes Fedora 44 |
| Node | 24.18.0 LTS |
| npm | 11.16.0 |
| bubblewrap | 0.12.0 |

Dependências foram obtidas previamente com `cargo fetch --locked`, em cache
local `.fictor/cargo`. Builds, lint e testes usaram `--locked --offline`:

| Verificação | Resultado |
|---|---|
| `cargo fmt --all -- --check` | Passou. |
| `cargo build --locked --offline` | Passou. |
| `cargo clippy --all-targets --locked --offline -- -D warnings` | Passou, sem avisos. |
| `cargo test --locked --offline` | **219 passaram, 0 falharam, 0 ignorados.** |
| `cargo build --release --locked --offline` | Passou. |

A suíte completa incluiu os testes reais de sandbox, init e supervisor, sem
desativar isolamento. A cobertura nova inclui Node Permission Model, proibição de
subprocessos, grants reais omitidos no smoke, arquivos do HOME inacessíveis ao
harness/escopo `tools`, fork duplo com `setsid()`, crash e SIGKILL do processo dono.
Também cobriu `tools.default` sem uma tool MCP desse nome, checks preservados em
falhas, cancelamento do chamador e aviso de shutdown antes da limpeza do socket.
Os providers são falsos e locais; os testes não usaram chaves reais ou rede externa.

Não há workspace TypeScript, shell ou extensões first-party nesta base; portanto
nenhuma suíte `vp` foi executada. O Trail 0.23.0, instalado apenas em
`.fictor/tools/trail`, atualizou o grafo de 47 arquivos sem passe de LLM.

Logs completos ficam localmente em `.fictor/logs/` (`container-build.log`,
`cargo-fetch.log`, `fmt.log`, `build.log`, `clippy.log`, `test.log`, `release.log`
e `trail-build.log`). A receita de criação do ambiente está no README.

**Estes resultados são diagnósticos no Bazzite, não satisfazem o gate de release.**
Não são execução no desktop COSMIC Atomic nem na CI. Os critérios completos no
Fedora COSMIC Atomic e os jobs remotos Ubuntu/Fedora continuam pendentes.

## Histórico da migração — 2026-10-17

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
Executar dentro do Toolbx na máquina COSMIC Atomic, seguindo o README e com os
caches Cargo/npm no workspace (sem instalar toolchains no host):

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
`local_checker`, `manifest`, `migrations`, `model_tls`, `models`, `proposal_recovery`,
`proposals`, `proxy` e `store`.
Ele exclui explicitamente somente o teste de bootstrap
`doctor_reports_development_runtime_status_without_modifying_config`, que chama o probe real
de sandbox. As suítes `sandbox`, `sandbox_init` e `supervisor` também dependem de
namespaces reais e ficam na execução completa do Ubuntu e do desktop. Nenhum teste
é marcado como ignorado para contornar isolamento; o Ubuntu não tem skips.

## Testes por invariante

São testes presentes no código. O diagnóstico Linux no Toolbx/Bazzite está registrado
acima; **a execução no COSMIC Atomic e na CI continua pendente**.

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
- M0.5 parcial: ativação/recuperação de promoção, overrides, limpeza de instâncias e
  backoff de crashes pendentes, conforme ARQ-020–024. Resolução, materialização e
  sink de log têm implementação e diagnóstico registrados acima; hot swap segue
  o corte de fases do roadmap.
- ARQ-001–018 foram resolvidas arquiteturalmente. Isso não representa conclusão
  das adaptações ou dos critérios de aceitação dos ADRs 025–031.
- O encerramento do ADR-029 exige confirmar a saída do bwrap antes de liberar
  recursos; fork duplo, `setsid()` e morte do core com SIGKILL exigem prova no Linux.
- A v0.1 também exige gerenciador de runtimes, compactação, login, rollback e
  roteiro de desenvolvimento de dentro do Fictor. A guarda de migração com backup
  foi implementada como pré-requisito da migração 0003.
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
  pelo ADR-035; naquela revisão, código e testes dos critérios 35–37 ainda estavam
  pendentes. Nenhuma suíte Rust ou teste de aceitação foi executado na revisão
  de arquitetura. A implementação posterior está registrada no início deste documento.

## Verificação arquitetural dos ADRs 036–040 — 2026-10-18

Base: `4d713979adce3f405a1798be565e6673f0ddc37d`, worktree isolado da branch
principal. Execução no Toolbx `fictor-dev`, Fedora Linux 44, sobre Bazzite
`44.20261012.0` (Kinoite). Diagnóstico do spec; não é gate COSMIC nem CI.

- Migrações 0001–0005 executadas em SQLite 3.51.2, bancos descartáveis em memória:
  preservados os sete estados de propostas, nonces e eventos; defaults novos
  corretos; 12 mutações inválidas recusadas, incluindo intenção pendente duplicada,
  foreign key inválida, snapshots inconsistentes, recuperação duplicada por
  sessão/global e UPDATE/DELETE de eventos. FTS, integridade e foreign keys passaram.
- Rollback de transação conservou proposta/journal; falha injetada na migração
  0004 desfez também ALTER TABLE e criação de tabela. PRAGMA FULL confirmado.
  Isso verifica o schema, não simula durabilidade física em perda de energia.
- Schema de overrides validado com a biblioteca Rust `jsonschema` já compilada
  no Toolbx: 27 casos, incluindo patches vazios/parciais, false, null, caminhos,
  chaves extras, env reservado, duplicatas, tipos e limites. A prova semântica
  de subconjunto e a integração dos consumidores continuam a cargo dos testes
  do implementador; validação JSON Schema não as substitui.
- Revisão cruzada exigiu FULL no writer e impediu sobrescrever uma chave aprovada
  com overrides diferentes. Nenhum arquivo de código ou migração antiga mudou.
- Conferidos 217 links/âncoras locais, sequência dos 46 critérios e `git diff --check`.
  Revisão independente também fixou a chave do bundle no journal de instância
  e a mensagem WebSocket do reset humano; ambas foram incorporadas.
- Critérios 38–46 descrevem os testes ainda necessários no produto. Nenhuma suíte
  Rust do core ou aceitação ponta a ponta foi executada nesta revisão arquitetural.

## Verificação arquitetural do ADR-041 — 2026-10-18

Base: `c87fba86ac68689859372723e0e0fc92eebaa799`, em worktree isolado da main.
Diagnóstico no Toolbx `fictor-dev`, Fedora Linux 44/SQLite 3.51.2, sobre Bazzite
`44.20261012.0` (Kinoite); não é gate COSMIC nem CI.

- Experimento Linux com dois descritores do mesmo diretório, por caminhos
  alternativos: o flock exclusivo recusou o segundo dono e permitiu aquisição
  depois da liberação do primeiro. Diretórios/banco eram descartáveis.
- Processo filho gravou `prepared` e `user_version=5` em WAL e terminou sem fechar
  a conexão. A leitura SQLite `mode=ro` encontrou ambos: o cabeçalho do arquivo
  principal ainda dizia versão 0, demonstrando por que não se deve ignorar o WAL.
- DELETE pela conexão read-only foi recusado e os bytes do arquivo principal
  ficaram intactos. Não se exige que os auxiliares SQLite nunca sejam tocados.
- Revisão independente definiu coordenação online/offline, formato do snapshot,
  limites e erros do canal. Nenhuma migração ou arquivo de código foi alterado;
  o experimento verifica primitivas, não a implementação futura de `ext list`.
- Revisão independente não encontrou bloqueadores na interação com os ADRs
  036/038/039 nem no contrato administrativo.
- Conferidos 156 links/âncoras locais, os 50 critérios, três exemplos JSON e
  `git diff --check`. Nenhuma migração histórica foi alterada.
- Critérios 47–50 devem virar testes do produto. Nenhuma suíte do core ou teste
  de aceitação ponta a ponta foi executado nesta revisão.

## Verificação arquitetural do ADR-042 — 2026-10-18

Base: `99989273af5949b0544a8122ca281488795bfe80`, em worktree isolado da main.
Diagnóstico no Toolbx `fictor-dev`, Fedora Linux 44, kernel
`7.2.9-ogc3.1.fc44.x86_64`, sobre Bazzite `44.20261012.0` (Kinoite);
não é gate COSMIC nem CI. Todos os arquivos do experimento eram descartáveis em `/tmp`.

- `openat2` com resolução BENEATH/NO_SYMLINKS/NO_XDEV e O_PATH/NOFOLLOW
  permitiu inspecionar arquivos regulares e recusou escape/intermediários inválidos.
  Symlink final, inclusive pendente, retornou FD do próprio link: a validação de
  tipo o recusou. Portanto não se pode depender somente de ELOOP.
- FIFO foi inspecionado sem bloqueio e recusado por tipo; hardlink foi recusado
  pelo número de links. Modos com escrita por terceiros, execução/bits especiais
  e ausência de leitura pelo dono falharam. A checagem de UID foi exercitada
  comparando fstat real a um UID esperado diferente, sem chown.
- Retargeting do alias do home não desviou o descritor ancorado. Rename sobre um
  controle preservou o inode do FD antigo, mas mudou nlink de 1 para 0 e os
  metadados observados, justificando o erro `changed` antes da devolução.
- Em namespaces novos de usuário e montagem, com identidade de namespace
  conferida antes das operações, bind mount de arquivo no mesmo dispositivo
  recebeu EXDEV. Bind do próprio diretório como raiz preservou dev/ino e
  permitiu abrir seu arquivo regular relativo. Nenhuma montagem ocorreu no host.
- Revisão independente não encontrou bloqueadores na interação com ADR-038,
  abertura/validação do mesmo objeto, erros, aliases e critérios 51–56.
- Conferidos 168 links/âncoras locais, 56 critérios consecutivos e
  `git diff --check`. Nenhum arquivo do produto ou migração foi alterado.
- Experimentos verificam primitivas Linux, não os critérios do produto. Não
  foram executadas suítes do core nem aceitação ponta a ponta; implementação,
  testes de corridas/adversários entre sessões e gate de release permanecem pendentes.
