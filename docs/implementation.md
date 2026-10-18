# Andamento da implementação

Atualizado em 2026-10-18. Fase ativa: **0**. Plataforma única: **Linux x86-64**.
Alvo de validação: **Fedora COSMIC Atomic**. Prioridade: **v0.1 autossuficiente**
([ADRs 030/031](../spec/11-decisions.md), [roadmap](../spec/10-roadmap.md)).

## Estado

“Implementado” descreve o código presente. Build e testes passaram no Toolbx Fedora 44
sobre Bazzite; o gate no COSMIC Atomic e a CI continuam pendentes. A
[verificação](verification.md) distingue esses ambientes. O
[mapa de invariantes](invariants.md) relaciona I1–I11 aos testes existentes e às
lacunas de cobertura funcional e de release.
O [caminho até a v1.0](release-path.md) reúne as etapas restantes e os gates.

Os ADRs 036–044 estão disponíveis e ARQ-020–028 estão resolvidas no spec. O produto
já aplica as migrações 0004/0005, FULL no writer, registros exatos de dependências,
snapshots de overrides, leitura protegida dos controles, IDs limitados do Kernel,
posse exclusiva do home e plano único de montagens com classificação de origens.
Promoção recuperável, barreira durável/recuperação de instâncias, proteção do
bootstrap antes do init, crash loop e listagem administrativa continuam pendentes.
Os ADRs 043/044 estão implementados parcialmente; o SDK ainda pertence ao M0.8.
Os registros anteriores abaixo descrevem os
snapshots em que foram produzidos, sem substituir este estado atual.

| Marco | Estado | Entrega e restante |
|---|---|---|
| M0.1 | Base implementada | Crate único, CLI `init`/`doctor`/`secrets`, TOML, FICTOR_HOME privado, migrações 0001–0005 e sessão `sys`. `init --first-party` aguarda instalador. |
| M0.2 | Base implementada | Writer único SQLite, pool somente leitura, eventos ULID, flags cumulativas, FTS5, forks/linhagens, blobs SHA-256 e KV. |
| M0.3 | Backend Linux; diagnóstico real no Bazzite passou | Bubblewrap e `__sandbox-init`, rede por ponte, ambiente limpo e namespace de PID. Gate no COSMIC Atomic pendente. |
| M0.4 | Base implementada | Egress autenticado, allowlist IPv6/NAT64, model proxy TLS com captura/auditoria, orçamento durável e keyring/file explícito. |
| M0.5 | Pipeline local ampliado; instalador parcial | Recebimento/recuperação, npm/uv com autoridades exatas e transporte protegido, smoke, materialização imutável, catálogo com overrides, logs e controles offline no lock. Migrações, controles protegidos, IDs do Kernel, posse exclusiva e plano de montagens disponíveis. Restam persistência dos overrides na aprovação/promoção, journal funcional, barreira/recuperação de instâncias, proteção pré-init do bootstrap, crash loop, listagem administrativa e integração first-party. |
| M0.6 | Não implementado | Política, aprovações e grants. |
| M0.7 | Não implementado | Servidor web e shell. |
| M0.8 | Não implementado | SDK, harness com compactação, fs-tools e shell-net. |
| M0.9 | Toolbx e guarda de migração preparados; runtime de uso pendente | Toolbx Fedora 44/Node 24 LTS e backup/recusa de downgrade disponíveis. Gerenciador de runtimes, login, rollback e unidade systemd de usuário pendentes. |
| M0.10 | Não implementado | Aceitação completa e roteiro de autossuficiência no Fedora COSMIC Atomic. |
| Fases 1–3 | Não iniciadas | Aguardam todos os critérios da Fase 0; corte v1.0 no roadmap. |

## Posse exclusiva e contratos de transporte/montagens (2026-10-18)

O core adquire `flock(LOCK_EX | LOCK_NB)` no próprio inode do home canônico,
privado e do usuário, antes de preparar seus descendentes ou abrir o writer.
O FD é CLOEXEC e vive em `Arc<HomeLease>`; writer, pool de leitura, capturas,
segredos e trabalhos independentes conservam a posse até terminarem. Uma mesma
posse não abre dois writers simultâneos. Os backends de segredos compartilham
um mutex da posse, sem tentar adquirir novamente o flock do mesmo diretório.
CLI ocupada falha antes de mutar; encaminhamento pelo admin ainda depende do
canal administrativo. Isso não implementa nem substitui o journal/barreira e a
confirmação de saída do ADR-038.

O Kernel mantém Number IDs como tokens JSON validados (`serde_json/raw_value`,
sem dependência nova) e String IDs como escalares UTF-8 limitados a 256 bytes.
A correlação precede autenticação/dispatch; batches não executam membros.
Respostas são serializadas com limite antes da transmissão e o fallback
`TOO_LARGE` conserva o ID. Falha de entrega não desfaz nem repete efeitos.

Um plano do core reúne reservas, aliases, modos e funções das montagens. Leituras
redundantes exigem identidade/subárvore comprovada; não removem o RW implícito de
ext_data. Fontes originais são resolvidas sem magic links. A lista fechada de
filesystems cruza nome exato de mount, fstatfs e statx da mesma FD, incluindo
submounts. Btrfs pode informar dispositivo de subvolume diferente do superbloco;
essa distinção é preservada sem confundir dispositivo com mount ID. Overlay
continua limitado às bases fixas/exceções nominais do ADR-044. A atestação final
confere objeto, topologia, filesystem e aliases. Ainda falta garantir o bootstrap
e suas bibliotecas antes da execução do init; sua própria atestação não basta.

## Migração para Linux x86-64 (2026-10-17)

O ADR-030 elimina backends, testes, CI e dependências de outras plataformas. O core
recusa compilação fora de Linux x86-64. `FICTOR_HOME` usa `$XDG_DATA_HOME/fictor`
ou `~/.local/share/fictor`, e o backend nativo de segredos é Secret Service.
O sandbox continua obrigatório; a migração não concede rede direta nem amplia
montagens para contornar restrições de isolamento.

A CI tem Ubuntu 22.04 x86-64 com a suíte completa e container Fedora 44 com build
e testes sem sandbox real. Actions permanecem fixadas por SHA. A versão do container
segue a [release estável oficial do COSMIC Atomic](https://fedoraproject.org/atomic-desktops/cosmic/download/)
consultada em 2026-10-17; conferir o SO instalado ao continuar no desktop. Nenhum
job remoto foi executado nesta entrega. Resultados anteriores fora da plataforma
atual deixam de ser evidência. Naquela entrega, a formatação e o diagnóstico cruzado
de tipos/Clippy para Linux x86-64 passaram, sem execução de binário ou testes Linux.
Os diagnósticos posteriores no Toolbx/Bazzite estão em `verification.md` e também
não substituem o gate no COSMIC Atomic.

Aliases de caminhos Atomic, certificados/NSS e proteções de credenciais/persistência
foram ajustados no launcher. O ambiente Toolbx e a guarda de migração fazem parte
do roadmap atualizado; a retirada de código de outras plataformas não
encerra esses marcos. `.fictor/` fica fora do Git para os caches locais do workspace,
conforme ADR-031. O fluxo de Git segue a coordenação registrada abaixo;
instalação do novo core e reinício do serviço são ações do usuário, fora do sandbox.

## Fluxo de Git

Definido pelo usuário em 2026-10-18:

- Implementações destinadas ao projeto são feitas e commitadas diretamente na `main`.
- Branches ficam reservadas a testes exploratórios descartáveis, sem entrega
  planejada de volta à `main`.
- Somente o agente principal executa commits, merges e demais operações Git do projeto.
  Agentes delegados editam arquivos e reportam resultados para integração.
- O Arquiteto edita somente os arquivos de arquitetura. O implementador integra
  e versiona essas edições, preservando a autoria das decisões normativas.

## Detalhes internos

- O SQL das migrações é cópia literal do spec, verificada por teste. Escritas,
  geração de ULID e reserva de orçamento passam pela task única do writer. Leituras
  usam conexões separadas somente leitura; reabrir respeita o maior ULID persistido.
- O store rejeita workspace relativo, inexistente, raiz `/` ou sobreposto ao
  FICTOR_HOME. Arquivos privados novos usam 0600 e diretórios 0700. Identidade,
  escopos, namespaces e proveniência são derivados pelo core, não pelo payload.
- O sandbox usa bubblewrap com `__sandbox-init` como PID 1, rede isolada e `/tmp`
  privado. Proxy e Kernel Protocol ficam em sockets privados no host, expostos à
  instância por TCP loopback em 3128/3129. Listeners são reservados antes do workload.
  Node usa Permission Model, inclusive bloqueio de subprocessos quando `spawn: false`.
  Bloqueio de `execve` por seccomp para os demais runtimes permanece na Fase 3.
- Montagens que se sobrepõem a caminhos sensíveis são recusadas. Descoberta usa
  ambiente e `gpgconf --list-dirs`, com prazo limitado e sem iniciar agentes.
- O egress resolve uma vez, valida todos os IPs e conecta somente aos aprovados.
  IP literal, localhost e destinos não públicos exigem host exato e porta explícita.
  IPv6 segue ADR-021; prefixos NAT64 configurados seguem RFC 6052/ADR-023 e o /48
  local é não público. `doctor` só sugere prefixos, sem mudar política.
- Tokens revogados encerram túneis. Negações são agregadas por instância/host/porta/minuto
  UTC e descarregadas para `sys`; falha de auditoria fecha o proxy. Encerramento
  abrupto pode perder o bucket em memória, conforme risco registrado.
- Providers HTTP só usam loopback literal autorizado. Model proxy reserva orçamento
  antes da conexão, captura request antes de enviar e response antes de entregar
  cada frame. Limites: request 64 MiB, response 256 MiB, quatro admissões simultâneas.
  Falha de captura/auditoria encerra o canal; outcome e resposta parcial são explícitos.
- Segredos têm backend explícito `keyring`/`file`, sem fallback. Arquivo schema 1
  exige dono próprio e modo 0600, com escrita atômica. Erros/Debug não expõem valores.
  Redaction cobre tracing e stderr incremental, inclusive valores multiline.
- Dependências de suporte: `libc`/`getrandom` para processos/tokens; Hyper para HTTP;
  `rustls`, `tokio-rustls` e `rustls-platform-verifier` para TLS/confiança do sistema;
  `rpassword` para TTY sem eco. Não há terminação TLS para injeção de segredos genérica.

## Base do M0.5

- Recebimento local usa dirfds/openat sem seguir symlinks, rejeita arquivos especiais
  e detecta alterações da fonte. Limites constantes do ADR-024 contam enquanto
  percorrem, antes de ordenar. Paths UTF-8, colisões NFC/minúsculas, modos normalizados
  e hash bytewise são verificados; dependências ignoradas no recebimento são listadas.
- YAML vira JSON limitado antes do schema embutido. Duplicatas, tags, expansão,
  profundidade, ambiente reservado e grants incompatíveis com mediação são bloqueados.
  Schemas de argumentos não resolvem `$ref` de rede ou filesystem. Dependências:
  `serde_yaml_ng`, `jsonschema` sem download, `serde_json_canonicalizer` (RFC 8785) e
  `unicode-normalization` para colisões de nomes.
- MCP usa [rmcp 3.5.1](https://docs.rs/rmcp/3.5.1/rmcp/) em stdio. Anuncia roots da
  sessão, sem sampling/elicitation. Inicialização, catálogo e resources do smoke
  compartilham prazo de 15 s. Catálogo é fixado por hash; notificação suspende chamadas
  e divergência desativa/audita. Frames/paginação/bytes são limitados e argumentos
  passam pelo schema antes do RPC. Campos que o SDK perderia são recusados.
- Kernel tem socket por instância 0600 em `run/k` 0700, token aleatório, hello com
  protocolo obrigatório, quatro conexões e frames de 16 MiB. Leitura de forks respeita
  o corte ancestral. KV é `ext_id@session_id`; config lê só tabela própria e IDs/URLs
  opacos de providers. Rotas de fases futuras retornam erro explícito.
- Supervisor revalida manifest/ambiente no spawn e registra valores na máscara antes
  de iniciar. Runtime nativo dentro do store só pode ser o executável do próprio bundle.
  Logs rotacionam em 10 MiB; crash tem cauda em blob. Encerramento revoga tokens e deve
  confirmar saída do bwrap antes de liberar recursos (ADR-029); sem confirmação em
  10 s, reter recursos e reportar `cleanup_failed`. A confirmação usa a saída do
  bwrap (namespace de PID), sem depender de grupos POSIX. Testes no Toolbx/Bazzite
  cobrem fork duplo, `setsid()`, crash e SIGKILL do processo dono do supervisor.
  O journal de identidade e a prova adicional de término do PID 1 exigidos pelo
  ADR-038 ainda precisam ser implementados.
- Smoke usa bundle, workspace, ext_data, configuração, Store e proxies descartáveis,
  sem acesso a credenciais/providers reais; segredos declarados viram honeytokens.
  ADR-028 exige omitir grants absolutos/`~/` e exibi-los na revisão. ADR-027 define
  runtime/MCP/papel. ADR-025 recusa processos globais na Fase 0. A integração desses
  contratos deve ser conferida nos testes Linux, sem antecipar mediação da Fase 1.
  A recusa `phase:global`, SemVer completo e combinações de runtime/MCP/papel foram
  ajustadas. O smoke agora omite grants absolutos/`~/` no manifest clonado; o original
  e a lista de omissões permanecem nas checagens da proposta (ADR-028).
  `permissions.toolchains` foi removido conforme ADR-034.
- Propostas têm transições e eventos `ext.*` na mesma transação. Aprovação/rejeição
  exigem nonce humano rotacionado, omitido de JSON/Debug. O lock schema 1 valida paths,
  ausência de symlinks e tools_hash; escreve arquivo privado com exclusão, fsync e
  rename. A escrita ainda não está ligada à promoção.
- `ext check` permite `binary`/`none` e Node sem dependências a instalar; npm/uv
  falham antes de executar quando precisam de resolver. `tools.default` é apenas
  classificação padrão, sem exigir uma tool MCP com esse nome. Checks aprovados
  continuam em quarentena. Falhas identificadas preservam os checks; cancelar o
  chamador não cancela o worker do core. Falhas antes da identidade e recuperação
  após morte do processo seguem o ADR-035: tentativa durável antes da origem,
  identidade vinculada após validar, falhas estáveis e limpeza após o commit.
- Kernel `log` usa o sink do supervisor. `tools.list` lê definições fixadas no lock,
  respeita a sessão e filtra hooks/tools ocultas. `tools.call`, hooks, UI, timers e
  aprovação aguardam seus marcos; nenhuma rota incompleta simula sucesso.

## Continuação do M0.5 — 2026-10-18

- O resolver usa uma home descartável com banco, configuração, workspace e proxy
  próprios. Um bootstrap fixo do core roda pelo supervisor normal; a candidata é
  copiada para `${ext_data}` gravável. Nenhuma quarentena, credencial ou dado real
  é montado no processo de instalação. O proxy permite apenas registros exatos
  configurados; wildcards são recusados até o ADR da ARQ-024.
- npm roda `ci --ignore-scripts --bin-links=false`, sem audit/fund, com cache em
  `/tmp` e retries de fetch desativados. O Node restringe filesystem e subprocessos.
  uv exige hashes e recusa builds, configuração externa e download de Python.
  `requirements.lock` é obrigatório para dependências Python; não há export
  automático de `uv.lock`. Node/npm, uv e Python fixos em `/usr` são bootstrap de
  desenvolvimento no Toolbx, até o gerenciador de runtimes de M0.9.
- O orçamento de 600 s cobre resolução e inspeção final. Só as árvores
  `node_modules`/`.pydeps` inspecionadas voltam à quarentena; manifest, código e
  lockfiles originais devem conservar bytes e modos. Hash final e inventário real
  de pacotes são persistidos com os checks. Sem resolver configurado, a API
  interna recusa dependências; a CLI `ext check` configura o resolver explicitamente.
  O prazo envolve também inicialização e handshake de lançamento. Jobs bloqueantes
  e a task de setup mantêm a posse dos temporários e do lease mesmo após timeout.
  Saída livre de npm/uv é descartada para não persistir credenciais embutidas em
  URLs/configurações de pacotes; os checks usam motivos estáticos do core.
- A materialização aceita apenas propostas `approved` por humano, com checks
  completos. Copia, verifica hash e manifest e congela arquivos 0444/0555 e
  diretórios 0555. Linux exige escrita na raiz para mover entre pais; por isso a
  cópia já verificada passa por staging privado no pai do store, congela a raiz
  e publica a chave final por rename no mesmo pai com `RENAME_NOREPLACE`.
  Colisões só são reutilizadas se hash completo, manifest e modos coincidirem.
  Essa API preserva lock, proposta, eventos, processos e quarentena original.
  Falha após entrar no store retém os bytes; recuperação/ativação aguarda ARQ-020.
- O registro lê manifest imutável e catálogo da versão ativa habilitada. Usa
  classificação nominal, senão `default`, senão restritiva; annotations MCP não
  concedem classificação. A resposta é contada como JSON UTF-8 escapado durante
  a acumulação, com teto do Kernel Protocol de 16 MiB. Estado inválido e overrides
  não vazios falham explicitamente (ARQ-021), sem catálogo parcial.
- Notificações `log` só são aceitas após autenticação e não têm resposta. Nível,
  mensagem e objeto de campos são validados. O destino usa identidade vinculada
  pelo supervisor, redator atualizado a cada entrega e rotação de 10 MiB no mesmo
  arquivo do stderr. Logs estruturados não entram na cauda de stderr dos crashes.
- O supervisor reserva o arquivo de PID antes do spawn e entrega falhas posteriores
  ao worker dono do processo. A resposta de erro de lançamento aguarda o reap e a
  limpeza; cancelamento durante a auditoria não libera os recursos. Um owner opaco
  permite que o resolver retenha home e lease sem alterar grants ou entradas do
  processo. Falha de confirmação conserva recursos conforme ADR-029.
- `ext enable/disable` com o core parado altera somente `enabled`. O lease cobre
  leitura e escrita atômica; qualquer entrada `admin.sock` recusa a operação sem
  removê-la. No-op preserva bytes e inode. O servidor futuro deve compartilhar a
  admissão e implementar o caminho administrativo. Não há reset de crash loop
  implícito nesses comandos (ARQ-023).

## Catálogo e correções de integração — 2026-10-18

- `catalog.list` exige escopo, parâmetros exatos e a própria sessão existente.
  Lê somente versões ativas habilitadas, compartilhando com `tools.list` a
  validação de identidade do manifest e a recusa de overrides indefinidos.
  Retorna skills e comandos com caminhos absolutos; surfaces e hooks da Fase 1
  ficam vazios, e declarações dessa fase são recusadas.
- Skills usam o diretório configurado ou `skills/`, com subdiretórios imediatos
  contendo `SKILL.md`. O frontmatter segue o [Agent Skills](https://agentskills.io/specification)
  e seu validador de referência, consultados em 2026-10-18. Somente nome e descrição
  entram no catálogo; corpo Markdown e prompts não são interpretados nem executados.
  Metadados opcionais, inclusive `allowed-tools`, não concedem permissões.
  A leitura usa descritores, recusa symlinks, tipos especiais e arquivos graváveis,
  e preserva os limites por bundle do ADR-024. A resposta conta JSON escapado
  cumulativamente antes de reter entradas, respeitando os 16 MiB do protocolo.
- O inventário npm agora exige correspondência entre raízes físicas de pacotes
  e o [hidden lockfile](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/#hidden-lockfiles).
  Tarballs com `node_modules` aninhado não declarado são recusados antes do smoke.
  Pacotes bundled, scoped e aninhados legítimos continuam aceitos; um
  `package.json` comum dentro de fixtures não cria um pacote no inventário.
- A identidade Python segue os headers de [Core Metadata](https://packaging.python.org/en/latest/specifications/core-metadata/):
  nomes dos campos sem distinção de case, whitespace e continuação de linha.
  `Name` e `Version` continuam obrigatórios, únicos e sem whitespace no valor
  final. Testes da CLI reproduzem a falha anterior e verificam ambas as correções.
- Antes de criar dados, grants ou processos, o supervisor exige sessão ativa,
  não sistêmica, cujo workspace persistido coincida com o caminho canonicalizado.
  Isso vale também para processos MCP sem canal kernel e para a sessão isolada
  de smoke. Sessão inexistente, arquivada ou workspace divergente são recusados.
- Capturas de streaming mantêm `flock` compartilhado em um descritor independente
  do diretório privado de blobs. A limpeza de boot exige bloqueio exclusivo sem
  espera; abrir outra `Store` com captura ativa falha antes de remover temporários.
  O lease dura até persistência e fsync, ou até descartar o temporário, e não cria
  formato persistido novo. Duas capturas simultâneas conservam leases independentes.
  O teste de reabertura falhava antes da correção; capturas, órfãos e streaming
  completo são verificados em testes automatizados.
- Fixtures de controle offline são serializados dentro do próprio alvo de teste.
  Isso impede que o fork de outra CLI retenha temporariamente descritores de
  leases de um teste vizinho. O teste de exclusão e as assertions continuam
  exigindo a recusa; não há retry nem alteração do runtime de produção.

O gerenciador lazy/idle permanece sem integração: os consumidores `tools.call`,
hooks e `session.input` ainda não existem nesta base; aplicar overrides e definir
reinício/crash loop depende das ARQ-021/023. Não há timers ou caminhos alternativos
que contornem esses contratos pendentes.

## Limites de leitura e revisão do inventário — 2026-10-18

- As leituras do Kernel Protocol contam o JSON escapado de KV e eventos antes
  de reter cada entrada, incluindo wrappers, vírgulas e o booleano `truncated`.
  Ao atingir 16 MiB, retornam `TOO_LARGE` sem resultado parcial nem decodificação
  das linhas seguintes. Os limites de quantidade, autorização, linhagem e ordem
  permanecem os mesmos. As APIs gerais do Store conservam sua semântica; só os
  caminhos usados pelo Kernel recebem esse orçamento de resposta.
- `blobs.get` considera a expansão base64 antes de carregar o arquivo. A leitura
  exige que o tamanho do descritor caiba no orçamento e usa `take(limite + 1)`
  para cobrir crescimento concorrente; nunca retorna prefixo ou dispensa o hash.
  Blobs de até 256 MiB continuam disponíveis ao restante do core.
- `config.get instructions` limita a leitura do `AGENTS.md` global antes de
  carregar ou decodificar o arquivo. Ausência continua retornando `null`, texto
  válido permanece intacto e a serialização final também limita o JSON escapado.
- A materialização compara o inventário atual da cópia privada com os pacotes
  aprovados. Checks antigos e hash correto não bastam quando a lista de revisão
  omite pacotes físicos ou informa versões divergentes. Não há nova resolução,
  rede, execução de código nem alteração da proposta. Um único prazo cobre cópia,
  inspeção, inventário, congelamento e verificação de uma versão já publicada.
- A invalidação terminal do catálogo MCP é ligada ao dono do processo. Divergência
  inicial ou durante a execução cancela o MCP, revoga kernel/proxy e encerra o
  sandbox. A task dona confirma o reap e tenta registrar `ext.tools_changed`
  antes do evento de encerramento, mantendo a posse dos recursos nesse intervalo.
  Suspensão temporária durante a confirmação de uma notificação idêntica não
  encerra a instância. Não há task observadora separada nem alteração do lock.
  Reutilizar a conexão com `Some(pin)` exige o mesmo pin usado na sua criação;
  fixar depois da descoberta sem pin ou trocar o hash encerra a instância.
  O bloqueio persistente da extensão e a integração com o gerenciador continuam
  pendentes; essa correção não declara o critério 13 completo.

`fictor ext list` não foi exposto: o texto sobre comandos disponíveis sem servidor
exclui a listagem, enquanto a tabela a prevê na Fase 0. A ARQ-025 registra a
contradição e pede esclarecer intenção no lock versus saúde de processos e o
caminho administrativo, se necessário. Nenhum comando offline ou protocolo novo
foi presumido.

## Cancelamento e arquivos de controle — 2026-10-18

- O handshake MCP tem um guard local armado antes de retirar os pipes da
  instância. Cancelar o future, mesmo conservando `ManagedInstance`, solicita
  encerramento à task dona. O guard só é desarmado após publicar a conexão e
  seu pin. Não há segunda task de cleanup, tentativa automática de reconexão ou
  liberação de recursos antes do reap. O encerramento é voluntário e gera
  `ext.stopped`, sem inventar mudança de catálogo ou crash.
- Uma chamada MCP com cancelamento já ativo, ou sem o dono do canal de
  cancelamento, retorna `Cancelled` antes de enviar `tools/call`. O servidor não
  recebe uma operação seguida de uma tentativa tardia de desfazê-la. Chamadas
  efetivamente enviadas continuam recebendo `notifications/cancelled` com o ID
  correspondente, conforme a [referência MCP de cancelamento](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation),
  consultado em 2026-10-18; uma notificação não referencia chamada nunca emitida.
- Leituras de configuração disparadas pelo Kernel exigem arquivo regular antes
  de abrir, usam `O_NONBLOCK|O_CLOEXEC` e conferem novamente o descritor. Isso
  impede que FIFO, dispositivo ou diretório prendam um worker bloqueante, inclusive
  quando acessados por link. Links para arquivos regulares continuam funcionando;
  limites de bytes, UTF-8, ausência opcional de instruções e filtro da própria
  tabela de extensão permanecem. O parser TOML é compartilhado, sem cópia de sua
  regra no Kernel.

A ARQ-026 registra separadamente a proteção dos destinos de links dos arquivos
globais. Exigir arquivo regular não garante autoria humana se o destino for
gravável por extensão. A política para esses destinos e sua interação com grants
e proveniência aguardam ADR; não foi criada exceção a I11 nem alegada proteção
de origem que a checagem de tipo não oferece.

## Prazos de chamadas MCP — 2026-10-18

- `McpConnection::call` mantém um único prazo, contado desde a entrada e limitado
  a 600 segundos. Validação, espera por espaço na fila do SDK e resposta usam o
  mesmo orçamento. O timer do SDK foi substituído porque começava depois da fila
  e podia aguardar indefinidamente a escrita da notificação de cancelamento.
- Cancelar antes de obter um handle da requisição não emite notificação MCP.
  Depois de obter o ID, a tentativa de `notifications/cancelled` usa no máximo
  100 ms do prazo restante. Se ele já venceu, o core faz um único poll para
  enfileirar a notificação, sem esperar sua escrita. Entrega é best effort quando
  o transporte está bloqueado; não há retry nem task separada de cancelamento.
- O receptor de cancelamento aguarda valor verdadeiro ou o fechamento do canal;
  atualizações com valor falso não cancelam a chamada. Testes com escrita
  controlada e fila saturada reproduzem os bloqueios sem serviços externos.

## Provas de isolamento no supervisor — 2026-10-18

- O cenário local do critério 5 usa uma extensão nativa compilada no teste e um
  provider HTTP em loopback. A credencial falsa aleatória fica só no SecretStore
  e no model proxy; não entra no binário, argumentos ou ambiente do probe. O
  upstream confirma sua injeção; o cliente recebe somente o payload público.
  Observações de ambiente, árvores de fixture (`workspace`, `${ext_data}`, tmp),
  descritores regulares e memória própria são procuradas pelo host. Há controles
  distintos, incluindo canário criado em heap durante a execução e arquivo
  desvinculado mantido em FD igual ou maior que 128. Os dumps são limitados e
  falham em erro inesperado ou limite excedido; não observam todos os arquivos
  do host nem todos os runtimes. Mapas VVAR e sem permissão de leitura são
  contabilizados explicitamente.
- O cenário local do critério 16 inicia duas instâncias simultâneas do mesmo
  `ext_id`, com sessões diferentes. Cada uma grava a mesma chave KV e o mesmo
  nome de arquivo, com canários distintos. B vê estado inicial vazio e não lê
  o caminho real de A; após B encerrar, A conserva seus valores e não lê o
  caminho real de B. As chamadas KV passam pelo Kernel TCP do próprio sandbox;
  a única concessão de filesystem é `${ext_data}` da instância.
- O teste de cancelamento da recuperação estaciona o writer por canal e confirma
  a entrada nessa barreira antes de cancelar o chamador. O bloqueio SQLite usado
  anteriormente podia devolver `DatabaseBusy` imediatamente durante a promoção
  de leitura para escrita, liberando legitimamente o lease antes da asserção.
  Agora a verificação ocorre com trabalho realmente pendente; a barreira é
  liberada antes das asserções e também pelo Drop do sender em caso de unwind.
  A implementação produtiva de recuperação e lease não mudou.

## Próxima sequência no Fedora

1. Repetir build, Clippy e suíte completa no COSMIC Atomic e conferir CI Ubuntu/Fedora;
   os diagnósticos no Bazzite constam em [verification.md](verification.md).
2. Completar M0.5, incluindo aplicação/testes dos ADRs 036–044 e dos requisitos Atomic;
   promoção recuperável, overrides, posse/limpeza de instâncias, crash loop,
   registros exatos, listagem administrativa e origem protegida dos controles.
   Recebimento, resolução, materialização, listagens do Kernel e logs já têm
   implementações e testes. Aplicar os ADRs 043/044 para correlação de IDs e fronteiras de montagens; os critérios novos ainda exigem testes do produto.
3. Integrar `init --first-party` ao mesmo pipeline. `ext check` não substitui instalação.
4. Seguir M0.6–M0.10 e os **65 critérios da Fase 0**, incluindo autossuficiência,
   antes de iniciar a Fase 1.

ARQ-001–018 estão resolvidas pelos ADRs 013–029. Resolução arquitetural não implica
implementação nem release concluída. A ARQ-019 foi resolvida pelo ADR-035 em
2026-10-18, com recebimento e recuperação implementados em M0.5; consulte
[architect-pending.md](architect-pending.md).

ARQ-020–028 foram resolvidas pelos ADRs 036–044; a implementação restante segue
com o dev. `spec/` permanece sob autoria do arquiteto, e somente o dev integra e
commita as alterações. O ADR-043 fixa admissão de IDs e falha de transporte sem
correlação inventada; o ADR-044 fixa reservas de destinos e origens de mounts.
O limite de 16 MiB e as invariantes permanecem.

## Recebimento durável — ADR-035

- Uma tentativa é commitada com identidade nula antes de qualquer acesso à origem.
  O writer revalida o manifest normalizado ao vincular a identidade na transição
  `received → checking`; depois disso, a identidade é imutável. Falha, checks e
  evento são gravados na mesma transação, com motivos finitos definidos pelo core.
- O recebimento cria `.receipt-<ULID>` sem sobrescrever. A publicação da cópia
  usa `renameat2(RENAME_NOREPLACE)` e fsync antes de vincular a identidade. Uma
  falha só libera os bytes após confirmar a transação terminal; erro de persistência
  informa o ID e conserva os bytes sem afirmar que a transição ocorreu.
- Um `flock` exclusivo no diretório privado de quarentena impede que dois donos
  recuperem ou instalem simultaneamente. O worker pertence ao core e conserva o
  lease ao atravessar tarefas bloqueantes, mesmo após cancelar o chamador.
- A recuperação primeiro encerra todas as tentativas interrompidas numa transação
  do writer. Só então remove recibos reconhecidos, ancorada em descritores, com
  `openat2` e `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV`.
  Falhas de limpeza geram diagnóstico e nova tentativa no próximo boot; falha de
  reconciliação no banco impede a admissão. Candidatas identificadas e estados
  terminais são preservados. A limpeza geral de instâncias continua pendente.
- O preflight SQLite é somente leitura e recusa versões futuras antes de abrir
  conexão gravável, inclusive quando há WAL de um core mais novo interrompido.
  Migrações usam a feature `backup` da dependência existente `rusqlite`, para
  incluir commits no WAL. A publicação privada é atômica e retém a cópia recém-criada
  mais duas anteriores, mesmo com timestamps futuros ou relógio regressivo.
  Falha no backup impede a migração. Isso é pré-requisito da migração 0003;
  não encerra o gerenciador de runtimes ou o rollback de M0.9.
- `unsafe-libyaml`, já transitiva e fixada no lockfile, é dependência direta para
  examinar tokens antes da desserialização: `serde_yaml_ng` descarta certas tags
  globais. Tags explícitas e diretivas são recusadas; texto semelhante em strings,
  comentários e blocos permanece válido. O scanner tem RAII e entrada limitada
  pelo mesmo teto de bytes do manifest. Nenhum novo pacote foi instalado no host.

## Ambiente e escolhas de desenvolvimento em 2026-10-18

- `dev/Containerfile` parte de `registry.fedoraproject.org/fedora-toolbox:44`.
  Usa os pacotes Fedora `nodejs24-bin`/`nodejs24-npm-bin`, pois os nomes genéricos
  selecionam Node 22 nessa imagem. Rust, GCC, Git, bubblewrap e ripgrep ficam no
  container. uv também faz parte da imagem; a base fornece Python 3. Caches
  Cargo/npm ficam em `.fictor/`; nenhum pacote foi instalado no host.
- Configuração segue fontes tipadas `nodejs`/`github-release`. Deno e configurações
  antigas de toolchains foram removidos (ADRs 033/034). Até M0.9, runtimes de
  desenvolvimento vêm de caminhos fixos em `/usr/bin`, somente dentro do Toolbx;
  não há fallback para executáveis arbitrários do PATH ou configuração.
- O launcher concede os caminhos Node individualmente e mantém os argumentos da
  extensão depois de `--`. Addons/WASI permanecem proibidos. No Node 24, a rede
  continua confinada pelos namespaces e proxy; `--allow-net` só se aplica às
  versões cujo Permission Model também restringe rede, conforme o spec.
- Harnesses e clientes com escopo `tools` não recebem `sandbox.home_ro_files`:
  o limite específico de arquivos da I11 prevalece sobre a opção geral de sessão.
- O Trail 0.23.0 foi instalado localmente em `.fictor/tools/trail`, sem scripts
  de instalação, para atualizar `.trail/cache/` com `trail build`. É ferramenta
  de contexto do agente, sem dependência no produto, sem instalação global e sem
  passe de LLM. Os cards existentes foram usados antes das leituras de código.

## Contratos arquiteturais liberados em 2026-10-18

ARQ-020–024 resolvidas pelos ADRs 036–040: promoção recuperável, overrides
humanos, posse/recuperação de instâncias, crash loops e fronteira dos registros de dependências. Migrações normativas
0004/0005, schema de overrides e critérios 38–46 estão no spec. Este registro
foi incorporado à `main` junto ao código do implementador. As migrações 0004/0005
já são aplicadas pelo produto; o journal de promoção e a recuperação de crash loops
ainda precisam de seus fluxos funcionais.

ARQ-025 resolvida pelo ADR-041: `ext list` consulta configuração online/offline
sem afirmar saúde; leitura coordenada com o journal e canal administrativo mínimo
definidos. Critérios 47–50 aguardam implementação e testes do produto.

ARQ-026 resolvida pelo ADR-042: origem protegida dos arquivos de controle,
validação por descritor e recusa de aliases que exponham a árvore privada.
Erros de `config.get`, ausência e tratamento do legado estão definidos; critérios
51–56 têm implementação parcial abaixo. Nenhum reparo de dados do usuário é automático.

## Base durável dos ADRs 036/039

O runner aplica as migrações literais 0004/0005 na mesma transação e preserva
recibos, nonces e eventos anteriores. O backup privado inclui o WAL e conserva o
schema anterior; falha de backup ou de qualquer migração impede a atualização.
Versões futuras continuam recusadas antes de abrir conexão de escrita.

Cada conexão de escrita do produto confirma `synchronous=FULL` antes da primeira
transação, inclusive a conexão de destino da API de backup. A task do writer
confirma novamente o valor antes de executar cada operação; uma mudança inesperada
recusa a operação, sem reparo silencioso. O comentário histórico de 0001 permanece
literalmente igual ao spec; os pragmas atuais são responsabilidade do runner.

Os testes dirigidos de migrações, bootstrap e orçamento passaram: **28 testes
no Toolbx Fedora 44 sobre Bazzite**. Cobrem rollback conjunto de 0004/0005,
constraints do journal e dos escopos de crash, recusa de escrita após perda de FULL,
backup/restauração de dados e imutabilidade dos eventos. Isso verifica o protocolo
SQLite escolhido, sem simular uma perda física de energia. A existência das tabelas
não encerra a promoção recuperável nem a supervisão de crash loops.

## Registros de dependências — ADR-040

`Config::parse` normaliza autoridades exatas e o resolver confere novamente a
lista inteira antes de criar o ambiente descartável. Porta omitida permanece
omitida; wildcard, URLs, IP/localhost sem porta e a rota interna de modelos são
recusados. A allowlist usa a validação existente de DNS/IP/NAT64 do proxy, sem
somar permissões da candidata nem destinos descobertos em redirects.

Dois testes reais reproduziram uma configuração `.npmrc` da candidata removendo
o proxy e outra desabilitando a validação TLS. O bootstrap agora fixa proxy,
`noproxy`, `strict-ssl` e arquivos globais/usuário descartáveis em flags npm de
maior prioridade. A configuração não executa scripts nem recebe credenciais do
host. Testes npm/uv com servidores locais cobrem redirects por porta/alias,
integridade, configuração hostil e recusa de certificado inválido.

`net.denied` registra a porta numérica junto do host; o agrupamento conserva
destinos com portas distintas. Esse detalhe interno cumpre o diagnóstico exigido
pelo ADR sem registrar URL, query, userinfo ou cabeçalhos. Dependencies (19),
local checker (14) e proxy (10) passaram no Toolbx Fedora 44 sobre Bazzite;
logs locais `adr040-dependencies-local-final.log` e `m05-contracts-store-tests.log`.

## Origem dos controles — base do ADR-042

Boot e releituras de `config.toml`/`AGENTS.md` usam `ControlFiles`: home canônico
ancorado em descritor próprio, UID efetivo e modo 0700. `openat2` exige resolução
beneath, sem symlinks nem travessia de mounts; ausência dessas garantias recusa
a operação. O core inspeciona um FD `O_PATH` antes de abrir o inode regular para
I/O, exige um único link e modos admitidos e compara seus metadados antes/depois
da leitura limitada. Nenhum descritor de controle é herdado pelo workload.

Alias inicial do home é permitido; retargeting não muda o descritor já retido
pelo Kernel. Ausência real de AGENTS é `null`; UTF-8/TOML inválido, links,
origem insegura e mudança observada não fornecem conteúdo nem defaults. Providers
conserva o snapshot do boot e strings de `[ext]` continuam opacas.

Os erros do protocolo preservam códigos/mensagens e acrescentam somente
`data.reason` e `data.file`, com nome lógico fixo. Excesso mantém `TOO_LARGE`.
`init` publica configuração nova 0600 por fsync/rename sem sobrescrita; diretórios
e controles existentes são validados, sem chmod/chown ou reparo automático.

Passaram 31 testes dirigidos no Toolbx Fedora 44 sobre Bazzite: primitiva (7),
integração de controles (4), limites/releituras do Kernel (7) e bootstrap (13).
A proteção de aliases de montagem foi integrada conforme a seção abaixo.
Nesta entrega, os limites de política da ARQ-028 ainda estavam abertos. O ADR-044
agora os define; sua implementação e o gate completo dos critérios 51–56 continuam pendentes.

## Overrides humanos — base do ADR-037

`Overrides` conserva o JSON esparso validado, sem inserir folhas ou defaults
ausentes. O parser recusa campos/nomes desconhecidos, duplicatas e valores fora do
schema; folhas explícitas exigem decisão humana. O lock admite ausência legada
como patch vazio, preservando exatamente os patches novos ao gravar/reabrir.

`resolve` produz um snapshot de permissões e classificações efetivas. Listas são
subconjuntos das declarações originais, com rebaixamento de escrita para leitura;
env e bindings de segredos não aceitam novos valores. Classificações aplicam base,
patch default e patch nominal, conservando os pisos estáticos de rede/modelos e
hooks. Gateway, catálogo e `spawn_effective` consomem o snapshot; o catálogo MCP
original permanece intacto para o pin da conexão. O supervisor e o proxy validam
novamente as permissões no contexto NAT64 do boot antes de executar.

Passaram 25 testes dirigidos no Toolbx Fedora 44 sobre Bazzite: overrides (6),
lock (7), registry (6), catálogo (5) e um teste real do supervisor. Este último
compara um controle positivo com a remoção de env/segredo/modelos/rede/spawn e o
rebaixamento do workspace para leitura. A persistência do patch junto da aprovação
na proposta e a publicação pelo journal ainda fazem parte da promoção pendente;
a política contextual do M0.6 continua fora desta entrega.

## Aliases e conferência das montagens antes do workload

A validação compara as fontes em coordenadas do filesystem obtidas de mountinfo,
incluindo bind mounts e submounts visíveis. A identidade dev/ino real fica separada
dessas coordenadas porque OverlayFS pode reportar dispositivos diferentes para
arquivos e para seu mount. O home é fixado por FD; substituí-lo não autoriza outro
inode. Isso não implementa a posse exclusiva do ADR-038.

O mesmo conjunto de FDs `O_PATH` validado produz a prova dos binds. Os FDs ficam
CLOEXEC no core e são retidos até o reap; a prova interna contém somente caminhos
e identidades, limitada a 64 KiB. O renderer compõe a topologia final respeitando
binds aninhados; fontes opcionais ausentes não são incorporadas se aparecerem
depois. `__sandbox-init` exige e confere a prova antes dos listeners/workload,
sem repassá-la aos argumentos ou ambiente da extensão. Troca de fonte ou submount
desconhecido aborta antes de executar a extensão.

O launcher fixo `unshare --user --map-root-user --mount --propagation private --`
precede bubblewrap, sem fork adicional. Isso impede que binds recebam montagens
posteriores do namespace externo; somente a propagação slave usada por
[bubblewrap](https://github.com/containers/bubblewrap/blob/v0.6.1/bubblewrap.c)
não oferecia essa garantia. `util-linux` é dependência explícita no Containerfile
e na CI, já presente no Toolbx usado; nenhuma ferramenta foi instalada no host.
O perfil de rede, os grants e a remoção de capacidades do workload são mantidos.

Passaram 18 testes dirigidos finais de sandbox/sandbox-init no Toolbx Fedora 44
sobre Bazzite. Incluem binds/submounts da árvore privada, raiz do home montada,
exceções próprias legítimas e seis cenários tardios após construir o Command:
controle seguro aninhado, fonte trocada, submount novo e provas inválida, ausente
e excessiva. Topologia coberta que não possa ser observada falha conservadoramente.
A política antes pendente na ARQ-028 foi definida pelo ADR-044; aplicar reservas
e tipos de origem ao plano/prova existentes ainda é trabalho do implementador.

## Contratos de IDs e montagens — ADRs 043/044

ARQ-027/028 resolvidas no spec em 2026-10-18. O Kernel deve preservar IDs admitidos,
recusar excesso antes de dispatch e tratar resposta perdida sem repetir efeitos.
O sandbox deve proteger os destinos e o bootstrap antes do init, admitir somente
as origens definidas e manter as exceções do Toolbx restritas às bases fixas.
Critérios 57–65 definidos; nenhuma implementação é afirmada por esta resolução.
As edições de arquitetura ficam na main sem commit para integração pelo dev.
