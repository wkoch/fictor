# Andamento da implementação

Data: 2026-10-17. Fase ativa: **0**. Plataforma única: **Linux x86-64**.
Alvo de validação: **Fedora COSMIC Atomic**. Prioridade: **v0.1 autossuficiente**
([ADRs 030/031](../spec/11-decisions.md), [roadmap](../spec/10-roadmap.md)).

## Estado

“Implementado” descreve o código presente; os testes Linux continuam pendentes.
A [verificação](verification.md) distingue execução no desktop, CI e checagens estáticas.

| Marco | Estado | Entrega e restante |
|---|---|---|
| M0.1 | Base implementada | Crate único, CLI `init`/`doctor`/`secrets`, TOML, FICTOR_HOME privado, migrações 0001/0002 e sessão `sys`. `init --first-party` aguarda instalador. |
| M0.2 | Base implementada | Writer único SQLite, pool somente leitura, eventos ULID, flags cumulativas, FTS5, forks/linhagens, blobs SHA-256 e KV. |
| M0.3 | Backend Linux; validação real pendente | Bubblewrap e `__sandbox-init`, rede por ponte, ambiente limpo e namespace de PID. Confinamento, caminhos Atomic e daemonização precisam de execução real no Fedora. |
| M0.4 | Base implementada | Egress autenticado, allowlist IPv6/NAT64, model proxy TLS com captura/auditoria, orçamento durável e keyring/file explícito. |
| M0.5 | Base implementada; instalador parcial | Manifest, supervisor/smoke, gateway MCP, Kernel Protocol, propostas auditadas com CAS/nonce e lock atômico. `ext check` mantém quarentena. Faltam resolvers, promoção/ativação, recuperação, backoff e integração first-party. |
| M0.6 | Não implementado | Política, aprovações e grants. |
| M0.7 | Não implementado | Servidor web e shell. |
| M0.8 | Não implementado | SDK, harness com compactação, fs-tools e shell-net. |
| M0.9 | Não implementado | Toolchains, guarda de migração/backup, login, rollback e unidade systemd de usuário. |
| M0.10 | Não implementado | Aceitação completa e roteiro de autossuficiência no Fedora COSMIC Atomic. |
| Fases 1–3 | Não iniciadas | Aguardam todos os critérios da Fase 0; corte v1.0 no roadmap. |

## Migração para Linux x86-64

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
atual deixam de ser evidência. A formatação e o diagnóstico cruzado de tipos/Clippy
para Linux x86-64 passaram; não houve execução de binário ou testes Linux. Esses
resultados não equivalem ao build/testes nativos ou ao gate no Fedora.

Aliases de caminhos Atomic, certificados/NSS e proteções de credenciais/persistência
foram ajustados no launcher, ainda sem execução no Fedora. Toolchains do usuário
e guarda de migração fazem parte do roadmap atualizado; a retirada de código de outras plataformas não
encerra esses marcos. `.fictor/` fica fora do Git para os caches locais do workspace,
conforme ADR-031. O agente faz commits locais; push, instalação do novo core e
reinício do serviço são ações do usuário, fora do sandbox.

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
  `spawn: false` para runtimes não Deno permanece declarativo até a Fase 3.
- Montagens que se sobrepõem a caminhos sensíveis são recusadas. Descoberta usa
  ambiente e `gpgconf --list-dirs`, com prazo limitado e sem iniciar agentes.
- O egress resolve uma vez, valida todos os IPs e conecta somente aos aprovados.
  IP literal, localhost e destinos não públicos exigem host exato e porta explícita.
  IPv6 segue ADR-021; prefixos NAT64 configurados seguem RFC 6052/ADR-023 e o /48
  local é não público. `doctor` só sugere prefixos, sem mudar política.
- Tokens revogados encerram túneis. Negações são agregadas por instância/host/minuto
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
  confirmar término do launcher e PID 1 antes de liberar recursos (ADRs 029/038); sem confirmação em
  10 s, reter recursos e reportar `cleanup_failed`. O algoritmo de encerramento ainda
  precisa ser alinhado integralmente ao ADR-029; hoje usa PGID e prazo de retorno.
  Validação adversarial pendente.
- Smoke usa bundle, workspace, ext_data, configuração, Store e proxies descartáveis,
  sem acesso a credenciais/providers reais; segredos declarados viram honeytokens.
  ADR-028 exige omitir grants absolutos/`~/` e exibi-los na revisão. ADR-027 define
  runtime/MCP/papel. ADR-025 recusa processos globais na Fase 0. A integração desses
  contratos deve ser conferida nos testes Linux, sem antecipar mediação da Fase 1.
  A recusa `phase:global`, SemVer completo e combinações de runtime/MCP/papel foram
  ajustadas; grants absolutos no smoke ainda falham em vez de serem omitidos (ADR-028).
  `permissions.toolchains: true` é recusado até a implementação de M0.9.
- Propostas têm transições e eventos `ext.*` na mesma transação. Aprovação/rejeição
  exigem nonce humano rotacionado, omitido de JSON/Debug. O lock schema 1 valida paths,
  ausência de symlinks e tools_hash; escreve arquivo privado com exclusão, fsync e
  rename. A escrita ainda não está ligada à promoção.
- `ext check` permite `binary`/`none`; Deno/npm/uv falham antes de executar até haver
  resolver. Checks aprovados continuam em quarentena. Falhas antes da identificação
  do manifest e recuperação após interrupção têm contrato no ADR-035 (ARQ-019 resolvida); migração
  0003, adaptação do recebimento e recuperação ainda precisam ser implementadas.
- Kernel `log` aguarda ligação ao sink do supervisor. Tools, hooks, UI, timers e
  aprovação aguardam seus marcos; nenhuma rota incompleta simula sucesso.

## Próxima sequência no Fedora

1. Executar build, Clippy e suíte completa no desktop; registrar SO, commit e saídas
   em [verification.md](verification.md). Conferir CI Ubuntu e Fedora.
2. Completar M0.5, incluindo aplicação/testes dos ADRs 025–029 e dos requisitos Atomic;
   resolvers, promoção, lock, ativação, recuperação e backoff.
3. Integrar `init --first-party` ao mesmo pipeline. `ext check` não substitui instalação.
4. Seguir M0.6–M0.10 e os **56 critérios da Fase 0**, incluindo autossuficiência,
   antes de iniciar a Fase 1.

ARQ-001–018 estão resolvidas pelos ADRs 013–029. Resolução arquitetural não implica
implementação nem release concluída. A ARQ-019 foi resolvida pelo ADR-035 em
2026-10-18, com implementação pendente em M0.5; consulte
[architect-pending.md](architect-pending.md).

## Contratos arquiteturais liberados em 2026-10-18

ARQ-020–024 resolvidas pelos ADRs 036–040: promoção recuperável, overrides
humanos, posse/recuperação de instâncias, crash loops e fronteira dos registros de dependências. Migrações normativas
0004/0005, schema de overrides e critérios 38–46 estão no spec. Este registro
abrange apenas arquitetura na branch principal; não incorpora nem certifica o
código em andamento na branch do implementador.

ARQ-025 resolvida pelo ADR-041: `ext list` consulta configuração online/offline
sem afirmar saúde; leitura coordenada com o journal e canal administrativo mínimo
definidos. Critérios 47–50 aguardam implementação e testes do produto.

ARQ-026 resolvida pelo ADR-042: origem protegida dos arquivos de controle,
validação por descritor e recusa de aliases que exponham a árvore privada.
Erros de `config.get`, ausência e tratamento do legado estão definidos; critérios
51–56 aguardam implementação e testes. Nenhum reparo de dados do usuário é automático.
