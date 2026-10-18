# Andamento da implementação

Atualizado em 2026-10-18. Fase ativa: **0**. Plataforma única: **Linux x86-64**.
Alvo de validação: **Fedora COSMIC Atomic**. Prioridade: **v0.1 autossuficiente**
([ADRs 030/031](../spec/11-decisions.md), [roadmap](../spec/10-roadmap.md)).

## Estado

“Implementado” descreve o código presente. Build e testes passaram no Toolbx Fedora 44
sobre Bazzite; o gate no COSMIC Atomic e a CI continuam pendentes. A
[verificação](verification.md) distingue esses ambientes.

| Marco | Estado | Entrega e restante |
|---|---|---|
| M0.1 | Base implementada | Crate único, CLI `init`/`doctor`/`secrets`, TOML, FICTOR_HOME privado, migrações 0001/0002 e sessão `sys`. `init --first-party` aguarda instalador. |
| M0.2 | Base implementada | Writer único SQLite, pool somente leitura, eventos ULID, flags cumulativas, FTS5, forks/linhagens, blobs SHA-256 e KV. |
| M0.3 | Backend Linux; diagnóstico real no Bazzite passou | Bubblewrap e `__sandbox-init`, rede por ponte, ambiente limpo e namespace de PID. Gate no COSMIC Atomic pendente. |
| M0.4 | Base implementada | Egress autenticado, allowlist IPv6/NAT64, model proxy TLS com captura/auditoria, orçamento durável e keyring/file explícito. |
| M0.5 | Base implementada; instalador parcial | Manifest, supervisor/smoke, gateway MCP, Kernel Protocol, propostas auditadas com CAS/nonce e lock atômico. `ext check` mantém quarentena. Faltam resolvers, promoção/ativação, recuperação, backoff e integração first-party. |
| M0.6 | Não implementado | Política, aprovações e grants. |
| M0.7 | Não implementado | Servidor web e shell. |
| M0.8 | Não implementado | SDK, harness com compactação, fs-tools e shell-net. |
| M0.9 | Ambiente de desenvolvimento preparado; runtime de uso pendente | Toolbx Fedora 44/Node 24 LTS disponível. Gerenciador de runtimes, guarda de migração/backup, login, rollback e unidade systemd de usuário pendentes. |
| M0.10 | Não implementado | Aceitação completa e roteiro de autossuficiência no Fedora COSMIC Atomic. |
| Fases 1–3 | Não iniciadas | Aguardam todos os critérios da Fase 0; corte v1.0 no roadmap. |

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
  Node usa Permission Model, inclusive bloqueio de subprocessos quando `spawn: false`.
  Bloqueio de `execve` por seccomp para os demais runtimes permanece na Fase 3.
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
  confirmar saída do bwrap antes de liberar recursos (ADR-029); sem confirmação em
  10 s, reter recursos e reportar `cleanup_failed`. A confirmação usa a saída do
  bwrap (namespace de PID), sem depender de grupos POSIX. Testes no Toolbx/Bazzite
  cobrem fork duplo, `setsid()`, crash e SIGKILL do processo dono do supervisor.
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
  após morte do processo têm contrato no ADR-035 (ARQ-019 resolvida); migração
  0003, adaptação do recebimento e recuperação ainda precisam ser implementadas.
- Kernel `log` aguarda ligação ao sink do supervisor. Tools, hooks, UI, timers e
  aprovação aguardam seus marcos; nenhuma rota incompleta simula sucesso.

## Próxima sequência no Fedora

1. Repetir build, Clippy e suíte completa no COSMIC Atomic e conferir CI Ubuntu/Fedora;
   os diagnósticos no Bazzite constam em [verification.md](verification.md).
2. Completar M0.5, incluindo aplicação/testes dos ADRs 025–029 e dos requisitos Atomic;
   resolvers, promoção, lock, ativação, recuperação e backoff.
3. Integrar `init --first-party` ao mesmo pipeline. `ext check` não substitui instalação.
4. Seguir M0.6–M0.10 e os **37 critérios da Fase 0**, incluindo autossuficiência,
   antes de iniciar a Fase 1.

ARQ-001–018 estão resolvidas pelos ADRs 013–029. Resolução arquitetural não implica
implementação nem release concluída. A ARQ-019 foi resolvida pelo ADR-035 em
2026-10-18, com implementação pendente em M0.5; consulte
[architect-pending.md](architect-pending.md).

## Ambiente e escolhas de desenvolvimento em 2026-10-18

- `dev/Containerfile` parte de `registry.fedoraproject.org/fedora-toolbox:44`.
  Usa os pacotes Fedora `nodejs24-bin`/`nodejs24-npm-bin`, pois os nomes genéricos
  selecionam Node 22 nessa imagem. Rust, GCC, Git, bubblewrap e ripgrep ficam no
  container. Caches Cargo/npm ficam em `.fictor/`; nenhum pacote foi instalado no host.
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
