# 02 — Core

O core tem os componentes abaixo. Política e aprovações estão em [05-security.md](05-security.md), o instalador em [06-lifecycle.md](06-lifecycle.md) e o servidor web em [08-shell.md](08-shell.md).

Meta de tamanho: 5–8 mil linhas de Rust, sem contar testes. Se passar disso, revisar o que deveria ser extensão.

## Supervisor

Responsável por subir, monitorar e encerrar processos de extensão.

### Identidade de instância

- `instance_id`: ULID gerado a cada spawn.
- Chave lógica: `(ext_id)` para `scope: global`; `(ext_id, session_id)` para `scope: session` e para o harness.

### Spawn

1. Resolver o bundle ativo no lock (`store/<id>/<key>/`).
2. Resolver as permissões do manifest em um `SandboxProfile` ([05-security.md](05-security.md#perfil-de-sandbox)), expandindo templates de caminho.
3. Gerar o token do proxy da instância e, se o manifest pedir escopos de kernel, criar `run/k/<instance_id>.sock` (0600) e um token de kernel.
4. Montar o ambiente do zero (nada herdado do usuário):

| Variável | Valor |
|---|---|
| `PATH` | binários do runtime + `/usr/bin:/bin` (+ `/usr/local/bin`, `/opt/homebrew/bin` no macOS se existirem) |
| `HOME` | diretório temporário da instância (`${tmp}/home`) |
| `TMPDIR` | `${tmp}` |
| `LANG` | `C.UTF-8` (Linux) ou `en_US.UTF-8` (macOS) |
| `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` e minúsculas | `http://fx:<proxy_token>@127.0.0.1:<porta>` |
| `NO_PROXY`, `no_proxy` | vazio |
| `NODE_USE_ENV_PROXY` | `1` |
| `FICTOR_EXT_ID`, `FICTOR_INSTANCE_ID` | identidade |
| `FICTOR_SESSION_ID`, `FICTOR_WORKSPACE` | só para instâncias de sessão |
| `FICTOR_KERNEL_SOCKET`, `FICTOR_KERNEL_TOKEN` | só se houver escopos de kernel; o caminho é o visto dentro do sandbox (`/fx/kernel.sock` no Linux) |
| `FICTOR_MODELS_URL` | `http://models.fictor.internal/p` se `permissions.models` não for vazio |
| variáveis de `permissions.env` | valores estáticos do manifest |
| variáveis de `permissions.secrets` | ver [05-security.md](05-security.md#segredos) |

5. Montar a linha de comando do runtime ([04-extensions.md](04-extensions.md#runtimes)) e envolvê-la no backend de sandbox da plataforma.
6. Conectar stdin/stdout ao cliente MCP (se `mcp: true`). Stderr vai para `logs/ext/<ext_id>.log`, com rotação a 10 MiB.
7. Gravar o evento `ext.started` na sessão `sys`.

### Encerramento

1. Enviar a notificação `shutdown` pelo Kernel Protocol (se houver canal) e fechar o stdin.
2. Aguardar 3 s e enviar SIGTERM ao grupo de processos.
3. Aguardar 2 s e enviar SIGKILL ao grupo.

### Falhas

- Saída inesperada: grava `ext.crashed` (com as últimas 50 linhas de stderr em blob). Reinício com backoff de 1 s, 2 s, 4 s, 8 s, 16 s.
- Mais de 5 crashes em 60 s: a instância fica `disabled` até ação do usuário. Chamadas pendentes falham com `EXT_UNAVAILABLE`.
- Chamadas em andamento quando o processo morre falham com `EXT_UNAVAILABLE`. O core não repete chamadas automaticamente.

### Troca de versão (hot swap)

Ao promover uma versão nova:

1. As instâncias da versão antiga entram em `draining`: não recebem chamadas novas.
2. Chamadas novas vão para instâncias da versão nova, criadas sob demanda.
3. Instâncias em `draining` encerram quando não houver chamada em andamento, ou após 30 s.
4. O core envia `tools.changed` a todos os harnesses e `catalog.changed` ao shell.

## Store

### SQLite

- Arquivo `fictor.db`, `journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=5000`, `synchronous=NORMAL`.
- Migrações em `core/migrations/NNNN_nome.sql`, aplicadas no boot dentro de uma transação, controladas por `PRAGMA user_version`. A migração inicial é [schemas/0001_init.sql](schemas/0001_init.sql).
- Escritas serializadas por uma única task (fila tokio). Leituras usam um pequeno pool de conexões somente leitura.

### Eventos

Campos e tipos estão na migração. Regras:

- `id` é ULID monotônico.
- `payload` é JSON inline até 64 KiB. Acima disso, o conteúdo vai para blob e `payload` guarda `{"$blob": "sha256:..."}`, com o hash também listado em `blob_refs`.
- `trust`, `sensitivity`, `source` e `flags` são calculados pelo core. Extensões não definem esses campos.
- `flags` é cumulativo: `flags = parent.flags | flags_do_evento`. Bit 0 = U (conteúdo não confiável), bit 1 = P (dado privado). Um evento acende U se `trust = untrusted` e P se `sensitivity = private`.
- `text` guarda o texto pesquisável de eventos com texto humano (`user.message`, `assistant.message`, `tool.result` textual até 32 KiB). Alimenta o FTS5.
- `UPDATE` e `DELETE` em `events` abortam (triggers na migração).

### Sessões

- Uma sessão é uma cadeia linear. `head_id` aponta para o último evento.
- `events.append` sem `parent_id` usa o `head_id` atual. Com `parent_id` diferente do head, falha com `HEAD_MOVED`. Ramificar exige fork.
- Fork em um evento E da sessão S cria a sessão S' com `parent_session_id = S` e `fork_event_id = E`. O primeiro evento de S' é `session.forked`, com `parent_id = E`. As flags de S' começam com `E.flags`.
- O caminho de uma sessão (raiz → head) atravessa as sessões ancestrais seguindo `parent_id`.
- A sessão reservada `sys` (`kind = system`) guarda eventos globais (ciclo de vida de extensões, rede, timers). É criada por `fictor init`.
- `kind` distingue sessões normais, delegadas (subagentes, Fase 2) e de eval (Fase 2). `ext_overrides` (JSON `{ext_id: chave do lock}`) faz o supervisor e o gateway usarem outra versão de uma extensão só naquela sessão; é usado apenas por evals.
- Ao criar sessão, o core valida `workspace`: diretório existente, caminho absoluto canônico, fora de `FICTOR_HOME`, diferente de `/`. Usar o `$HOME` inteiro exige confirmação explícita no shell.

### Blobs

- Endereço: `sha256:<hex>`. Arquivo em `blobs/<hex[0..2]>/<hex[2..]>`.
- Escrita: arquivo temporário no mesmo diretório, fsync, rename. Se já existir, não reescreve.
- Limite por blob: 256 MiB.
- Coleta de lixo: `fictor gc` (Fase 2) remove blobs não referenciados por eventos, kv, propostas ou lock.

### KV

- Namespace = `ext_id` da extensão chamadora. O core usa o namespace `core`.
- Valor JSON até 1 MiB.

## Gateway MCP

O core é cliente MCP de cada extensão com `mcp: true`.

### Conexão

- Transporte stdio do MCP via `rmcp`.
- No `initialize`, o core anuncia a capability `roots` para instâncias de sessão (com o workspace como único root). Sampling e elicitation não são anunciados na Fase 0 (elicitation na Fase 2).
- Após `initialize`, o core chama `tools/list` e calcula o hash canônico das definições ([06-lifecycle.md](06-lifecycle.md#fixação-das-tools)). Se o hash diferir de `tools_hash` no lock, a extensão é desativada, o evento `ext.tools_changed` é gravado e o shell mostra o alerta. A extensão só volta após nova proposta aprovada.
- `notifications/tools/list_changed` em runtime dispara a mesma verificação.

### Registro de tools

- Nome exposto: `<ext_id>__<tool_name>` (dois underscores). IDs de extensão não contêm `_`, então a separação é inequívoca.
- Definições vêm do lock, não do processo vivo.
- Classificação de cada tool: `tools.<nome>` do manifest; senão `tools.default`; senão o default restritivo (`effect: external`, `sensitivity: private`, `output_trust: untrusted`, `model_visible: true`, `ui_callable: false`).
- Annotations MCP de terceiros (`readOnlyHint`, `openWorldHint` etc.) são só dicas para o revisor no pipeline. Não afetam a classificação em runtime.
- Tools com nome iniciado por `hook_` são hooks. Nunca aparecem em `tools.list` nem podem ser chamadas por `tools.call`.
- Tools com `model_visible: false` não aparecem em `tools.list`. Podem ser chamadas pelo shell (MCP Apps) se `ui_callable: true`.

### Execução de `tools.call`

1. Resolver a tool. Se inexistente ou a extensão estiver desativada: `NOT_FOUND` / `EXT_UNAVAILABLE`.
2. Validar `arguments` contra o `inputSchema` fixado. Falha: `INVALID_PARAMS`.
3. Decidir pela política ([05-security.md](05-security.md#decisão)). Se `ask`, criar a aprovação e aguardar. Se negar, gravar `tool.denied` e retornar `POLICY_DENIED` ou `APPROVAL_REJECTED`.
4. Gravar `tool.call`.
5. Garantir a instância e chamar `tools/call`. Timeout: `timeout_ms` da tool (default 120 s, máximo 600 s). Ao estourar, enviar `notifications/cancelled` e retornar `TIMEOUT`.
6. Gravar `tool.result` com `trust` e `sensitivity` derivados da classificação e das flags de rede da instância ([05-security.md](05-security.md#proveniência)).
7. Retornar ao chamador.

Cancelamento: `session.cancel` cancela as chamadas pendentes da sessão (MCP `notifications/cancelled`) e as aprovações pendentes.

### Fan-out de hooks

`hooks.invoke` ([03-kernel-protocol.md](03-kernel-protocol.md#hooks)) é executado aqui. O core não interpreta o significado dos hook points.

1. Selecionar as extensões ativas cujo manifest declara `hooks[].point == point`, ordenadas por `priority` (menor primeiro) e depois por `ext_id`.
2. Para cada uma, chamar a tool `hook_<point com "." trocado por "_">` com `{session_id, point, payload}`.
3. Modo `pipeline`: cada hook recebe o `payload` devolvido pelo anterior (se devolvido). Modo `collect`: todos recebem o payload original.
4. A resposta do hook é o `structuredContent` da tool: `{payload?: any, ...sinais}`. O core acumula `{ext_id, signals}` para cada hook.
5. Timeout por hook: `hooks[].timeout_ms` (default 2000 ms). Erro ou timeout: o hook é pulado, grava `hook.failed`. Três falhas seguidas na mesma sessão desativam aquele hook na sessão.
6. Hooks de extensões `scope: session` só rodam para a própria sessão.

## Egress proxy

Um único proxy HTTP no core.

### Escuta

- Linux: Unix socket `run/proxy.sock`. Dentro do sandbox, `__sandbox-init` escuta em `127.0.0.1:3128` e repassa para o socket montado em `/fx/proxy.sock`.
- macOS: TCP em `127.0.0.1:<porta aleatória>`. O perfil Seatbelt só permite saída para essa porta.

### Autenticação

- Toda requisição exige `Proxy-Authorization: Basic` com usuário `fx` e o token da instância. Token desconhecido: 407.
- O token identifica a instância (extensão, sessão).

### CONNECT (HTTPS)

- O destino `host:porta` é comparado com `permissions.net.allow` da extensão. Padrões: `exemplo.com` (exato), `*.exemplo.com` (subdomínios, sem o domínio raiz), `*` (qualquer). Sem porta no padrão, só 443.
- Destinos IP literais, `localhost` e redes privadas (RFC 1918, link-local, loopback) só são aceitos se listados explicitamente com porta.
- Negado: 403 e evento `net.denied` (agregado: um evento por par instância+domínio por minuto).
- Permitido: túnel TCP. O proxy não faz MITM na Fase 0.
- A resolução DNS é feita pelo core. No Linux o sandbox não tem DNS.

### HTTP simples

- `http://models.fictor.internal/...` vai para o model proxy.
- Outros destinos `http://` só se o padrão da allowlist incluir a porta (ex.: `127.0.0.1:11434` para Ollama).

### Proveniência de rede

- Instâncias de sessão (harness e `scope: session`) que conectam a um domínio fora de `policy.trusted_domains` acendem U na sessão: o core grava `session.tainted {flag: "U", reason: "net:<domínio>"}`.
- Hosts de providers de modelo configurados não contaminam.

## Model proxy

Rota: `http://models.fictor.internal/p/<provider_id>/<resto>` → `<base_url>/<resto>`.

1. Exigir que `provider_id` esteja em `permissions.models` da extensão (ou `*`). Senão, 403.
2. Remover cabeçalhos hop-by-hop e qualquer cabeçalho de credencial: `authorization`, `x-api-key`, `api-key`, `proxy-authorization` e o `auth_header` do provider.
3. Adicionar `<auth_header>: <auth_prefix><segredo>` e os `extra_headers` do provider.
4. Repassar via TLS (rustls, raízes do sistema). Responses em streaming (SSE) são repassadas sem buffer.
5. Gravar em paralelo o corpo da requisição e da resposta em blobs. Cabeçalhos não são gravados.
6. Gravar `model.call {provider, path, status, duration_ms, req_blob, resp_blob, bytes_in, bytes_out}` na sessão da instância (ou em `sys` para extensões globais).
7. Orçamento: contar requisições por dia e por sessão. Ao exceder `budget.*`, responder 429 com corpo JSON `{"error": "fictor_budget_exceeded"}`.

O core não interpreta o corpo. Uso de tokens e custo são reportados pelo harness em `assistant.message`.

## Segredos

- Armazenamento: crate `keyring` (Secret Service no Linux, Keychain no macOS), serviço `fictor`, conta = nome do segredo.
- Sem backend de keyring: `$FICTOR_HOME/secrets.toml` com modo 0600. `fictor doctor` avisa.
- Entrada só pela CLI: `fictor secrets set <nome>` lê do TTY sem eco. Nunca pelo chat.
- Leitores: model proxy e supervisor (para segredos declarados em `permissions.secrets`).
- Logs: o layer de tracing DEVE substituir valores de segredos carregados por `***`.

## Timers

- `timers.set` grava em `timers` (migração). Uma task do core verifica a cada 15 s os timers vencidos.
- Ao vencer: sobe a extensão se necessário e envia `timer.fired`. Recalcula `next_at` para cron; remove se for `at_ms`.
- Cron: 5 campos, fuso local. Intervalo mínimo de 1 minuto.
- Timers de extensão desativada não disparam.

## Configuração

Arquivo `$FICTOR_HOME/config.toml`, criado por `fictor init`:

```toml
[server]
listen = "127.0.0.1:7350"        # shell (UI confiável)
surface_port = 7351              # surfaces servidas em http://localhost:7351

[paths]
default_workspace = "~/Projetos"

[runtimes]                       # vazio = procurar no PATH em `fictor doctor`
deno = ""
node = ""
uv = ""
python = ""

[providers.anthropic]
base_url = "https://api.anthropic.com"
auth_header = "x-api-key"
auth_prefix = ""
secret = "anthropic_api_key"

[providers.openai]
base_url = "https://api.openai.com"
auth_header = "authorization"
auth_prefix = "Bearer "
secret = "openai_api_key"

[providers.deepseek]
base_url = "https://api.deepseek.com"
auth_header = "authorization"
auth_prefix = "Bearer "
secret = "deepseek_api_key"

[providers.ollama]
base_url = "http://127.0.0.1:11434"   # sem secret

[policy]
default_mode = "default"         # plan | default | auto
trusted_domains = []             # domínios cujo conteúdo não acende U

[[policy.rules]]                 # opcional; ordem não importa (deny > ask > allow)
tool = "fs-tools__bash"
decision = "allow"

[budget]
max_model_requests_per_day = 2000
max_model_requests_per_session = 300

[harness]
default = "harness"              # ext_id com role=harness
idle_timeout_min = 30

[sandbox]
home_ro_files = ["~/.gitconfig"] # arquivos do HOME real montados só leitura em instâncias de sessão

[installer]
registries = ["jsr.io", "registry.npmjs.org", "deno.land", "pypi.org", "files.pythonhosted.org"]
trusted_packages = ["jsr:@std/*", "npm:@modelcontextprotocol/sdk", "npm:zod"]   # não contam como dependência nova

[evals]                          # Fase 2
judge_model = "sonnet"           # chave de [ext.harness.models]
max_call_ratio = 1.25

[ext.harness]                    # seção opaca: só a extensão "harness" lê via config.get
default_model = "anthropic/claude-sonnet"
```

Seções `[ext.<id>]` são opacas para o core e só legíveis pela extensão `<id>`.

## CLI

Binário único `fictor`. Comandos que alteram estado com o servidor rodando falam com ele via `run/admin.sock`. Sem servidor, só funcionam `init`, `doctor`, `secrets` e `serve`.

| Comando | Fase | Função |
|---|---|---|
| `fictor init [--first-party <repo>]` | 0 | Cria `FICTOR_HOME`, config, banco, sessão `sys`; instala bundles first-party do repositório com confirmação. |
| `fictor doctor` | 0 | Verifica sandbox (bwrap/userns ou sandbox-exec), runtimes, keyring, portas. |
| `fictor serve [--open] [--shell-dir <dir>]` | 0 | Sobe o core e imprime a URL de login com token único. `--shell-dir` serve assets do disco (desenvolvimento). |
| `fictor secrets set\|list\|rm <nome>` | 0 | Gerencia segredos. `list` mostra só nomes. |
| `fictor ext list` | 0 | Extensões, versões ativas, estado. |
| `fictor ext install <caminho> [--yes]` | 0 | Proposta de origem `local`; mostra permissões e pede confirmação no TTY. |
| `fictor ext enable\|disable <id>` | 0 | Liga ou desliga no lock. |
| `fictor ext rollback <id> [--to <key>]` | 1 | Volta para a versão anterior (ou a indicada). |
| `fictor ext remove <id> [--purge-data]` | 1 | Remove do lock; store e dados ficam até `gc`/`--purge-data`. |
| `fictor proposal list\|show\|approve\|reject <id>` | 1 | Revisão de propostas pela CLI. |
| `fictor ext add git\|mcp\|skill\|claude-plugin <ref>` | 3 | Importação de terceiros. |
| `fictor eval run <ext>[@<key>] [--baseline <key>]` | 2 | Roda evals. |
| `fictor gc` | 2 | Coleta blobs e versões antigas do store (mantém as 5 últimas por extensão). |
| `fictor __sandbox-init` | 0 | Interno: init do sandbox Linux. |
