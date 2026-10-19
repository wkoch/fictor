# 03 — Kernel Protocol

Protocolo entre o core e extensões para serviços do kernel. Ferramentas, resources e hooks usam MCP; tudo que é serviço do kernel usa este protocolo.

## Transporte

- JSON-RPC 2.0, uma mensagem JSON UTF-8 por linha.
- Endereço em `FICTOR_KERNEL_URL` (sempre `tcp://127.0.0.1:3129`), token em `FICTOR_KERNEL_TOKEN`.
- `__sandbox-init` escuta nesse endereço, dentro do namespace de rede isolado da instância, e repassa para o Unix socket da instância no host. Assim a carga de trabalho não precisa de sockets Unix por caminho, e a Fase 3 pode bloqueá-los com seccomp ([05-security.md](05-security.md#linux-bubblewrap)).
- Tamanho máximo de mensagem: 16 MiB (16.777.216 bytes do JSON codificado em UTF-8, excluindo o LF delimitador). Conta a serialização real, inclusive escapes e envelope. JSON de exatamente esse tamanho é permitido; a linha pode ter um byte adicional de LF. Não existe exceção para erro, hello ou notificação.
- A primeira requisição DEVE ser `kernel.hello`. Antes dela, qualquer outra requisição recebe `UNAUTHENTICATED` e a conexão é fechada.
- Só existe canal se o manifest declarar pelo menos um escopo em `kernel`.

### IDs, admissão e correlação

O perfil do Kernel Protocol admite um único objeto JSON-RPC por linha. Array no topo, inclusive batch vazio ou com apenas um membro, recebe `INVALID_REQUEST` (`-32600`, `id: null`) e nenhum membro é autenticado, admitido ou executado. O limite do frame é verificado antes; frame excessivo encerra sem resposta. Não há respostas agregadas nem execução parcial de lote.

Os IDs de requisição seguem os tipos do JSON-RPC: String, Number ou Null. Ausência do campo `id` indica notificação; `"id": null` é uma requisição com ID Null e recebe resposta como tal. Boolean, objeto e array não são IDs válidos.

| Tipo | Teto | Preservação |
|---|---|---|
| String | 256 bytes UTF-8 do valor depois de decodificar escapes JSON; vazio permitido | Mesma sequência de caracteres; sem truncamento, hashing ou normalização Unicode. Grafias equivalentes de escapes podem ser reserializadas. |
| Number | 256 bytes do token JSON original, sem whitespace que o rodeia | Mesmo valor numérico, sem arredondamento/conversão destrutiva. Sinais, frações e expoentes válidos continuam aceitos; preservar o token original validado evita perda de precisão. |
| Null | Token `null` | Responder com `id: null` porque esse era o ID, não como fallback. |

ID String deve decodificar para uma sequência de escalares Unicode. Par surrogate válido, como `\uD83D\uDE00`, representa um escalar de quatro bytes UTF-8; surrogate isolado é recusado antes de dispatch com `INVALID_REQUEST` (`-32600`, `id: null`). Se o parser rejeitar o JSON inteiro antes de identificar o campo, aplica-se `Parse error` (`-32700`, `id: null`). Esses são os dois erros admitidos para essa entrada; nenhum caminho substitui o escalar inválido por U+FFFD nem envia seu valor alterado. O problema de interoperabilidade é descrito na [RFC 8259, seção 8.2](https://www.rfc-editor.org/rfc/rfc8259#section-8.2).

O limite numérico é lexical, não uma faixa de inteiros ou regra de arredondamento. Não converter IDs arbitrários em `f64`/Number JavaScript e depois usar o valor arredondado como correlação. O ID é opaco para o dispatch. Nenhum limite novo de números em parâmetros ou resultados decorre desta regra.

Verificar o limite da mensagem e a identidade de correlação antes de `kernel.hello`, de usar o token de autenticação e de qualquer admissão de método, reserva, escrita ou efeito da requisição. Um ID acima do teto fecha o transporte sem resposta JSON-RPC e sem executar essa requisição, mesmo que uma resposta específica com esse ID ainda pudesse caber. Não enviar erro com ID nulo, truncado ou reescrito. Isso é recusa pelo perfil de transporte, não execução seguida de erro de aplicação. Outras requisições já admitidas não são desfeitas pela recusa.

Para uma mensagem JSON completa cujo ID seja válido, único e dentro do teto, o ID permanece conhecido mesmo quando outro campo do envelope/parâmetros é inválido: o erro conserva esse ID. `id: null` por erro de identificação fica restrito aos casos em que não há um ID válido e unívoco: JSON não decodificável, ID de tipo inválido ou campo `id` duplicado, por exemplo. Duplicatas são comparadas depois de decodificar o nome da chave (`id` e `i\u0064` são a mesma chave), inclusive quando os valores repetidos seriam iguais. Não procurar ID por regex, por prefixo truncado ou por análise permissiva de JSON incompleto. Duplicação de outro campo rejeita o envelope; se o JSON completo estabelece um ID único e válido, esse ID continua sendo a correlação do erro.

Notificação reconhecida não recebe resposta, inclusive para erro de método ou parâmetros. Isso não transforma envelope inválido ou ID de tipo inválido em notificação. As regras de autenticação permanecem: somente uma requisição `kernel.hello` válida autentica a conexão; uma notificação não autentica. Rejeição pelo limite de mensagem/ID pode encerrar o transporte antes de qualquer resposta de autenticação.

### Limite da resposta e resultado desconhecido

Montar a resposta completa em memória limitada e conferir o tamanho codificado antes de transmitir qualquer byte dela. Se a resposta original exceder 16 MiB, substituí-la por este erro mínimo em JSON compacto, preservando o ID admitido:

```json
{"jsonrpc":"2.0","id":"<mesmo ID>","error":{"code":-32010,"message":"TOO_LARGE"}}
```

O exemplo usa String somente para ilustrar; Number e Null preservam seus próprios tipos/valores. Não anexar ao fallback o resultado, parâmetros ou detalhes grandes. Com o teto de ID definido acima, o pior String de 256 bytes exige no máximo 1.538 bytes JSON de ID quando cada byte é um controle escapado; esse envelope mínimo ocupa no máximo 1.607 bytes JSON. Number preservado ocupa até 256 bytes de token. O fallback cabe sem ampliar o limite.

Se nem a resposta mínima puder ser serializada dentro do limite, ou se houver falha de escrita, encerrar a conexão. Nunca enviar uma resposta posterior usando `id: null` para substituir ID conhecido. Não iniciar a resposta normal e depois concatenar um erro ao prefixo: o cliente só considera resposta completa e válida terminada por LF. Uma notificação de saída que exceder o limite não pode virar resposta JSON-RPC sem requisição; falhar/encerrar o transporte, sem criar ID.

`TOO_LARGE` pode significar que o método foi admitido e produziu resultado que não cabe. O cliente não pode inferir “nenhum efeito ocorreu” desse erro, de EOF, timeout ou falha de entrega. Os efeitos seguem o contrato de cada método e sua auditoria; entrega malsucedida não autoriza rollback adivinhado, remoção de eventos ou repetição. Nenhuma promessa nova de execução exatamente uma vez é criada por IDs: repetir o mesmo ID não é mecanismo de deduplicação de efeitos.

Decisão e compatibilidade: [ADR-043](11-decisions.md#adr-043--ids-limitados-e-respostas-correlacionadas-no-kernel-protocol-resolve-arq-027). Este contrato é do Kernel Protocol; os limites próprios de MCP, WebSocket e do [canal administrativo](02-core.md#canal-administrativo-mínimo) permanecem separados.

## Escopos

O manifest declara os escopos em `kernel: [...]`. O core recusa com `SCOPE_DENIED` métodos fora dos escopos concedidos.

| Escopo | Métodos | Observação |
|---|---|---|
| `events.read` | `events.get`, `events.path`, `events.query` | Instância de sessão: só a linhagem da própria sessão. Instância global (Fase 1): todas as sessões, e as flags dos eventos lidos entram na marca d'água da extensão. |
| `events.write` | `events.append` | Kinds `x.<ext_id>.*`. O harness também pode `assistant.*` e `harness.*`. Instância de sessão: só na própria sessão. Instância global (Fase 1): `sys` ou qualquer sessão, com a proveniência da tabela [Proveniência dos eventos](#proveniência-dos-eventos). |
| `sessions` | `sessions.get`, `sessions.fork`, `sessions.delegate` (Fase 2), `sessions.complete` (Fase 2) | Só instâncias de sessão. |
| `sessions.input` | `sessions.input` | Injeta entrada e dispara um turno do agente. |
| `blobs` | `blobs.put`, `blobs.get` | Conhecer o hash é a capacidade de leitura. |
| `kv` | `kv.get`, `kv.set`, `kv.delete`, `kv.list` | Namespace `ext_id` (global) ou `ext_id@session_id` (instância de sessão). |
| `tools` | `tools.list`, `tools.call` | Só instâncias de sessão. |
| `hooks` | `hooks.invoke` | Só instâncias de sessão. |
| `catalog` | `catalog.list` | |
| `ui` | `ui.emit`, `ui.mount` (Fase 1) | |
| `timers` | `timers.set`, `timers.cancel`, `timers.list` | |
| `ext.propose` | `ext.propose`, `ext.proposal_status` (Fase 1) | |
| `config` | `config.get` | Seções `ext` (só a própria), `providers`, `instructions`. |
| `approval` | `approval.request` | |

O harness padrão declara: `events.read`, `events.write`, `sessions`, `blobs`, `kv`, `tools`, `hooks`, `catalog`, `ui`, `config`, `approval` e, a partir da Fase 1, `ext.propose`.

## Tipos

```ts
type Ulid = string;
type BlobRef = `sha256:${string}`;

type Session = {
  id: Ulid | "sys";
  kind: "normal" | "delegated" | "eval" | "system";
  title: string;
  workspace: string | null;
  workspace_trust: "trusted" | "untrusted";
  harness: string | null;
  mode: "plan" | "default" | "auto";
  model: string | null;                 // opaco para o core
  parent_session_id: Ulid | null;
  fork_event_id: Ulid | null;
  head_id: Ulid | null;
  flags: { U: boolean; P: boolean };
  archived: boolean;
  created_at: number;                   // unix ms
  updated_at: number;
};

type Event = {
  id: Ulid;
  parent_id: Ulid | null;
  session_id: string;
  kind: string;
  actor: string;                        // "user" | "core" | "ext:<id>" | "ext:<id>@ui"
  payload: unknown;                     // JSON; {"$blob": BlobRef} se grande
  blob_refs: BlobRef[];
  trust: "trusted" | "untrusted";
  sensitivity: "public" | "private";
  source: string;                       // ex.: "user", "tool:web__web_fetch", "net:example.com"
  flags: { U: boolean; P: boolean };    // cumulativo até este evento
  created_at: number;
};

type Part =
  | { type: "text"; text: string }
  | { type: "image"; blob: BlobRef; mime: string }
  | { type: "file"; blob: BlobRef; name: string; mime: string };

type McpContent = unknown;              // item de content do MCP, repassado sem alteração

type ToolDef = {
  name: string;                         // "<ext_id>__<tool>"
  description: string;
  input_schema: object;                 // JSON Schema fixado no lock
  effect: "read" | "write_local" | "external";
  sensitivity: "public" | "private";
  ui_resource?: string;                 // ui:// declarado pela tool (MCP Apps)
};
```

## Métodos

### `kernel.hello`

```ts
params: { protocol: 1; token: string }
result: {
  protocol: 1;
  ext_id: string;
  instance_id: Ulid;
  scopes: string[];
  session?: Session;                    // instâncias de sessão
}
```

Versões de protocolo incompatíveis: erro `INVALID_PARAMS` com `data.supported: number[]`.

### Eventos

```ts
// events.append — escopo events.write
params: { session_id: string; kind: string; payload: unknown; parent_id?: Ulid }
result: { id: Ulid; flags: { U: boolean; P: boolean } }
// Erros: INVALID_KIND (kind fora do namespace permitido), HEAD_MOVED, TOO_LARGE.

// events.get — escopo events.read
params: { id: Ulid }
result: Event

// events.path — escopo events.read
// Eventos do caminho raiz → head, em ordem crescente, estritamente depois de after_id.
// Se houver mais que limit, retorna os limit mais recentes e truncated=true.
params: { session_id: string; after_id?: Ulid; limit?: number }   // limit default 2000, máx. 10000
result: { events: Event[]; truncated: boolean }

// events.query — escopo events.read. Mais recentes primeiro.
params: {
  session_id?: string; kinds?: string[]; text?: string;           // text = consulta FTS5
  since_ms?: number; until_ms?: number; limit?: number             // limit máx. 500
}
result: { events: Event[] }
```

### Sessões

```ts
// sessions.get — escopo sessions
params: { session_id: string }
result: Session

// sessions.fork — escopo sessions
params: { from_event_id: Ulid; title?: string }
result: Session

// sessions.input — escopo sessions.input
// Grava ext.input na sessão e notifica o harness com session.input.
params: { session_id: string; text: string }
result: { event_id: Ulid }

// sessions.delegate — escopo sessions (Fase 2). Ver 07-harness.md#subagentes.
params: { parent_session_id: string; prompt: string; title?: string; model?: string; tools?: string[] }
result: { session_id: Ulid; text: string; trust: "trusted" | "untrusted" }

// sessions.complete — escopo sessions (Fase 2). Chamado pelo harness de uma sessão delegada.
params: { session_id: string; text: string }
result: {}
```

### Blobs e KV

```ts
// blobs.put — escopo blobs. Máx. 32 MiB por chamada. Exatamente um de text ou base64.
// Blobs são só bytes; o MIME acompanha a referência (ex.: Part.mime), não o blob.
params: { text?: string; base64?: string }
result: { hash: BlobRef; size: number }

// blobs.get — escopo blobs
params: { hash: BlobRef }
result: { base64: string; size: number }

// kv.* — escopo kv. Valor JSON até 1 MiB.
kv.get    params: { key: string }                     result: { value: unknown | null }
kv.set    params: { key: string; value: unknown }     result: {}
kv.delete params: { key: string }                     result: {}
kv.list   params: { prefix?: string; limit?: number } result: { items: { key: string; value: unknown }[] }
```

### Tools

```ts
// tools.list — escopo tools. Só tools model_visible de extensões ativas.
params: { session_id: string }
result: { tools: ToolDef[] }

// tools.call — escopo tools. call_id único na sessão (o harness usa o id do provider).
// Bloqueia enquanto houver aprovação pendente.
params: { session_id: string; name: string; arguments: object; call_id: string }
result: {
  content: McpContent[];
  structured?: unknown;
  is_error: boolean;
  trust: "trusted" | "untrusted";
  sensitivity: "public" | "private";
  event_id: Ulid;                       // id do tool.result
}
// Erros: NOT_FOUND, EXT_UNAVAILABLE, INVALID_PARAMS, POLICY_DENIED, APPROVAL_REJECTED, TIMEOUT, CANCELLED.
```

`is_error: true` é erro da própria tool (resultado MCP com `isError`). Erros JSON-RPC são falhas de kernel ou de política.

### Hooks

```ts
// hooks.invoke — escopo hooks. Ver 02-core.md#fan-out-de-hooks.
params: {
  session_id: string;
  point: string;                        // opaco para o core
  payload: unknown;
  mode: "pipeline" | "collect";
}
result: {
  payload: unknown;                     // pipeline: final; collect: original
  results: { ext_id: string; payload?: unknown; signals?: object; error?: string }[];
}
```

Antes de retornar, o core acende na sessão as flags de cada hook que respondeu ([05-security.md](05-security.md#fluxo-entre-sessões)). O harness não precisa declarar nada.

O contrato da tool de hook do lado da extensão:

```ts
// tool MCP "hook_<point com . → _>"
input:  { session_id: string; point: string; payload: unknown }
output: structuredContent = { payload?: unknown; [signal: string]: unknown }
```

### Catálogo

```ts
// catalog.list — escopo catalog. Itens das extensões ativas. Caminhos absolutos no store.
params: { session_id: string }
result: {
  skills:   { ext_id: string; name: string; description: string; path: string }[];   // path do SKILL.md
  commands: { ext_id: string; name: string; description: string; prompt_path: string }[];
  surfaces: { ext_id: string; id: string; slot: "left" | "right" | "bottom"; resource: string; title: string }[];
  hooks:    { [point: string]: string[] };    // ext_ids assinantes, na ordem do fan-out
}
```

### UI

```ts
// ui.emit — escopo ui. Efêmero: não vai para o event log. Máx. 64 KiB.
params: { session_id: string; channel: string; data: unknown }
result: {}

// ui.mount — escopo ui (Fase 1). O resource deve pertencer à extensão chamadora.
params: { session_id?: string; slot: "left" | "right" | "bottom"; resource: string; title?: string }
result: { surface_id: Ulid }
```

Canais de `ui.emit` usados pelo harness padrão: `assistant.delta` (`{text?, reasoning?}`) e `status` (`{text}`). O shell DEVE ignorar canais que não conhece.

### Timers

```ts
// escopo timers
timers.set    params: { id: string; cron?: string; at_ms?: number; payload?: unknown }  result: {}
timers.cancel params: { id: string }                                                     result: {}
timers.list   params: {}                                                                 result: { timers: { id: string; cron?: string; next_at: number }[] }
```

Exatamente um de `cron` ou `at_ms`.

### Propostas (Fase 1)

```ts
// ext.propose — escopo ext.propose. Limites da origem ai: 06-lifecycle.md#limites.
params: {
  session_id?: string;
  ext_id: string;
  files: { path: string; text?: string; base64?: string; mode?: "644" | "755" }[];
  note?: string;
}
result: { proposal_id: Ulid }
```

`path` é relativo à raiz do bundle, sem `..`, sem caminho absoluto, sem symlink. O manifest `fictor.yaml` DEVE estar entre os arquivos. A proposta herda `tainted = true` se a sessão tiver U.

```ts
// ext.proposal_status — escopo ext.propose. Só propostas criadas pela própria extensão.
params: { proposal_id: Ulid }
result: {
  state: "received" | "checking" | "checked" | "approved" | "rejected" | "promoted" | "failed";
  checks: { name: string; passed: boolean; blocking: boolean; detail?: string }[];
  awaiting_human: boolean;
}
```

### Configuração

```ts
// config.get — escopo config
params: { section: "ext" | "providers" | "instructions" }
result:
  | { ext: object }                                         // tabela [ext.<ext_id>] do config.toml
  | { providers: { id: string; url: string }[] }            // url = "http://models.fictor.internal/p/<id>"
  | { instructions: string | null }                         // conteúdo de $FICTOR_HOME/AGENTS.md
```

As fontes de `ext` e `instructions` seguem [Arquivos de controle do core](02-core.md#arquivos-de-controle-do-core), revalidadas a cada chamada. `providers` continua usando o snapshot validado no boot; não relê o arquivo para essa resposta. Apenas ausência da entrada final `AGENTS.md` sob o home válido retorna `instructions: null`; arquivo vazio retorna `instructions: ""`. Link pendente não significa ausência. `config.toml` ausente falha. Strings de caminhos/URLs nos valores opacos de `ext` são dados e não autorizam leituras adicionais.

Falhas dessas fontes usam JSON-RPC `-32603` (`INTERNAL_ERROR`), com `error.data.reason` definido abaixo. Não há resultado parcial, fallback para conteúdo antigo/default, conversão de erro em `null` ou retry automático. Um limite excedido mantém `-32010` (`TOO_LARGE`), conforme os tetos já definidos.

| `error.data.reason` | Condição |
|---|---|
| `control_file:unsafe` | Origem/tipo/UID/modos/links ou montagem recusados pelas verificações de segurança. |
| `control_file:changed` | Mudança de metadados observada entre as validações da leitura. |
| `control_file:unreadable` | Falha de abertura/leitura sem violação de segurança identificada, inclusive `config.toml` ausente. |
| `control_file:invalid` | Conteúdo lido não é UTF-8 válido ou, para `config.toml`, TOML válido. |

Diagnósticos de CLI/boot e erros de protocolo identificam apenas o nome lógico `config.toml`/`AGENTS.md` e o código da falha; não incluem conteúdo bruto, segredos ou caminhos externos/alvos de links. A seção `config` e os formatos de sucesso permanecem iguais.

### Aprovação customizada

```ts
// approval.request — escopo approval
// O shell exibe o pedido rotulado como vindo da extensão. Não autoriza tool calls.
params: { session_id: string; title: string; body_md: string; options: string[] }   // 2 a 4 opções
result: { choice: string | null }                                                    // null = cancelado
```

### Log

Notificação extensão → core: `log { level: "debug" | "info" | "warn" | "error"; message: string; fields?: object }`. Vai para `logs/ext/<ext_id>.log`.

## Notificações do core para a extensão

| Método | Params | Destinatário |
|---|---|---|
| `session.input` | `{ session_id, event: Event }` | harness da sessão. `event.kind` ∈ `user.message`, `ext.input`, `ui.event` (ações do chat). |
| `session.cancel` | `{ session_id }` | harness e instâncias da sessão |
| `ui.event` | `{ session_id?, surface_id, type, payload }` | extensão dona da surface |
| `tools.changed` | `{}` | harnesses |
| `catalog.changed` | `{}` | harnesses |
| `timer.fired` | `{ id, payload }` | extensão dona do timer |
| `shutdown` | `{}` | todos |

## Erros

| Código | Nome | Quando |
|---|---|---|
| -32602 | `INVALID_PARAMS` | Parâmetros inválidos ou argumentos fora do schema da tool. |
| -32001 | `UNAUTHENTICATED` | Sem `kernel.hello` ou token inválido. |
| -32002 | `SCOPE_DENIED` | Método fora dos escopos concedidos. |
| -32003 | `POLICY_DENIED` | A política negou a ação. |
| -32004 | `APPROVAL_REJECTED` | O usuário negou. `data.message` pode trazer o texto do usuário. |
| -32005 | `HEAD_MOVED` | `parent_id` diferente do head atual. |
| -32006 | `NOT_FOUND` | Sessão, evento, tool, blob ou chave inexistente. |
| -32007 | `TIMEOUT` | Tempo esgotado. |
| -32008 | `RATE_LIMITED` | Orçamento ou limite de taxa. |
| -32009 | `INVALID_KIND` | Kind de evento fora do namespace permitido. |
| -32010 | `TOO_LARGE` | Mensagem, payload ou proposta acima do limite. |
| -32011 | `EXT_UNAVAILABLE` | Extensão desativada, em backoff/crash loop ou caiu durante a chamada. |
| -32012 | `CANCELLED` | Cancelado pelo usuário. |

`EXT_UNAVAILABLE` por recuperação inclui `error.data.reason = "backoff"` ou `"crash_loop"`. Somente `backoff` inclui `retry_after_ms`, inteiro não negativo calculado no momento da resposta. Essa informação não concede autorização nem instrui o core a repetir uma chamada.

## Kinds de evento

### Gravados pelo core

| Kind | Actor | Payload |
|---|---|---|
| `session.created` | core | `{title, workspace, workspace_trust, harness, mode, model}` |
| `session.forked` | core | `{from_session_id, from_event_id}` |
| `session.mode_changed` | user | `{mode}` |
| `session.model_changed` | user | `{model}` |
| `session.tainted` | core | `{flag: "U" \| "P", reason, source_event_id?}` |
| `user.message` | user | `{content: Part[], command?: {ext_id, name, args}}` |
| `ui.event` | `user` ou `ext:<id>@ui` | `{surface_id?, type, payload}` |
| `ext.input` | `ext:<id>` | `{text}` |
| `model.call` | core | `{provider, method, path, outcome, error?, status, req_blob, req_bytes, resp_blob, resp_bytes, resp_complete, duration_ms, ttfb_ms}` — `outcome` ∈ `complete`, `client_cancelled`, `upstream_error`, `capture_failed`, `capture_limit`, `rejected`; `error` é o código do corpo de erro (`fictor_*`) ou de transporte (`connect_timeout`, `idle_timeout`, `connection_reset`); `status` é o do provider, ou o devolvido pelo proxy em `rejected`, ou `null` se não houve resposta. Ver [02-core.md](02-core.md#model-proxy). |
| `tool.call` | core | `{call_id, name, arguments, origin: "harness" \| "ui"}` |
| `tool.result` | core | `{call_id, content, structured?, is_error, duration_ms}` |
| `tool.denied` | core | `{call_id, name, reason: "policy" \| "user", message?}` |
| `approval.requested` | core | `{approval_id, kind, title}` |
| `approval.decided` | user | `{approval_id, decision, scope}` |
| `hook.failed` | core | `{point, ext_id, error}` |
| `net.denied` | core | `{ext_id, host, count}` |
| `ext.started`, `ext.stopped`, `ext.tools_changed`, `ext.cleanup_failed` | core | `{ext_id, key, instance_id, ...}` — sessão `sys` |
| `ext.crashed` | core | `{ext_id, key, instance_id, session_id: string \| null, code: number \| null, signal: number \| null, stderr_blob?, stderr_unavailable?, recovery_count, backoff_ms: number \| null, blocked}` — sessão `sys`. `recovery_count` é 1–6 após contar o crash; `backoff_ms` é 1000/2000/4000/8000/16000 ou nulo quando bloqueado. |
| `ext.crash_blocked` | core | `{ext_id, key, session_id: string \| null, instance_id, crashes: 6, window_ms: 60000}` — sessão `sys`, na mesma transação do sexto crash. |
| `ext.crash_reset` | user | `{ext_id, key, session_id: string \| null, previous_count, was_blocked}` — sessão `sys`, na mesma transação que limpa a recuperação selecionada. |
| `ext.proposed`, `ext.checking`, `ext.checked`, `ext.approved`, `ext.rejected`, `ext.failed` | core ou user | `{proposal_id, ext_id: string \| null, version: string \| null, from: string \| null, state, reason?}` — sessão `sys`. `from = null` na criação; `reason` obrigatório em `ext.failed`. Identidade nula somente em `ext.proposed`/`ext.failed`; não há `key` antes da promoção. Ver [06-lifecycle.md](06-lifecycle.md#identidade-e-persistência). |
| `ext.promotion_prepared` | core | `{operation_id, proposal_id, ext_id, key, before_hash: string \| null, after_hash}` — sessão `sys`, na mesma transação que prepara o journal. |
| `ext.promotion_aborted` | core | `{operation_id, proposal_id, ext_id, key, reason}` — sessão `sys`, na mesma transação que aborta a intenção; `reason` é código estável `promotion:*`. |
| `ext.promoted` | core | `{operation_id, proposal_id, ext_id, key}` — sessão `sys`, na mesma transação que confirma a proposta e o journal. |
| `ext.rolled_back` | core ou user | `{proposal_id?, ext_id, key}` — sessão `sys` |
| `workspace.flagged` | core | `{workspace, flag: "U", session_id, source_event_id}` — sessão `sys` |
| `workspace.cleared` | user | `{workspace}` — sessão `sys` |
| `ext.flags_changed` | core | `{ext_id, flags: {U, P}, session_id?, reason}` — marca d'água de extensão global (Fase 1), sessão `sys` |
| `runtime.installed`, `runtime.activated`, `runtime.rolled_back`, `runtime.integrity_failed` | core ou user | `{name, version, from?}` — sessão `sys` |
| `update.batch` | user | `{batch_id, items: [{kind: "runtime" \| "extension", id, from, to}]}` — sessão `sys` |
| `ext.state_reset` | user | `{ext_id}` — kv, `${ext_data}` e marca d'água apagados (Fase 1), sessão `sys` |

`ext.failed.reason` é um código estável do core para a checagem bloqueante que falhou, nunca o texto livre de `detail`. Antes da identidade e na recuperação, usar os códigos de [06-lifecycle.md](06-lifecycle.md#falhas-antes-da-identidade). Nas demais checagens, usar `check:failed` se não houver código específico.

Os campos novos dos eventos de proposta valem a partir do ADR-035. Consumidores do histórico aceitam eventos anteriores sem `version`, `from`, `state` ou `reason`; não inferem uma identidade ausente e não reescrevem eventos. `proposal.updated` continua contendo somente `{proposal_id, state}`, e `ext.proposal_status` não muda de formato nem de fase.

Os eventos de promoção do ADR-036 identificam a tentativa por `operation_id`; consumidores aceitam `ext.promoted` legado sem esse campo. Snapshots de lock são dados privados do journal e nunca entram nesses eventos. Recuperação idempotente não reescreve eventos nem duplica `ext.promoted`.

Os campos de recuperação de `ext.crashed` valem para processos ativos a partir do ADR-039. Consumidores aceitam o histórico anterior sem esses campos e nunca reescrevem os eventos. Se o smoke registrar um crash diagnóstico com `smoke: true`, aquele evento não leva `recovery_count`, `backoff_ms` ou `blocked` e não cria estado de recuperação. `session_id` do payload identifica a instância; o evento continua na sessão `sys`.

### Gravados pelo harness

| Kind | Payload |
|---|---|
| `assistant.message` | `{text, reasoning?, tool_call_ids: string[], provider, model, stop_reason, usage?: {input_tokens, output_tokens, cache_read_tokens?, cache_write_tokens?}}` |
| `harness.local_tool` | `{call_id, name, arguments, result, is_error}` — tools locais (`load_skill`, `todo_write`, `propose_extension`, `delegate`); resultado grande em blob |
| `harness.tool_skipped` | `{call_id, name, reason, ext_id?}` — chamada barrada por hook ou por aprovação customizada negada |
| `harness.compaction` | `{summary, covers_until_event_id}` |
| `harness.continue` | `{text, ext_id}` — continuação pedida por hook `turn.end` |
| `harness.error` | `{message, retryable}` |

Semântica de `assistant.message.usage`: entrada total inclui cache; campos de cache
são detalhamentos opcionais. A normalização por adapter e a compatibilidade com
histórico estão em [Prompt caching](07-harness.md#prompt-caching-m08), ADR-046.
O core não extrai nem interpreta esses contadores nas APIs de modelo.

### Gravados por outras extensões

`x.<ext_id>.<nome>` com payload livre.

### Proveniência dos eventos

| Origem | `trust` | `sensitivity` |
|---|---|---|
| `user.message`, `session.*`, `approval.decided` | trusted | public |
| `tool.result` | ver [05-security.md](05-security.md#proveniência) | classificação da tool |
| `ui.event` de surface, `ext.input` | `output_trust` default da extensão (`tools.default`), senão untrusted; combinado com a marca d'água se a extensão for global | `tools.default`, senão private; combinado com a marca d'água |
| `events.append` por instância de sessão, na própria sessão | trusted | public |
| `events.append` por instância global, em sessão diferente de `sys` (Fase 1) | `output_trust` default da extensão (`tools.default`), senão untrusted, combinado com a marca d'água; acende as flags da sessão | `tools.default`, senão private, combinado com a marca d'água |
| `events.append` por instância global, em `sys` | trusted | public |
| demais eventos do core | trusted | public |

Eventos gravados por instâncias de sessão na própria sessão não acendem flags. Isso é seguro porque toda entrada de dados nesses processos já passou por um canal mediado que acendeu as flags da sessão ([05-security.md](05-security.md#fluxo-entre-sessões)), e as flags são cumulativas. Instâncias globais recebem dados de várias sessões, por isso o que elas gravam numa sessão acende flags e carrega a marca d'água. Na Fase 0 não há instâncias globais com processo ([04-extensions.md](04-extensions.md#combinações-válidas)).


### Eventos de manutenção no M0.9

O [ADR-048](12-maintenance.md#eventos-e-compatibilidade) define os eventos de planos,
preparação/conclusão de manutenção e rollback de lote; estende ext.rolled_back e
eventos de runtime com operation_id/from. O payload antigo continua aceito no
histórico. No M0.9, runtime gerenciado ausente acrescenta o motivo estável
`check:runtime_required` a ext.failed, antes de executar dependências; nova tentativa
exige nova proposta após instalação humana do runtime. ext.promoted de proposta em lote aponta para maintenance_intents, pela
associação explícita, sem intenção individual fictícia. Nenhum método update.*,
runtime.list ou login.issue é adicionado ao Kernel Protocol por essa extensão.
