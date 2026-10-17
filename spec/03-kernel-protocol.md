# 03 — Kernel Protocol

Protocolo entre o core e extensões para serviços do kernel. Ferramentas, resources e hooks usam MCP; tudo que é serviço do kernel usa este protocolo.

## Transporte

- JSON-RPC 2.0, uma mensagem JSON UTF-8 por linha.
- Unix socket por instância. Caminho em `FICTOR_KERNEL_SOCKET`, token em `FICTOR_KERNEL_TOKEN`.
- Tamanho máximo de mensagem: 16 MiB.
- A primeira requisição DEVE ser `kernel.hello`. Antes dela, qualquer outra requisição recebe `UNAUTHENTICATED` e a conexão é fechada.
- Só existe canal se o manifest declarar pelo menos um escopo em `kernel`.

## Escopos

O manifest declara os escopos em `kernel: [...]`. O core recusa com `SCOPE_DENIED` métodos fora dos escopos concedidos.

| Escopo | Métodos | Observação |
|---|---|---|
| `events.read` | `events.get`, `events.path`, `events.query` | Instância de sessão: só a linhagem da própria sessão. Instância global: todas as sessões. |
| `events.write` | `events.append` | Kinds `x.<ext_id>.*`. O harness também pode `assistant.*` e `harness.*`. |
| `sessions` | `sessions.get`, `sessions.fork`, `sessions.delegate` (Fase 2), `sessions.complete` (Fase 2) | |
| `sessions.input` | `sessions.input` | Injeta entrada e dispara um turno do agente. |
| `blobs` | `blobs.put`, `blobs.get` | Conhecer o hash é a capacidade de leitura. |
| `kv` | `kv.get`, `kv.set`, `kv.delete`, `kv.list` | Namespace = `ext_id`. |
| `tools` | `tools.list`, `tools.call` | |
| `hooks` | `hooks.invoke` | |
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
// blobs.put — escopo blobs. Máx. 32 MiB por chamada.
params: { text?: string; base64?: string; mime?: string }
result: { hash: BlobRef }

// blobs.get — escopo blobs
params: { hash: BlobRef }
result: { base64: string; mime: string; size: number }

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
// ext.propose — escopo ext.propose. Máx. 500 arquivos e 5 MiB no total.
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
| -32011 | `EXT_UNAVAILABLE` | Extensão desativada, em crash loop ou caiu durante a chamada. |
| -32012 | `CANCELLED` | Cancelado pelo usuário. |

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
| `model.call` | core | `{provider, path, status, duration_ms, req_blob, resp_blob, bytes_in, bytes_out}` |
| `tool.call` | core | `{call_id, name, arguments, origin: "harness" \| "ui"}` |
| `tool.result` | core | `{call_id, content, structured?, is_error, duration_ms}` |
| `tool.denied` | core | `{call_id, name, reason: "policy" \| "user", message?}` |
| `approval.requested` | core | `{approval_id, kind, title}` |
| `approval.decided` | user | `{approval_id, decision, scope}` |
| `hook.failed` | core | `{point, ext_id, error}` |
| `net.denied` | core | `{ext_id, host, count}` |
| `ext.started`, `ext.stopped`, `ext.crashed`, `ext.tools_changed` | core | `{ext_id, key, instance_id, ...}` — sessão `sys` |
| `ext.proposed`, `ext.promoted`, `ext.rejected`, `ext.rolled_back` | core ou user | `{proposal_id?, ext_id, key}` — sessão `sys` |

### Gravados pelo harness

| Kind | Payload |
|---|---|
| `assistant.message` | `{text, reasoning?, tool_call_ids: string[], provider, model, stop_reason, usage?: {input_tokens, output_tokens, cache_read_tokens?, cache_write_tokens?}}` |
| `harness.local_tool` | `{call_id, name, arguments, result, is_error}` — tools locais (`load_skill`, `todo_write`, `propose_extension`, `delegate`); resultado grande em blob |
| `harness.tool_skipped` | `{call_id, name, reason, ext_id?}` — chamada barrada por hook ou por aprovação customizada negada |
| `harness.compaction` | `{summary, covers_until_event_id}` |
| `harness.continue` | `{text, ext_id}` — continuação pedida por hook `turn.end` |
| `harness.error` | `{message, retryable}` |

### Gravados por outras extensões

`x.<ext_id>.<nome>` com payload livre.

### Proveniência dos eventos

| Origem | `trust` | `sensitivity` |
|---|---|---|
| `user.message`, `session.*`, `approval.decided` | trusted | public |
| `tool.result` | ver [05-security.md](05-security.md#proveniência) | classificação da tool |
| `ui.event` de surface, `ext.input` | `output_trust` default da extensão (`tools.default`), senão untrusted | public |
| `events.append` por extensão | trusted | public |
| demais eventos do core | trusted | public |

Eventos gravados por extensões não acendem flags. As flags da sessão continuam cumulativas, então conteúdo derivado em sessão contaminada continua sob U.
