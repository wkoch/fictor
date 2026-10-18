# 08 — Shell web

O shell é a UI confiável. É servido pelo core, roda no navegador e é a única coisa que exibe e decide aprovações e propostas.

## Stack e build

- TypeScript, Lit, Vite, markdown-it, DOMPurify, highlight.js.
- `vp build` (Vite) gera `shell/dist/`, embutido no binário com `rust-embed`.
- Desenvolvimento (no toolbx): build em modo watch + `fictor serve --shell-dir shell/dist`. Assim o desenvolvimento usa os mesmos hosts, CSP e autenticação de produção.

## Hosts, portas e autenticação

Regras normativas em [05-security.md](05-security.md#endurecimento-web). Resumo:

| Host | Conteúdo |
|---|---|
| `http://127.0.0.1:<listen>` | shell, `/ws`, `/api/*`, `/login` |
| `http://localhost:<surface_port>` | só resources de surfaces e `/ds/*` |

### Endpoints HTTP do shell

| Método e caminho | Função |
|---|---|
| `GET /login?t=<token>` | Troca o token de uso único pelo cookie e redireciona para `/`. |
| `GET /`, `GET /assets/*` | Assets embutidos. |
| `GET /ws` | Upgrade para WebSocket. |
| `POST /api/blobs` | Upload de anexo (até 50 MiB). Retorna `{hash, size}`. O `Content-Type` enviado pelo navegador é ignorado; o shell põe o MIME e o nome do arquivo no `Part` da mensagem. |
| `GET /api/blobs/<hash>[?name=<nome>]` | Download com `X-Content-Type-Options: nosniff`. O tipo vem só da assinatura dos bytes: PNG, JPEG, GIF e WebP são servidos inline com o tipo detectado; todo o resto, inclusive SVG e HTML, como `application/octet-stream` com `Content-Disposition: attachment`. `name` (sanitizado: sem `/`, `\`, controles e aspas; até 200 caracteres) só define o nome do download. |

### Endpoints do host de surfaces

| Método e caminho | Função |
|---|---|
| `GET /r/<mount_token>` | HTML do resource `ui://` da montagem. O token (128 bits) mapeia para `(ext_id, resource, session_id?)` e expira quando a surface é desmontada. Conteúdo obtido via `resources/read` da extensão. |
| `GET /ds/fx.js`, `GET /ds/fx.css` | Design system. |

## Protocolo WebSocket

Mensagens JSON. Requisições do cliente têm `id`; o servidor responde `{type: "ack", id, result?}` ou `{type: "error", id, code, message}`.

### Cliente → servidor

| `type` | Campos | Efeito |
|---|---|---|
| `hello` | — | Servidor responde com `state`. |
| `session.create` | `{title?, workspace, workspace_trust?, mode?, model?, harness?}` | Cria sessão. |
| `session.open` | `{session_id}` | Assina a sessão. Servidor envia `session.snapshot`. |
| `session.close` | `{session_id}` | Cancela a assinatura. |
| `session.fork` | `{from_event_id, title?}` | Fork. |
| `session.set_mode` | `{session_id, mode}` | Grava `session.mode_changed`. |
| `session.set_model` | `{session_id, model}` | Grava `session.model_changed`. O valor é opaco para o core. |
| `session.archive` | `{session_id}` | Arquiva; encerra harness e instâncias da sessão. |
| `session.cancel` | `{session_id}` | Cancela o turno. |
| `user.message` | `{session_id, content: Part[], command?}` | Grava `user.message`. Anexos sobem antes por `POST /api/blobs`. |
| `events.page` | `{session_id, before_id, limit}` | Histórico mais antigo. |
| `search` | `{text, limit?}` | Busca FTS5 entre sessões. |
| `approval.decide` | `{approval_id, nonce, decision: "allow" \| "deny", scope?, message?}` | Decide aprovação. |
| `ui.event` | `{session_id, surface_id?, type, payload}` | Ação do chat (`fx-action`) ou evento de surface. |
| `app.request` | `{surface_id, request_id, method, params}` | Ponte MCP Apps. |
| `ext.list` | — | Extensões e estado. |
| `proposal.list` | `{state?}` | Propostas. |
| `proposal.get` | `{proposal_id}` | Detalhe: checagens, diff, pacotes, relatório, `nonce`. |
| `proposal.decide` | `{proposal_id, nonce, decision: "approve" \| "reject", overrides?}` | Decide proposta; `overrides` segue [o schema](schemas/overrides.schema.json) e o [contrato de aplicação](06-lifecycle.md#overrides-humanos). |
| `ext.rollback` | `{ext_id, to?}` | Rollback. |
| `ext.set_enabled` | `{ext_id, enabled}` | Liga ou desliga. |
| `ext.reset_crashes` | `{ext_id, key?, session_id?}` | Reset humano auditado da recuperação; seleção e semântica de [02-core.md](02-core.md#reabilitação-humana). Não habilita nem executa a extensão. |
| `ext.reset_state` | `{ext_id}` | Limpa kv, `${ext_data}` global e marca d'água (Fase 1). Exige confirmação no modal. |
| `update.check` | — | Verifica atualizações de runtimes, extensões e core. Servidor responde `update.candidates`. |
| `update.apply` | `{items: string[] \| "all_passing", nonce}` | Aplica os itens escolhidos, ou todos os que passaram nas checagens sem ampliar permissões. |
| `update.rollback` | `{batch_id, nonce}` | Reverte um lote. |
| `runtime.rollback` | `{name, nonce}` | Volta o runtime à versão anterior. |
| `workspace.clear_flag` | `{workspace}` | Apaga a flag U do workspace. Exige confirmação no modal, que mostra a sessão de origem. |

### Servidor → cliente

| `type` | Campos |
|---|---|
| `state` | `{sessions, catalog, approvals_pending, proposals_pending, updates_pending}` |
| `session.snapshot` | `{session, events (até 500 mais recentes do caminho), approvals_pending}` |
| `event` | `{event}` — sessões assinadas e eventos `ext.*` de `sys` |
| `ui` | `{session_id, channel, data}` — de `ui.emit` |
| `approval.request` | `{approval_id, nonce, session_id, kind, title, tool?, arguments?, classification?, origin, flags, taint_reasons, allowed_scopes, rule_of_two: boolean}` |
| `approval.resolved` | `{approval_id, status}` |
| `app.response` | `{surface_id, request_id, result?, error?}` |
| `app.notify` | `{surface_id, method, params}` |
| `catalog.changed` | `{catalog}` |
| `update.candidates` | `{runtimes: [...], extensions: [...], core?: {current, latest}, nonce}` |
| `proposal.updated` | `{proposal_id, state}` |

## Layout

```text
┌ barra: sessão · workspace · modo [plan|default|auto] · modelo · flags U/P · busca · configurações ┐
├ esquerda: sessões (Fase 2: árvore de forks) ┬ centro: chat ┬ direita: abas de surfaces ┤
├ inferior: abas de surfaces "bottom" e log de eventos                                     ┤
└ composer: texto, anexos, /comandos, Enviar, Parar                                       ┘
```

- Colunas laterais recolhíveis. Em telas estreitas, só o chat, com as laterais em gavetas.
- Flags U e P aparecem como badges com tooltip listando os motivos (eventos `session.tainted`).
- Workspace com flag U: badge "workspace contaminado" na barra, com a sessão e o evento de origem e a ação "Revisei, marcar como confiável" (`workspace.clear_flag`).
- Paleta de comandos (Ctrl/Cmd+K): sessões, comandos de extensões, páginas.
- Atalhos: Ctrl/Cmd+Enter envia; Esc no composer cancela o turno em andamento.

## Chat

| Evento | Renderização |
|---|---|
| `user.message` | balão do usuário, anexos |
| `assistant.message` | markdown sanitizado; `reasoning` em bloco recolhível |
| canal `assistant.delta` | texto em streaming até chegar o `assistant.message` |
| `tool.call` + `tool.result` | card: extensão/tool, argumentos (JSON recolhido), estado (pendente, ok, erro, negado), resultado (recolhido, 20 primeiras linhas), badge "externo" se `untrusted`, iframe MCP Apps se a tool tiver `ui_resource` |
| `harness.local_tool` de `todo_write` | lista de tarefas fixa no topo do chat (a mais recente) |
| `session.tainted` | marcador fino na linha do tempo com o motivo |
| `harness.error`, `tool.denied`, `harness.tool_skipped` | aviso inline |
| canal `status` | linha de status sob o composer |
| demais | só no log de eventos |

### Sanitização de markdown

- markdown-it com HTML habilitado, saída passada no DOMPurify com allowlist.
- Tags: `p br hr h1–h6 strong em del code pre blockquote ul ol li table thead tbody tr th td a img details summary kbd sup sub` e as tags `fx-*` do catálogo.
- Atributos: `href` (a), `src` e `alt` (img), `class`, `colspan`, `rowspan`, `align` e os atributos de cada componente `fx-*` listados no catálogo. Nada de `style`, `id` ou `on*`.
- `href`: só `http:`, `https:`, `mailto:`. Abre com `target="_blank" rel="noopener noreferrer"` e mostra a URL completa no hover.
- `img src`: só `fictor-blob:<hash>` (reescrito para `/api/blobs/<hash>`) e `data:image/(png|jpeg|gif|webp)`. Outra origem vira o texto "imagem remota bloqueada" com a URL visível.
- Blocos de código com destaque de sintaxe e botão de copiar.

## Aprovações

- `<dialog>` modal do shell, visualmente distinto do resto da UI. Iframes de surfaces não conseguem desenhar fora da própria área.
- Conteúdo: o listado em [05-security.md](05-security.md#aprovações).
- Botões: "Permitir uma vez", "Permitir nesta sessão", "Sempre permitir", "Negar" (com campo opcional de mensagem). Só os escopos de `allowed_scopes` aparecem.
- Variante Rule of Two: faixa vermelha explicando a combinação (fontes não confiáveis e dados privados já vistos, ação com efeito externo), só "Permitir uma vez" e "Negar".
- Nenhum botão recebe foco inicial. Enter não aprova. Esc fecha o modal sem decidir; a aprovação continua pendente num badge da barra.
- Fila: uma aprovação por vez, com contador.
- Acessibilidade: `aria-modal`, foco preso no diálogo, rótulos explícitos.

## Gerenciador de extensões

Página `#/extensions`, parte da UI confiável.

- **Instaladas**: id, nome, versão ativa, origem, aprovada por, liga/desliga, resumo de permissões (rede, segredos, escrita fora do workspace, hooks, escopos de kernel), badge "segredo exposto", badge com a marca d'água U/P de extensões globais (Fase 1), estado (ativa, desativada, crash loop, tools alteradas). Ações: rollback, desativar, ver versões, limpar estado (Fase 1).
- **Propostas**: um card por proposta com:
  - origem (IA com link para a sessão e badge "sessão contaminada", local, git, mcp);
  - estado e checagens (passou/falhou, com detalhes);
  - diff de permissões, com expansões em vermelho;
  - árvore de arquivos e diff contra a versão ativa (ou conteúdo completo, se nova);
  - pacotes, com os novos destacados;
  - relatório do auditor (Fase 3) e gate de evals (Fase 2);
  - editor de overrides: restringir permissões e ajustar classificação de tools pelo [contrato normativo](06-lifecycle.md#overrides-humanos), mostrando o resultado efetivo;
  - Aprovar / Rejeitar.
- **Recuperação**: listar esperas/bloqueios por chave e sessão, separadamente de `enabled`. A ação humana `ext.reset_crashes` mostra a seleção afetada e limpa somente a recuperação; não reinicia chamadas nem altera o estado da extensão.
- **Atualizações**: página `#/updates`, parte da UI confiável. Mostra runtimes (versão atual e candidata, checksum, resultado do smoke das extensões afetadas), extensões (inclusive propostas com `update_of`) e o aviso de release nova do core, que só se instala pela CLI. Tem o botão "Atualizar tudo", a lista de lotes anteriores com rollback, e um badge na barra quando a checagem automática encontra novidades.

O editor distingue valor herdado de valor explícito, inclusive `false`; objetos estruturais vazios não apagam campos irmãos. Listas presentes substituem as anteriores, `[]` retira suas entradas, e `env: {}` retira as variáveis declaradas. `null` é inválido. Mostra o efeito do patch comum `default` e do nominal, valida inclusive nomes com patch `{}` e informa as bases implícitas do sandbox que continuam disponíveis. Ocultar do catálogo não é negar todas as chamadas por nome. A decisão congela o objeto exato com a aprovação; alterações posteriores de overrides exigem nova versão do manifest e nova revisão, preservando a identidade de versões já aprovadas. A UI não oferece ajustes que violem a prova de restrição nem apresenta erro como aprovação parcial.

## Host de MCP Apps

O shell implementa o lado host do padrão MCP Apps. Registrar no código a versão da spec implementada; os nomes exatos de métodos seguem essa versão.

- **Montagem**: `<iframe sandbox="allow-scripts allow-forms" src="http://localhost:<surface_port>/r/<mount_token>">`.
- **Canal**: postMessage com JSON-RPC. Mensagens são aceitas só se `event.source === iframe.contentWindow`. Como a origem do iframe é opaca, respostas usam `targetOrigin "*"` e nunca carregam dados de outra extensão ou sessão.
- **Requisições app → host suportadas**:
  - handshake de inicialização do MCP Apps;
  - `tools/call`: só tools da própria extensão com `ui_callable: true` efetivo, via `app.request` → `tools.call` do core com origem `ui` (mesma política);
  - `resources/read`: só resources da própria extensão;
  - abrir link: o shell mostra a URL completa e pede confirmação antes de `window.open(url, "_blank", "noopener")`;
  - enviar mensagem ao chat: vira `ui.event` para o harness da sessão, com actor `ext:<id>@ui`, exibido como "[app <id>]".
- **Notificações host → app**: input e resultado da tool (surfaces de resultado), contexto do host (tema, idioma), mudança de tamanho.
- Métodos não suportados: erro JSON-RPC "method not found".

## Design system

Web components Lit com prefixo `fx-`, tokens em propriedades CSS `--fx-*`, tema claro e escuro (`prefers-color-scheme`). Os mesmos arquivos servem o chat e as surfaces.

| Tag | Atributos | Uso |
|---|---|---|
| `fx-card` | `title`, `tone` | contêiner |
| `fx-badge` | `tone` (`neutral`, `info`, `success`, `warning`, `danger`) | status |
| `fx-callout` | `tone` | aviso em destaque |
| `fx-stat` | `label`, `value`, `delta`, `tone` | métrica |
| `fx-kv` | — (filhos `dt`/`dd`) | pares chave-valor |
| `fx-table` | `sortable` | envolve um `<table>` |
| `fx-code` | `lang` | código com copiar |
| `fx-diff` | — (texto unificado) | diff |
| `fx-progress` | `value`, `max` | progresso |
| `fx-tabs`, `fx-tab` | `label` | abas |
| `fx-split` | `ratio` | dois painéis |
| `fx-action` | `action`, `payload` (JSON) | botão; no chat envia `ui.event {type: "action"}` ao harness; numa surface, notifica a extensão dona |
| `fx-chart` (Fase 2) | `spec` (JSON) | gráfico |
| `fx-terminal` (Fase 2) | — | terminal somente leitura |

`shell/ds/CATALOG.md` descreve tags e atributos em até ~1500 tokens. É usado pela skill de autoria e PODE entrar no system prompt.

Acessibilidade em todos os componentes: navegação por teclado, foco visível, contraste AA, `prefers-reduced-motion`.
