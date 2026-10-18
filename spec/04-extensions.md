# 04 — Extensões

Uma extensão é um bundle (diretório) com um manifest `fictor.yaml` na raiz. Ela pode fornecer, em qualquer combinação: tools MCP, hooks, surfaces de UI (MCP Apps), skills, comandos e o loop do agente (`role: harness`).

## Estrutura do bundle

```text
<bundle>/
├── fictor.yaml          manifest (obrigatório)
├── dist/server.mjs      entry do runtime (nome livre, definido em runtime.entry); um único arquivo empacotado, ou
├── package.json, package-lock.json   dependências resolvidas na quarentena (node_modules/)
├── skills/<nome>/SKILL.md
├── prompts/*.md         prompts de comandos
├── ui/*.html            resources ui:// servidos como surfaces
├── tests/               testes executados no pipeline
└── evals/               casos de eval (Fase 2)
```

Restrições: sem symlinks, sem arquivos especiais, sem `..` em caminhos, nomes em UTF-8 válido. Limites de entradas, bytes, profundidade e tempo em [06-lifecycle.md](06-lifecycle.md#limites).

## Manifest

Schema normativo: [schemas/extension.schema.json](schemas/extension.schema.json). Exemplo completo:

```yaml
schema: 1
id: tdd-autopilot
version: 0.3.1
name: TDD Autopilot
description: Roda a suíte de testes após edições e mostra o status num painel.

role: extension                 # extension | harness
scope: session                  # global | session
runtime:
  kind: node                    # node | python | binary | remote | none
  entry: dist/server.mjs
  args: []
mcp: true                       # o processo fala MCP no stdio

kernel: [ui, kv, timers]        # escopos do Kernel Protocol

hooks_api: 1
hooks:
  - point: tool.after
    priority: 100
    timeout_ms: 2000

tools:
  run_tests:
    effect: write_local
    sensitivity: private
    output_trust: workspace
  panel_refresh:
    effect: read
    sensitivity: private
    output_trust: workspace
    model_visible: false
    ui_callable: true
  default:
    effect: read
    sensitivity: public
    output_trust: trusted

surfaces:
  - id: panel
    slot: right
    resource: ui://tdd-autopilot/panel
    title: TDD

skills: skills
commands:
  - name: tdd
    description: Roda os testes e corrige falhas
    prompt: prompts/tdd.md

permissions:
  fs:
    read: ["${workspace}"]
    write: ["${workspace}/target", "${ext_data}"]
  net:
    allow: []
  models: []
  spawn: true
  secrets: []
  env: {}

isolation: os                   # os | container (Fase 3) | vm (Fase 4)
tests:
  command: ["node", "--test", "tests/"]
evals: evals
```

### Campos

| Campo | Obrigatório | Descrição |
|---|---|---|
| `schema` | sim | Sempre `1`. |
| `id` | sim | `^[a-z][a-z0-9]*(-[a-z0-9]+)*$`, até 40 caracteres. Sem `_`. |
| `version` | sim | SemVer 2.0.0, inclusive pré-release e `+build`, até 64 caracteres. Pode se repetir entre builds; o store distingue por hash. Ordem: precedência SemVer, que ignora `+build`; empates são desfeitos pela data de aprovação. |
| `name`, `description` | `description` sim | Texto para UI e catálogo. |
| `role` | não | `extension` (default) ou `harness`. Ver [Combinações válidas](#combinações-válidas). |
| `hooks_api` | se `hooks` | Versão da API de hooks esperada (atual: `1`). |
| `scope` | não | `global` (default) ou `session`. Extensões globais com processo só a partir da Fase 1. |
| `runtime` | sim | Ver [Runtimes](#runtimes). |
| `mcp` | não | Default `true` se `runtime.kind` ≠ `none`, `false` se `none`. |
| `kernel` | não | Escopos do [Kernel Protocol](03-kernel-protocol.md#escopos). |
| `hooks` | não | Lista de `{point, priority?, timeout_ms?}`. Exige tool `hook_<point>` no servidor. |
| `tools` | não | Classificação por tool e `default`. Ver [Classificação](#classificação-de-tools). |
| `surfaces` | não | Lista de `{id, slot, resource, title}`. |
| `skills` | não | Diretório de skills. Default `skills` se existir. |
| `commands` | não | Lista de `{name, description, prompt}`. |
| `permissions` | não | Ver [Permissões](#permissões). Ausente = nada. |
| `isolation` | não | `os` (default), `container`, `vm`. |
| `tests` | não | `{command: string[]}` executado no sandbox durante as checagens. |
| `evals` | não | Diretório de evals (Fase 2). |

### Combinações válidas

Regras bloqueantes na validação (etapa 2 do pipeline); o schema cobre as estruturais.

| Caso | Exige | Proíbe |
|---|---|---|
| `runtime.kind: none` | `mcp: false` (ou ausente) | `role: harness`, `kernel`, `hooks`, `surfaces`, `tools`, `permissions`. Permite só `skills`, `commands`, `tests`, `evals`. |
| `runtime.kind: remote` (Fase 3) | `mcp: true` (ou ausente), `scope: global` | `role: harness`, `kernel`, `hooks`, `permissions` (o core deriva a rede do host de `runtime.url`), `isolation` diferente de `os` |
| `role: harness` | runtime com processo (`node`, `python`, `binary`), `scope: session`, `mcp: false` | `hooks`, `surfaces`, `tools` |
| Runtime com processo e `mcp: false` | `kernel` com pelo menos um escopo | `hooks`, `surfaces`, `tools` |
| `scope: global` com runtime com processo | Fase 1 ou posterior. Na Fase 0, o instalador recusa com motivo `phase:global`, porque a marca d'água ainda não existe | — |

`hooks` e `surfaces` exigem um servidor MCP, então só existem com `mcp: true`.

## Runtimes

| `kind` | Execução | Dependências (resolvidas na quarentena) |
|---|---|---|
| `node` | `node --permission <flags> <entry> <args>`. Entry `.mjs`, `.cjs`, `.js` ou `.ts` (o Node remove os tipos; só sintaxe que pode ser apagada) | Nenhuma, se o entry já é um arquivo empacotado (como as extensões padrão, feitas com `vp pack`). Senão, `npm ci --ignore-scripts` com `package-lock.json` obrigatório. |
| `python` | `python <entry> <args>` com `PYTHONPATH=<bundle>/.pydeps`; o Python é instalado pelo uv do gerenciador de runtimes | `uv pip install --target .pydeps -r requirements.lock` (ou export do `uv.lock`). |
| `binary` | `<bundle>/<entry> <args>` | Binário incluído no bundle; hash fixado como qualquer arquivo. |
| `remote` | Sem processo local. O gateway conecta via HTTP streamable do MCP à `runtime.url`, através do egress proxy (Fase 3). | — |
| `none` | Sem processo. Bundle só de skills e comandos. | — |

Flags do modelo de permissões do Node derivadas das permissões efetivas aprovadas: manifest com os [overrides humanos validados](06-lifecycle.md#overrides-humanos). É defesa em profundidade; a fronteira principal continua sendo o sandbox do SO e o egress proxy. Runtime, sandbox e proxies recebem o mesmo resultado, sem reconstruir defaults ou merges próprios.

| Permissão | Flag |
|---|---|
| sempre | `--permission`; nunca `--allow-addons` nem `--allow-wasi` |
| `fs.read` | um `--allow-fs-read=<caminho>` por caminho: bundle, runtime e caminhos expandidos |
| `fs.write` | um `--allow-fs-write=<caminho>` por caminho: caminhos expandidos e `${tmp}` |
| `spawn: true` | `--allow-child-process` e `--allow-worker` |
| `net.allow` ou `models` não vazios, ou escopos de kernel | `--allow-net`, nas versões em que o modelo de permissões restringe a rede. O destino continua sendo filtrado pelo proxy. |

O executável de cada runtime vem do gerenciador de runtimes ([02-core.md](02-core.md#runtimes)). O diretório da versão ativa é montado só leitura no sandbox. Em runtime nenhuma extensão baixa código (invariante I7).

## Escopo e templates de caminho

| Template | Valor | Disponível em |
|---|---|---|
| `${workspace}` | workspace da sessão | só `scope: session` |
| `${ext_data}` | global: `$FICTOR_HOME/extensions/data/<id>`; instância de sessão: `$FICTOR_HOME/extensions/data/<id>/sessions/<session_id>` | todas |
| `${ext_root}` | raiz do bundle no store (sempre legível, nunca gravável) | todas |
| `${store}` | `$FICTOR_HOME/extensions/store` (somente leitura) | só `role: harness` |
| `${tmp}` | tmpfs/diretório temporário da instância | todas |

Também são aceitos caminhos absolutos e `~/...`. Qualquer caminho fora dos templates impede promoção automática. Caminhos e templates continuam sujeitos às [reservas e origens admitidas](05-security.md#árvores-de-montagem-e-origens-admitidas) do ADR-044: aprovação não autoriza sobrepor mounts internos nem importar um tipo de filesystem recusado. `${tmp}` é o temporário interno, sem importar conteúdo do `/tmp` do host; referências compatíveis a recursos já montados são normalizadas sem bind adicional.

Regras de validação por escopo (bloqueantes no pipeline):

- `${workspace}` em extensão `scope: global` é erro.
- Os escopos de kernel `tools`, `hooks` e `sessions` exigem `scope: session` ou `role: harness`.
- Extensões com `role: harness` ou com o escopo `tools` alimentam o modelo, então não acessam dados por fora do core: `fs.read` e `fs.write` só com `${store}`, `${ext_root}`, `${ext_data}` e `${tmp}`; `net.allow` e `secrets` vazios; `models` é permitido. Workspace, web e qualquer outro dado chegam a elas apenas por `tools.call` (invariante I11).

## Permissões

| Campo | Tipo | Significado |
|---|---|---|
| `fs.read` | caminhos | Leitura. O bundle é sempre legível. |
| `fs.write` | caminhos | Escrita (implica leitura). |
| `net.allow` | padrões de host | Destinos permitidos no egress proxy. `[]` = sem rede. |
| `models` | ids de provider ou `*` | Acesso ao model proxy. |
| `spawn` | bool | Pode criar subprocessos (dentro do mesmo sandbox). |
| `secrets` | `{name, env}[]` | Segredo injetado como variável de ambiente. Ver [05-security.md](05-security.md#segredos). |
| `env` | mapa | Variáveis estáticas. Não podem usar nomes reservados. |

Listas e `env` ausentes significam vazios; `spawn` ausente significa `false`. As bases implícitas do sandbox continuam valendo. O humano pode retirar capacidades pela prova de restrição dos [overrides](06-lifecycle.md#overrides-humanos), sem alterar o bundle. Overrides não ampliam permissões nem dispensam as regras semânticas abaixo; o resultado efetivo alimenta supervisor, runtime e proxies.

### Variáveis de ambiente reservadas

O supervisor define o ambiente; o manifest não pode sobrescrevê-lo nem injetar variáveis que mudam o carregamento de código ou o roteamento de rede. Um nome reservado em `permissions.env` ou em `permissions.secrets[].env` é erro bloqueante na validação (etapa 2 do pipeline). O mesmo nome em `env` e em `secrets` também é erro.

| Tipo | Nomes |
|---|---|
| Prefixos | `FICTOR_`, `LC_`, `LD_`, `DYLD_`, `DENO_`, `BASH_FUNC_` |
| Ambiente base | `PATH`, `HOME`, `TMPDIR`, `TMP`, `TEMP`, `LANG`, `LANGUAGE`, `USER`, `LOGNAME`, `SHELL`, `PWD` |
| Rede e proxy | `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, `NODE_USE_ENV_PROXY` |
| Certificados | `SSL_CERT_FILE`, `SSL_CERT_DIR`, `NODE_EXTRA_CA_CERTS`, `NODE_TLS_REJECT_UNAUTHORIZED`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_NO_VERIFY` |
| Carregamento de código | `NODE_OPTIONS`, `NODE_PATH`, `PYTHONPATH`, `PYTHONHOME`, `PYTHONSTARTUP`, `PYTHONUSERBASE`, `BASH_ENV`, `ENV`, `PROMPT_COMMAND`, `PERL5OPT`, `RUBYOPT`, `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM` |
| Agentes e sessão gráfica | `SSH_AUTH_SOCK`, `GPG_AGENT_INFO`, `GNUPGHOME`, `DOCKER_HOST`, `XDG_RUNTIME_DIR`, `DBUS_SESSION_BUS_ADDRESS`, `DISPLAY`, `WAYLAND_DISPLAY` |

Variáveis em minúsculas não podem ser declaradas (o schema só aceita `^[A-Z][A-Z0-9_]*$`). O schema rejeita os nomes desta tabela; o supervisor confere de novo no spawn.

### Sintaxe de `net.allow`

| Forma | Exemplo | Casa |
|---|---|---|
| `*` | `*` | Qualquer nome DNS na porta 443, se todos os endereços resolvidos forem públicos. |
| Domínio | `api.github.com` | Exatamente esse nome, porta 443. |
| Subdomínios | `*.github.com` | Subdomínios, sem o domínio raiz, porta 443. |
| Domínio com porta | `registry.local.test:8443` | Esse nome nessa porta. |
| IPv4 com porta | `127.0.0.1:11434` | Esse IP nessa porta. A porta é obrigatória para IP literal. |
| IPv6 com porta | `[::1]:11434`, `[2001:db8::10]:8080` | Esse IP nessa porta. Colchetes e porta obrigatórios. |

Regras semânticas (etapa 2 do pipeline):

- IPv6 é normalizado na forma da RFC 5952 antes de gravar no lock.
- Zonas (`[fe80::1%eth0]:80`) não são aceitas.
- IPv4 mapeado em IPv6 (`[::ffff:127.0.0.1]:80`) não é aceito; escreva a forma IPv4.
- IPv6 dentro de `64:ff9b::/96` ou de um prefixo de `[egress] nat64_prefixes` não é aceito; escreva o IPv4 embutido ([02-core.md](02-core.md#nat64)).
- `*:porta`, curingas no meio do nome e faixas de IP (CIDR) não são aceitos.
- Destinos não públicos e `localhost` só casam por regra exata com porta ([02-core.md](02-core.md#connect-https)).

## Classificação de tools

Cada tool tem as seguintes propriedades usadas pela política e pelo catálogo:

| Propriedade | Valores | Significado |
|---|---|---|
| `effect` | `read` | Só lê. Não altera nada nem comunica para fora. |
| | `write_local` | Altera estado local dentro das permissões do sandbox. |
| | `external` | Pode comunicar para fora da máquina ou mudar estado externo. Toda tool com rede é `external`, inclusive um "fetch": a URL pode carregar dados. |
| `sensitivity` | `public`, `private` | O resultado contém dados privados (arquivos do usuário, email, documentos). |
| `output_trust` | `trusted`, `untrusted`, `workspace` | O resultado pode conter instruções de terceiros? `workspace` herda `workspace_trust` da sessão. |
| `model_visible` | bool | Aparece em `tools.list`. Default `true`. |
| `ui_callable` | bool | Pode ser chamada por surfaces da própria extensão. Default `false`. |
| `timeout_ms` | 1000–600000 | Default 120000. |

A base é o objeto inteiro `tools.<nome>` do manifest, senão `tools.default`, senão um objeto vazio. Campos ausentes nesse objeto recebem `effect: external`, `sensitivity: private`, `output_trust: untrusted`, `model_visible: true`, `ui_callable: false` e `timeout_ms: 120000`; uma classificação nominal não herda campos do `default` do manifest.

O core aplica os [overrides humanos](06-lifecycle.md#overrides-humanos) da versão aprovada: patch `default` comum, depois patch nominal por campo, preservando as imposições estruturais de segurança. O mesmo resultado efetivo alimenta catálogo, chamadas e proveniência. O processo não consegue alterá-lo em runtime. Classificações declaradas por terceiros são revisadas no pipeline. `model_visible: false` oculta do catálogo, sem ser uma regra de negação de toda chamada por nome; `ui_callable: false` impede chamadas de surfaces.

## Hooks

Hooks são tools MCP com nome reservado `hook_<point>` (pontos trocados por `_`), invisíveis ao modelo. O harness define os hook points e chama `hooks.invoke`; o core faz o fan-out ([02-core.md](02-core.md#fan-out-de-hooks)) sem interpretar o conteúdo.

Hooks servem para qualidade e customização. Eles nunca substituem a política do core: um hook `tool.before` que responde "allow" não dispensa aprovação.

Hook points definidos pelo harness padrão, `hooks_api: 1`:

| Point | Modo | Payload | Retorno (`payload` / sinais) | Semântica no harness |
|---|---|---|---|---|
| `session.start` | collect | `{session}` | sinal `system_append: string` | Textos concatenados ao system prompt da sessão. |
| `prompt.submit` | pipeline | `{message: Part[]}` | `payload` / sinal `block: {reason}` | Transforma a mensagem; `block` interrompe o turno e mostra o motivo. |
| `context.assemble` | pipeline | `{system, messages, tools}` | `payload` | Transforma o contexto final antes da chamada ao modelo. |
| `model.route` | collect | `{model, reason}` | sinal `model: string` | O resultado de menor prioridade numérica vence. |
| `stream.chunk` | pipeline | `{delta: {text?, reasoning?}}` | `payload` | Chamado com deltas agrupados a cada 100 ms. Timeout fixo de 200 ms. |
| `tool.before` | pipeline | `{call: {name, arguments}}` | `payload` (argumentos reescritos) / sinais `decision: "deny" \| "ask"`, `reason` | `deny` vence. `ask` faz o harness chamar `approval.request` antes de `tools.call`. |
| `tool.after` | pipeline | `{call, result}` | `payload` / sinal `follow_up: string` | `follow_up` vira nota anexada ao resultado. |
| `turn.end` | collect | `{turn_event_ids}` | sinal `continue: string` | Primeiro `continue` inicia outro turno com esse texto. Máximo 3 encadeados. |
| `compact` | collect | `{event_ids}` | sinal `summary: string` | Primeiro resumo substitui a compactação padrão. |

Novos hook points são adicionados no harness sem mudar o core. Mudanças incompatíveis incrementam `hooks_api`; o harness recusa extensões com `hooks_api` não suportado.

## Surfaces (MCP Apps)

A UI de uma extensão segue o padrão MCP Apps: resources `ui://` com HTML, renderizados pelo shell num iframe isolado, comunicando por postMessage. Detalhes do host estão em [08-shell.md](08-shell.md#host-de-mcp-apps).

Dois usos:

- **Painel**: declarado em `surfaces` com um `slot` (`left`, `right`, `bottom`). O shell monta como aba no slot.
- **Resultado de tool**: a tool declara o resource UI conforme o MCP Apps. O shell renderiza o iframe sob o card da chamada no chat, recebendo input e resultado da tool.

Uma surface só chama tools da própria extensão com `ui_callable: true` na classificação efetiva aprovada, sempre via `tools.call` do core (origem `ui`, mesma política). Eventos de interface vão para a extensão como notificação `ui.event`.

Resources UI DEVEM ser autocontidos (HTML, CSS e JS inline ou servidos do próprio bundle). O iframe não tem acesso à rede. O design system `fx-*` está disponível em `/ds/fx.js` e `/ds/fx.css` no host de surfaces.

## Skills

Formato Agent Skills sem alterações: `skills/<nome>/SKILL.md` com frontmatter `name` e `description`, mais arquivos auxiliares. O harness lista via `catalog.list`, coloca só nome e descrição no contexto e carrega o corpo sob demanda. Scripts de skills nunca são executados pelo core; só rodam se o modelo chamar uma tool de shell, dentro do sandbox dessa tool.

## Comandos

`commands[]` vira entrada na paleta do shell e `/nome` no chat. Ao escolher, o shell envia `user.message` com `command: {ext_id, name, args}`. O harness lê `prompt_path` (via `catalog.list`), substitui `$ARGUMENTS` por `args` e usa o resultado como a mensagem.

## SDK `@fictor/sdk`

Pacote TypeScript para Node que esconde MCP e Kernel Protocol. Usa o SDK oficial de MCP em TypeScript para o servidor. Usa só APIs web padrão e módulos `node:`, sem APIs exclusivas de um runtime.

```ts
import { defineExtension, z } from "@fictor/sdk";

export default defineExtension({
  tools: {
    run_tests: {
      description: "Roda a suíte de testes do workspace e retorna as falhas.",
      input: z.object({ filter: z.string().optional() }),
      async run({ filter }, ctx) {
        const out = await ctx.exec(["cargo", "test", ...(filter ? [filter] : [])], { cwd: ctx.workspace });
        await ctx.ui.emit("tdd.status", { ok: out.code === 0 });
        return { text: out.stdout.slice(-20_000), isError: out.code !== 0 };
      },
    },
  },
  hooks: {
    "tool.after": async ({ call, result }, ctx) => {
      if (call.name.endsWith("__edit_file")) return { follow_up: "Considere rodar run_tests." };
      return {};
    },
  },
  resources: {
    "ui://tdd-autopilot/panel": { file: "ui/panel.html" },
  },
  onUiEvent: async (ev, ctx) => {},
  onTimer: async (id, payload, ctx) => {},
});
```

Responsabilidades do SDK:

- Subir o servidor MCP no stdio e registrar tools, hooks (`hook_*`) e resources.
- Conectar ao Kernel Protocol se `FICTOR_KERNEL_URL` existir e expor `ctx.kv`, `ctx.events`, `ctx.ui`, `ctx.timers`, `ctx.tools` conforme os escopos.
- Gerar IDs String dentro do [teto do Kernel Protocol](03-kernel-protocol.md#ids-admissão-e-correlação) de 256 bytes UTF-8 (por exemplo, contador decimal em string ou ULID), sem reutilizar um ID na mesma conexão, e correlacionar respostas por ID. EOF ou resposta que viole o protocolo encerra o transporte e conclui todas as pendências locais com falha/resultado desconhecido. Timeout conclui a chamada correspondente com resultado desconhecido; resposta tardia desse ID é descartada, sem reassociá-la a outro pedido. Não repetir automaticamente chamadas sem resposta ou que receberam `TOO_LARGE`, pois efeitos podem ter ocorrido. Reconectar/hello não reenvia chamadas anteriores. Essa regra é do cliente Kernel Protocol, sem mudar os IDs do servidor MCP.
- `ctx.exec`: subprocesso com timeout e truncamento de saída.
- Validar que hooks implementados batem com `hooks` do manifest na inicialização.

O SDK não é uma API do core. Ele entra em cada bundle de duas formas: embutido pelo `vp pack` no arquivo empacotado (extensões padrão), ou como dependência resolvida na quarentena. Neste caso, o instalador usa a cópia de `@fictor/sdk` embutida no binário, sem baixar do npm, e ela conta como pacote confiável.

## Importação de formatos externos (Fase 3)

O instalador converte formatos externos em bundles Fictor. O manifest gerado usa defaults restritivos e é revisado por humano.

| Origem | Conversão |
|---|---|
| Servidor MCP stdio (npm, PyPI, binário) | `runtime` correspondente; `tools.default` restritivo; classificação revisada na aprovação. |
| Servidor MCP remoto (HTTP) | `runtime.kind: remote`, `net.allow` = host do servidor, `output_trust: untrusted`. |
| Skill (repositório com `SKILL.md`) | Bundle `runtime.kind: none` com `skills/`. |
| Plugin Claude Code (`.claude-plugin/plugin.json`) | `skills/` → `skills`; `commands/*.md` → `commands`; cada entrada de `.mcp.json` → bundle MCP separado; `hooks/hooks.json` e `agents/` não suportados até a Fase 4. |
| Entrada do MCP Registry (`server.json`) | Resolve o pacote declarado e aplica a conversão de servidor MCP. |
