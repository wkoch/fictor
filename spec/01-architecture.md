# 01 — Arquitetura

## Camadas

```text
 Navegador (shell web servido pelo core)
 ┌ UI confiável: chat, aprovações, gerenciador ┐  ┌ iframes de surfaces (host separado) ┐
 └──────────────────────┬──────────────────────┘  └────────────────┬────────────────────┘
                        └──────── HTTP + WebSocket (cookie, Origin) ┘ (via postMessage → shell)
 ┌──────────────────────────────────────▼───────────────────────────────────────────────┐
 │ L0 CORE (Rust, binário `fictor`)                                                     │
 │ Store (eventos, sessões, blobs, kv) · Supervisor · Gateway MCP · Kernel Protocol     │
 │ Política + aprovações · Sandbox launcher · Egress proxy · Model proxy · Instalador   │
 └───────┬──────────────────────────┬─────────────────────────────┬─────────────────────┘
         │ Kernel Protocol (socket) │ MCP stdio + Kernel Protocol │ MCP stdio
  ┌──────▼────────┐         ┌───────▼─────────┐           ┌───────▼──────────┐
  │ L1 Harness    │         │ L2 Extensões    │           │ L2 MCP terceiros │
  │ role=harness  │         │ first-party/IA  │           │ normalizados e   │
  │ 1 por sessão  │         │ tools+hooks+UI  │           │ auditados        │
  └───────────────┘         └─────────────────┘           └──────────────────┘
        todos os processos: sandbox do SO + rede só via egress proxy
```

- **L0 Core.** Base de confiança. Não sabe o que é chat, agente ou canvas. A IA não altera o core.
- **L1 Harness.** Extensão com `role: harness`. Implementa o loop do agente, os adapters de provider, a montagem de contexto, compactação e subagentes. Define os hook points. Pode ser trocado e versionado como qualquer extensão. O harness decide qualidade; segurança fica no core.
- **L2 Features.** Todo o resto: tools de arquivo e terminal, web, painéis, skills, MCP de terceiros.

Analogia: kernel / libc / aplicativos.

## Processos

| Processo | Quantidade | Escopo | Canais |
|---|---|---|---|
| `fictor serve` | 1 por `FICTOR_HOME` | máquina | HTTP/WS para o navegador; socket admin para a CLI |
| Harness | 1 por sessão ativa | sessão | Kernel Protocol |
| Extensão `scope: global` | 0 ou 1 por extensão | máquina | MCP stdio; Kernel Protocol se pedir escopos |
| Extensão `scope: session` | 0 ou 1 por (extensão, sessão ativa) | sessão | MCP stdio; Kernel Protocol se pedir escopos |

Regras:

- Processos de extensão sobem sob demanda (lazy): na primeira chamada de tool, hook ou surface. A lista de tools vem do lock (tools fixadas na promoção), então listar tools não exige subir o processo.
- O harness sobe quando a sessão recebe a primeira entrada e morre após `harness.idle_timeout_min` sem atividade.
- Extensões `scope: session` morrem após 15 min sem chamadas ou quando a sessão é arquivada.
- Cada extensão roda no seu próprio namespace de PID, com `__sandbox-init` como PID 1. O encerramento confirma a saída do init e do launcher antes de liberar recursos; grupos POSIX não são a prova de contenção. Um único dono mutante mantém a posse do home durante toda sua vida ([02-core.md](02-core.md#posse-do-diretório-de-dados)).

## Canais

| Canal | Transporte | Uso |
|---|---|---|
| Navegador ↔ core | HTTP + WebSocket em `127.0.0.1` | UI confiável, eventos, aprovações. Ver [08-shell.md](08-shell.md). |
| Navegador ↔ surfaces | iframe em `localhost` (host diferente), postMessage | UI de extensões (MCP Apps). |
| Core ↔ extensão (MCP) | stdio, JSON-RPC delimitado por linha (transporte stdio do MCP) | tools, resources, hooks. O core é o cliente MCP. |
| Core ↔ extensão (Kernel Protocol) | Unix socket por instância no host, exposto dentro do sandbox por `__sandbox-init` como TCP em `127.0.0.1:3129`. JSON-RPC delimitado por linha. | serviços do kernel. Ver [03-kernel-protocol.md](03-kernel-protocol.md#transporte). |
| Extensão → internet | HTTP(S) via egress proxy do core | allowlist por domínio, log, contaminação. |
| Extensão → modelo | HTTP via proxy para o host interno `models.fictor.internal` | o core injeta a chave e repassa via TLS. |
| CLI ↔ core | Unix socket `run/admin.sock` (0600), JSON-RPC por linha | [Contrato administrativo mínimo](02-core.md#canal-administrativo-mínimo); canal separado do Kernel Protocol e do WebSocket. |

## Fluxo de um turno

1. O usuário envia uma mensagem no shell. O WebSocket entrega `user.message`.
2. O core grava o evento `user.message` (actor `user`), garante um processo de harness para a sessão e envia a notificação `session.input`.
3. O harness lê o caminho de eventos (`events.path`) e invoca os hooks `prompt.submit` e `context.assemble` via `hooks.invoke`.
4. O harness escolhe o modelo (hook `model.route`) e faz a requisição HTTP para `http://models.fictor.internal/p/<provider>/...` através do proxy.
5. O core injeta a chave, repassa via TLS, devolve o stream e grava o evento `model.call` com request e response em blobs.
6. O harness transmite os tokens ao shell com `ui.emit` e grava `assistant.message` quando a resposta termina.
7. Para cada tool pedida pelo modelo, o harness invoca o hook `tool.before` e depois chama `tools.call`.
8. O core classifica a chamada e decide: permite, pede aprovação no shell ou nega. Se permitido, sobe a extensão se necessário, chama `tools/call` via MCP, grava `tool.call` e `tool.result` com proveniência e atualiza as flags U/P da sessão.
9. O harness invoca `tool.after`, devolve o resultado ao modelo e repete do passo 4 até não haver mais tools.
10. O harness invoca `turn.end`.

## Layout do repositório

```text
fictor/
├── AGENTS.md                 instruções para a IA que implementa
├── spec/                     esta especificação
├── core/                     Rust, crate único, binário `fictor`
│   ├── Cargo.toml
│   ├── migrations/           SQL numerado (0001_init.sql = spec/schemas/0001_init.sql)
│   └── src/
│       ├── main.rs           CLI (clap)
│       ├── config.rs
│       ├── store/            events, sessions, blobs, kv, approvals, proposals, timers
│       ├── supervisor.rs     ciclo de vida dos processos de extensão
│       ├── sandbox/          linux.rs (bubblewrap), init.rs (__sandbox-init)
│       ├── proxy/            egress.rs, models.rs
│       ├── gateway/          cliente MCP, registro de tools, fan-out de hooks
│       ├── kernel/           servidor do Kernel Protocol
│       ├── policy/           classificação, flags, decisão, aprovações, grants
│       ├── installer/        pipeline, lock, store, hash de bundle
│       ├── admin.rs          socket administrativo
│       └── web/              axum: auth, WebSocket, assets embutidos, host de surfaces
├── package.json              workspace npm do código TypeScript; Vite+ como dependência de desenvolvimento
├── dev/Containerfile         ambiente de desenvolvimento (toolbx)
├── shell/                    TypeScript + Lit; build com `vp build`, embutido no core
│   └── ds/                   design system `fx-*` e CATALOG.md
├── sdk/                      @fictor/sdk (TypeScript/Node)
├── harness/                  extensão role=harness; `vp pack` gera dist/main.mjs
├── extensions/               extensões padrão (fs-tools, shell-net, ...); `vp pack` gera dist/server.mjs
└── tests/acceptance/         testes de ponta a ponta (Vitest) + provider falso
```

Um crate único com módulos. Dividir em crates só quando houver motivo concreto (tempo de compilação, reuso).

## Diretório de dados

`FICTOR_HOME`, com default `$XDG_DATA_HOME/fictor` ou `~/.local/share/fictor` (no Fedora Atomic, `/var/home/<usuário>/.local/share/fictor`).

```text
$FICTOR_HOME/
├── config.toml
├── AGENTS.md                 instruções globais do usuário (opcional)
├── fictor.db                 SQLite (WAL)
├── secrets.toml              só com [secrets] backend = "file" (0600)
├── blobs/<2 hex>/<62 hex>    conteúdo endereçado por sha256
├── evals/<case_id>/          casos criados pelo usuário (Fase 2)
├── runtime/                  runtimes gerenciados pelo core: node-<versão>/, uv-<versão>/, python/ (somente leitura)
├── extensions/
│   ├── lock.json
│   ├── store/<id>/<version>-<hash12>/    somente leitura após promoção
│   ├── quarantine/<proposal_id>/
│   └── data/<id>/                         ${ext_data} de extensões globais
│       └── sessions/<session_id>/         ${ext_data} de instâncias de sessão
├── run/                      sockets e registros de instância (diretório 0700)
│   ├── admin.sock
│   ├── proxy.sock            (Linux)
│   ├── k/<instance_id>.sock  Kernel Protocol por instância
│   └── instances/<instance_id>/
│       ├── state.json        posse e identidades de processos; schema 1, 0600
│       └── tmp/              árvore auxiliar descartável; não é o /tmp do sandbox
└── logs/
```

Nenhum caminho de `FICTOR_HOME` é montado em sandbox, exceto: o bundle da própria extensão (`store/...`, leitura), o `${ext_data}` da instância (escrita) e os sockets da própria instância. O harness também lê `store/` inteiro. Registros de instância e a árvore auxiliar de preparação não são montados; o `/tmp` do sandbox continua privado. Recuperação e descarte seguem [02-core.md](02-core.md#confirmação-e-recuperação-no-boot).

## Stack

| Parte | Escolha | Observação |
|---|---|---|
| Core | Rust stable, tokio, axum, rusqlite (`bundled`), rmcp, hyper + rustls, keyring, directories, serde, tracing, ulid, sha2, rust-embed, clap | sem C++ nem runtime JS embutido |
| Runtime das extensões JavaScript | Node LTS, baixado pelo gerenciador de runtimes ([02-core.md](02-core.md#runtimes)) | permissões do Node derivadas do manifest; mesmo runtime para extensões padrão e MCP de terceiros |
| Harness e extensões padrão | TypeScript, empacotado com `vp pack` num único `.mjs` | embutidas no binário como origem `builtin` |
| Extensões Python | Python instalado pelo uv do gerenciador de runtimes | dependências instaladas na quarentena |
| Shell | TypeScript, Lit, markdown-it, DOMPurify; build com `vp build` (Vite) | assets embutidos no binário |
| Ferramentas de desenvolvimento | Vite+ (`vp check`, `vp test`, `vp build`, `vp pack`, `vp run`) como dependência npm; Rust e demais ferramentas no container toolbx | só no desenvolvimento, nunca no app em execução ([ADR-034](11-decisions.md#adr-034--desenvolvimento-em-toolbx-vite-como-ferramenta-de-desenvolvimento)) |
| Banco | SQLite com FTS5 | um arquivo; extensões usam o próprio diretório de dados |

## Plataformas

Só Linux x86-64 ([ADR-030](11-decisions.md#adr-030--só-linux-x86-64-alvo-atual-fedora-cosmic-atomic)). O core não compila em outro SO ou arquitetura.

| Ambiente | Papel |
|---|---|
| Fedora COSMIC Atomic, versão estável corrente, x86-64 (máquina do usuário) | Alvo único validado e gate de toda release. |
| Ubuntu 22.04 x86-64 (CI) | Roda todos os testes, inclusive de sandbox real. Necessário, mas não substitui o Fedora. |
| Container Fedora da versão alvo (CI) | Build e testes que não criam sandbox. |
| Outras distros Linux x86-64 | Podem funcionar; não são testadas. |

Sandbox: bubblewrap + namespaces; Landlock e seccomp na Fase 3. `fictor doctor` DEVE detectar e explicar user namespaces bloqueados (por exemplo, AppArmor no Ubuntu 24.04+).

### Fedora COSMIC Atomic

- `/usr` é imutável, e nada é sobreposto nela (R8). Da imagem base, o Fictor usa só o bubblewrap, que vem como dependência do flatpak, e o navegador. Runtimes de extensões ficam em `$FICTOR_HOME/runtime/`.
- Desenvolvimento do Fictor: dentro de um container toolbx ([10-roadmap.md](10-roadmap.md#instância-de-desenvolvimento-no-toolbx)). O host continua limpo.
- `/home`, `/opt`, `/srv`, `/mnt`, `/root` e `/usr/local` são symlinks para `/var/...`. O core trabalha com caminhos canônicos e recria esses symlinks dentro do sandbox ([05-security.md](05-security.md#linux-bubblewrap)).
- SELinux fica em modo enforcing. O core não exige mudanças de política; `fictor doctor` reporta negações (AVC) que afetem o sandbox.
- A instalação de uso não usa toolbox nem distrobox. Só o desenvolvimento usa toolbx.
- Navegador alvo do shell: Firefox, o padrão do Fedora.
