# AGENTS.md — Fictor

Instruções para agentes de IA que implementam este repositório.

## O projeto

Fictor é um runtime pessoal de agentes de IA. O core (Rust) é um kernel de confiança pequeno: isola, registra e autoriza. Toda funcionalidade é extensão em processo separado e em sandbox, falando MCP. A especificação completa está em [spec/](spec/README.md).

## Leitura obrigatória antes de qualquer tarefa

1. [spec/README.md](spec/README.md): requisitos, **invariantes I1–I11**, glossário.
2. [spec/01-architecture.md](spec/01-architecture.md): camadas, processos, layout.
3. [spec/10-roadmap.md](spec/10-roadmap.md): fase atual, marcos e critérios de aceitação.
4. O arquivo do spec do componente em que você vai mexer.

## Regras

1. **Uma fase por vez.** Implemente os marcos na ordem do roadmap. Não implemente itens marcados com fase posterior.
2. **Invariantes não se negociam.** Se uma tarefa parecer exigir quebrar uma invariante, pare e pergunte ao usuário.
3. **Nunca afrouxe segurança para fazer algo funcionar.** Isso inclui: desligar o sandbox, ampliar montagens, liberar rede direta, relaxar CSP, pular checagem de `Host`/`Origin`/CSRF, passar segredos para extensões, permitir UPDATE/DELETE em `events`. Um teste que falha por causa de uma dessas proteções indica bug na implementação ou no teste.
4. **O spec é do arquiteto.** Não edite `spec/` nem `AGENTS.md`. Divergência, lacuna ou ambiguidade em segurança, formato de dados persistidos ou protocolo vira uma pendência `ARQ-NNN` em `docs/architect-pending.md` (referência, dúvida, o que é necessário, impacto). Não implemente a parte afetada até o arquiteto responder com um ADR em [spec/11-decisions.md](spec/11-decisions.md); depois, marque a pendência como resolvida citando o ADR.
5. **Detalhe interno.** Decida pela opção mais simples, siga e registre a decisão em `docs/implementation.md` ou num comentário curto.
6. **Critérios de aceitação viram testes automatizados** sempre que possível.
7. **Dependências.** Prefira as listadas em [spec/01-architecture.md](spec/01-architecture.md#stack). Dependência nova precisa de motivo claro.
8. **Fora do escopo, sempre:** Tauri/Electron, JS ou WASM embutido no core, Docker como requisito, bancos especializados no core.

## Ambiente de desenvolvimento

Tudo roda dentro do container toolbx definido em `dev/Containerfile` ([ADR-034](spec/11-decisions.md#adr-034--desenvolvimento-em-toolbx-vite-como-ferramenta-de-desenvolvimento)). Nada é instalado no host: nada de `rpm-ostree`, e nenhuma ferramenta global no `$HOME`. O Vite+ é dependência npm de desenvolvimento do repositório; o Node vem do container, e `vp env` não é usado.

## Comandos

| Parte | Formatar e lint | Testes | Build |
|---|---|---|---|
| `core/` | `cargo fmt`, `cargo clippy --all-targets -- -D warnings` | `cargo test` | `cargo build --release` |
| `sdk/`, `harness/`, `extensions/*`, `shell/`, `tests/acceptance/` | `vp check` | `vp test` | `vp pack` (extensões) e `vp build` (shell) |

Ordem da build completa: `vp run build` gera o shell e as extensões empacotadas, que o core embute; depois `cargo build`. Desenvolvimento do shell: build em modo watch + `fictor serve --shell-dir shell/dist`.

Instância de desenvolvimento: dentro do toolbx, com `FICTOR_HOME=~/.local/share/fictor-dev` e portas 7360/7361, para não colidir com a instância de uso do host ([spec/10-roadmap.md](spec/10-roadmap.md#instância-de-desenvolvimento-no-toolbx)).

## Testes

- Unitários junto ao código. Integração do core em `core/tests/`. Aceitação de ponta a ponta em `tests/acceptance/` (Vitest), dirigindo o core pelo WebSocket e pelo socket admin.
- **Sem chaves reais nem rede externa nos testes.** Use um provider falso: servidor HTTP local que imita o streaming das APIs Anthropic e OpenAI com respostas roteirizadas. Configure-o como provider com `base_url = "http://127.0.0.1:<porta>"`.
- **Plataforma única: Linux x86-64; alvo validado: Fedora COSMIC Atomic** ([ADR-030](spec/11-decisions.md#adr-030--só-linux-x86-64-alvo-atual-fedora-cosmic-atomic)). Não escreva nem mantenha código, testes ou CI para outros sistemas operacionais ou arquiteturas.
- **Onde os testes contam.** Build e testes só valem como evidência quando rodam na máquina Fedora COSMIC Atomic do usuário ou na CI (Ubuntu 22.04 x86-64 e container Fedora). Ao reportar, diga onde cada suíte rodou.
- **Gate de release:** os critérios de aceitação passando na máquina Fedora COSMIC Atomic do usuário ([spec/10-roadmap.md](spec/10-roadmap.md#gate-de-cada-release)).
- **Prioridade atual:** chegar à v0.1 autossuficiente ([spec/10-roadmap.md](spec/10-roadmap.md#marco-de-autossuficiência-v01)). Depois dela, o desenvolvimento continua de dentro do próprio Fictor.

## Convenções

### Rust

- Erros com `thiserror` nos módulos; `anyhow` só na CLI e no `main`.
- Sem `unwrap`/`expect` fora de testes, exceto para invariantes documentadas no próprio ponto.
- Logs com `tracing`. Nunca registrar valores de segredos, cabeçalhos de autenticação nem o ambiente de processos filhos.
- Escritas no SQLite passam pela task única de escrita.

### TypeScript

- `strict`. Sem `any`, exceto em fronteiras de protocolo validadas com zod.
- Extensões usam `@fictor/sdk`; não reimplemente MCP ou Kernel Protocol em cada extensão.
- Só APIs web padrão e módulos `node:`; nada exclusivo de um runtime.
- Código executado pelo Node em `.ts` usa só sintaxe que pode ser apagada (sem `enum`, `namespace` ou parameter properties).

### Commits

- Um marco (ou parte coesa dele) por commit/PR.
- Mensagens em inglês, no imperativo.

<!-- trail:start -->
## Trail — repo context graph

This repo is indexed in `.trail/cache/`: small linked markdown nodes that explain each
system and carry exact file:line spans, kept in sync with the code through git.

For ANY task here — understanding how something works, finding where code lives,
or scoping a change — get context from the graph before grepping or opening
source files. Re-ask freely (it's cheap) and reuse literal identifiers you
already have (symbol, error string, file name) as the query. New to this repo?
Run `trail map` first — a token-budgeted orientation (dir clusters, hubs,
hotspots), no LLM, no key.

- Run `trail ask "<your question>" --source` → ranked nodes with the relevant
  code spans inlined (each hit's ≤8-line crux by default; `--full` for whole
  definitions when the crux isn't enough). Match the tool to the task shape:
  for understanding or editing, the top node IS the answer — cite its
  `covers:` file:line spans and edit straight from `--source`. For
  exhaustive tasks ("every occurrence / every caller of this pattern"), ranked
  results are top-N, not complete — run `trail grep "<literal>"` instead
  (exhaustive over indexed files, grouped by enclosing symbol), falling back
  to raw `grep -rn` only for unindexed files.
- `trail skeleton <file>` → every definition's signature + span, ~10× cheaper
  than reading the file; use it to skim an API surface.
- `trail callers <symbol>` gives precomputed, exact edges — who calls this.
  Add `--direction out` for what it calls, or `--depth N` to walk
  transitively for the full blast radius. For structural questions, skip
  ranking and use this directly.
- Or browse: `.trail/cache/INDEX.md` lists every node; follow the links.
- Monorepos and folders of multiple repos rank fairly across sub-projects —
  hits carry `[scope/]` labels naming which one they're from. Narrow with
  `trail ask "<task>" --in <scope>/` once you know where you're working.

If a returned span is truncated ("+N more lines"), open the file at that exact
range before finalizing. Only open source files when a node genuinely lacks a
needed detail, and then at the exact file:line the node points to — never
re-read whole files.

After big code changes, refresh the graph with `trail build` (deterministic,
no API key, $0).
<!-- trail:end -->
