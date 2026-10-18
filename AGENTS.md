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

## Comandos

| Parte | Formatar | Lint | Testes |
|---|---|---|---|
| `core/` | `cargo fmt` | `cargo clippy --all-targets -- -D warnings` | `cargo test` |
| `sdk/`, `harness/`, `extensions/*` | `deno fmt` | `deno lint` | `deno test` |
| `shell/` | `deno fmt` | `deno lint` | `deno task test` |

Build do shell: `deno task build` em `shell/` (Vite via `npm:vite`). Desenvolvimento: `deno task dev` (build em watch) + `fictor serve --shell-dir shell/dist`.

## Testes

- Unitários junto ao código. Integração do core em `core/tests/`. Aceitação de ponta a ponta em `tests/acceptance/` (Deno), dirigindo o core pelo WebSocket e pelo socket admin.
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

### Commits

- Um marco (ou parte coesa dele) por commit/PR.
- Mensagens em inglês, no imperativo.
