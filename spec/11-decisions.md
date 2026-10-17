# 11 — Decisões (ADRs)

Formato: contexto, decisão, consequências. Para mudar uma decisão, adicionar um ADR novo que substitui o anterior; não editar o antigo.

## ADR-001 — Core em Rust, crate único, base de confiança mínima

- **Contexto.** O core concentra sandbox, segredos, política e registro. O gargalo de desempenho do sistema é a latência do modelo, não o core.
- **Decisão.** Rust, um crate, binário único. Meta de 5–8 mil linhas.
- **Consequências.** Syscalls de sandbox e binário estático por plataforma ficam simples. O core muda pouco e não é editado pela IA.

## ADR-002 — Extensões fora do processo; sem JS ou WASM embutido

- **Contexto.** Um interpretador embutido (QuickJS) obriga o core a expor cada capacidade que as extensões precisam (fetch, sqlite, websockets, SDKs). O core cresceria a cada funcionalidade. Gerar WASM exige toolchains pesadas e os modelos escrevem WIT mal.
- **Decisão.** Cada extensão é um processo separado, em qualquer linguagem, falando protocolos. TypeScript em Deno é o default para extensões first-party e geradas pela IA.
- **Consequências.** Extensões usam npm, JSR e PyPI livremente. Crash isolado por processo. Custo de IPC na ordem de 1 ms por chamada, irrelevante perto do modelo. Depende de Deno instalado (~100 MB).

## ADR-003 — MCP para extensões; Kernel Protocol para serviços do kernel

- **Contexto.** MCP já cobre tools, resources e UI (MCP Apps) e tem ecossistema. Serviços do kernel (eventos, kv, hooks, sessões) não têm padrão.
- **Decisão.** Toda extensão com tools é um servidor MCP. Hooks são tools com prefixo reservado. Serviços do kernel usam um JSON-RPC próprio e pequeno sobre Unix socket.
- **Consequências.** Servidores MCP de terceiros funcionam sem adaptação. O protocolo próprio fica restrito ao que não tem padrão.

## ADR-004 — O harness é uma extensão; um processo por sessão; sem estado próprio

- **Contexto.** Loops de agente mudam o tempo todo e cada concorrente tem o seu.
- **Decisão.** O loop do agente vive numa extensão `role: harness`. Um processo por sessão ativa. Todo estado é reconstruível do event log.
- **Consequências.** Trocar ou evoluir o loop não toca o core. A contaminação por sessão é aplicável pelo core no limite do processo.

## ADR-005 — Event log append-only em SQLite; sessões lineares; DAG por forks

- **Contexto.** Fork, rewind, comparação de modelos, auditoria e evals dependem de histórico imutável.
- **Decisão.** Tabela `events` append-only com proveniência e flags cumulativas. Cada sessão é uma cadeia linear; ramificar cria uma sessão nova.
- **Consequências.** Fork é O(1). O histórico vira benchmark. Expurgo de dados fica fora da v1.

## ADR-006 — Chaves de provider só no model proxy

- **Contexto.** Extensões e o próprio harness podem ser influenciados por injection.
- **Decisão.** O harness fala com `models.fictor.internal` em HTTP via proxy; o core injeta a chave e faz o TLS. Segredos de terceiros via env são exceção documentada até a injeção no proxy (Fase 3).
- **Consequências.** Provider novo é só configuração. Nenhum processo de extensão vê chave de modelo.

## ADR-007 — Política no core: classificação, flags U/P, Rule of Two, modos

- **Contexto.** Filtros de prompt injection são contornáveis. O harness não é confiável para segurança.
- **Decisão.** O core decide toda chamada de tool com a função normativa de [05-security.md](05-security.md#decisão). Hooks não substituem a política. Escrita local não conta como efeito externo.
- **Consequências.** Defesa estrutural e auditável. Algumas ações legítimas pedem aprovação em sessões contaminadas.

## ADR-008 — Um pipeline para todo código; runtime nunca baixa código

- **Contexto.** Código da IA, local e da internet têm riscos parecidos. Downloads em runtime quebram a fixação por hash.
- **Decisão.** Toda entrada no store passa pelo mesmo pipeline. Dependências são resolvidas e vendorizadas na quarentena. Promoção automática só no perfil dev.
- **Consequências.** Velocidade para extensões simples da IA; revisão humana para tudo que tem rede, segredos, hooks ou origem externa.

## ADR-009 — UI web em localhost; surfaces via MCP Apps em host separado

- **Contexto.** Sem Tauri. UI em localhost é alvo de sites no navegador. Scripts gerados pela IA no DOM principal poderiam forjar aprovações.
- **Decisão.** Shell em `127.0.0.1` com cookie, Origin, CSRF e checagem de Host. Surfaces em `localhost` (host diferente), iframe sandboxed sem `allow-same-origin`, CSP sem rede.
- **Consequências.** Extensões não tocam o DOM confiável nem a rede pelo navegador. Dados chegam às surfaces só por postMessage.

## ADR-010 — Linux e macOS de primeira classe; Windows via WSL2

- **Contexto.** O usuário alterna entre Fedora Atomic e macOS. Sandboxes nativas diferem por SO.
- **Decisão.** Backends bubblewrap (Linux) e Seatbelt (macOS). Windows só via WSL2 na v1.
- **Consequências.** Dois backends para manter e testar. Landlock e seccomp chegam na Fase 3.

## ADR-011 — Sem bancos especializados no core

- **Contexto.** Vetores, grafos e séries temporais servem a funcionalidades específicas.
- **Decisão.** O core usa SQLite com FTS5. Extensões que precisam de outra coisa trazem o próprio banco no `${ext_data}`.
- **Consequências.** Core simples. Grafo de código, por exemplo, vive no SQLite da extensão com CTEs recursivas.

## ADR-012 — Lock em arquivo JSON

- **Contexto.** O usuário pode querer versionar o conjunto de extensões.
- **Decisão.** `extensions/lock.json`, escrito só pelo instalador com escrita atômica. Propostas e histórico ficam no banco.
- **Consequências.** Legível e versionável. O core mantém o lock em memória e o recarrega só após escrever.
