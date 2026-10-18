# Fictor — Especificação v0.1

Status: rascunho para implementação · Data: 2026-10-17 · Dono: wkoch

## O que é

Fictor é um runtime pessoal de agentes de IA. O core é um kernel de confiança pequeno, escrito em Rust, que isola, registra e autoriza. Toda funcionalidade é extensão rodando em processo separado e dentro de sandbox, falando MCP. Isso inclui o loop do agente, as ferramentas de arquivo e terminal e os painéis de UI. A própria IA escreve extensões novas, que passam por um pipeline de verificação antes de ficarem ativas. A interface é web, servida em localhost.

## Requisitos fundadores

| ID | Requisito |
|---|---|
| R1 | Core minimalista para Linux x86-64. Alvo atual e único validado: Fedora COSMIC Atomic ([ADR-030](11-decisions.md#adr-030--só-linux-x86-64-alvo-atual-fedora-cosmic-atomic)). |
| R2 | A IA cria funcionalidades novas e o app passa a usá-las sem reiniciar. |
| R3 | Qualquer funcionalidade de concorrentes (Claude Code, Codex, Cowork, Pi, Kimi, DeepSeek etc.) é implementável sem alterar o core. |
| R4 | Compatibilidade com padrões: MCP, MCP Apps, Agent Skills, AGENTS.md. Inventar só onde não há padrão. |
| R5 | Nada de terceiros (MCP, skills, plugins) roda sem passar pelo pipeline de verificação e sem versão fixada por hash. |
| R6 | Defesa estrutural contra prompt injection, sem depender de filtros. |
| R7 | Uso pessoal: um usuário, uma máquina, UI em localhost. |

## Invariantes

Estas regras não podem ser relaxadas para fazer um teste passar ou para simplificar uma implementação. Qualquer mudança exige um ADR novo em [11-decisions.md](11-decisions.md).

| ID | Invariante |
|---|---|
| I1 | Extensões nunca rodam dentro do processo do core. |
| I2 | Todo processo de extensão roda em sandbox, com permissões declaradas no manifest. O default é negar. |
| I3 | Toda chamada de ferramenta feita pelo modelo ou por UI de extensão passa por `tools.call` do core, que aplica política e registra no event log. |
| I4 | Chaves de API de provider de modelo nunca entram em processos de extensão. A exceção documentada está em [05-security.md](05-security.md#segredos). |
| I5 | O event log é append-only. Nenhum UPDATE ou DELETE em `events`. |
| I6 | O estado do harness é reconstruível a partir do event log e do kv. Matar o processo do harness não perde nada. |
| I7 | Nenhum código entra no store sem passar pelo pipeline ([06-lifecycle.md](06-lifecycle.md)). Em runtime, nenhuma extensão baixa código. |
| I8 | Aprovações são exibidas e decididas só pela UI confiável do core ou pela CLI. Extensões e modelo não conseguem forjar nem responder uma aprovação. |
| I9 | O core não conhece formatos de API de modelo nem conceitos como "chat", "agente" ou "canvas". Hook points são strings opacas para o core. |
| I10 | O core só muda por: novo backend de sandbox ou isolamento, nova primitiva de segurança, bug ou performance. |
| I11 | Todo dado que entra em processo vinculado a uma sessão chega por um canal mediado pelo core que propaga as flags U/P. Nenhuma garantia de contaminação depende de declaração voluntária de uma extensão ([05-security.md](05-security.md#fluxo-entre-sessões)). |

## Mapa do spec

| Arquivo | Conteúdo |
|---|---|
| [01-architecture.md](01-architecture.md) | Camadas, processos, canais, fluxo de um turno, layout do repositório e do diretório de dados, stack. |
| [02-core.md](02-core.md) | Componentes do core: supervisor, store, gateway MCP, proxies, segredos, configuração, CLI. |
| [03-kernel-protocol.md](03-kernel-protocol.md) | Protocolo entre core e extensões: métodos, notificações, escopos, erros, tipos de evento. |
| [04-extensions.md](04-extensions.md) | Manifest, runtimes, classificação de tools, hooks, surfaces, skills, comandos, SDK, importação de formatos externos. |
| [05-security.md](05-security.md) | Modelo de ameaças, sandbox, política (Rule of Two), aprovações, segredos, endurecimento web. |
| [06-lifecycle.md](06-lifecycle.md) | Pipeline de extensões: proposta, quarentena, checagens, auditoria, promoção, atualização, rollback. |
| [07-harness.md](07-harness.md) | Harness padrão (loop do agente) e extensões first-party. |
| [08-shell.md](08-shell.md) | UI web: autenticação, protocolo WebSocket, layout, renderização, host de MCP Apps, design system. |
| [09-evals.md](09-evals.md) | Evals, gates de promoção, replay do histórico. |
| [10-roadmap.md](10-roadmap.md) | Fases, marcos e critérios de aceitação. |
| [11-decisions.md](11-decisions.md) | Registro de decisões (ADRs). |
| [schemas/extension.schema.json](schemas/extension.schema.json) | JSON Schema do manifest `fictor.yaml`. |
| [schemas/0001_init.sql](schemas/0001_init.sql) | Migração inicial do SQLite. |
| [schemas/0002_flow_budget.sql](schemas/0002_flow_budget.sql) | Migração 0002: orçamento do model proxy e flags de workspace e de extensão. |

Ordem de leitura para implementar: README → 01 → 10 → o arquivo da fase/componente em andamento.

## Convenções

- **DEVE / NÃO DEVE / DEVERIA / PODE** têm o sentido da RFC 2119.
- Identificadores, nomes de métodos, campos e código ficam em inglês. A prosa fica em português.
- "(Fase N)" marca itens que só entram na fase N do [roadmap](10-roadmap.md). Itens sem marca são da Fase 0.
- Exemplos de código são ilustrativos. Assinaturas, schemas e tabelas de regras são normativos.

## Glossário

| Termo | Definição |
|---|---|
| Core | Binário Rust `fictor`. Base de confiança (TCB). Camada L0. |
| Extensão | Processo separado, descrito por um manifest `fictor.yaml`, que fala MCP e/ou Kernel Protocol. |
| Harness | Extensão com `role: harness`. Implementa o loop do agente. Um processo por sessão ativa. Camada L1. |
| Bundle | Diretório de uma extensão: manifest, código, dependências vendorizadas, skills, UI, evals. |
| Store | Diretório somente leitura com bundles promovidos, endereçados por versão e hash. |
| Lock | `extensions/lock.json`: quais versões estão ativas, com hash, permissões e tools fixadas. |
| Quarentena | Área onde propostas ficam enquanto passam pelas checagens. Nada roda dali com rede ou segredos. |
| Proposta | Pedido de instalação ou atualização de um bundle, vindo da IA, de um caminho local ou da internet. |
| Promoção | Mover uma proposta aprovada para o store e ativá-la no lock. |
| Sessão | Cadeia linear de eventos com um `head`. Forks criam sessões novas; o conjunto forma um DAG. |
| Evento | Registro imutável no event log, com proveniência (`trust`, `sensitivity`, `source`). |
| Flag U | A sessão já recebeu conteúdo não confiável. |
| Flag P | A sessão já recebeu dados privados. |
| Efeito externo | Tool com `effect: external`: pode comunicar para fora ou mudar estado fora da máquina. |
| Rule of Two | Sem aprovação humana, uma sessão nunca combina U, P e efeito externo. |
| Surface | UI de extensão renderizada num iframe isolado, conforme MCP Apps. |
| Kernel Protocol | JSON-RPC entre core e extensões para serviços do kernel (eventos, kv, tools, hooks, UI). |
| Perfil dev | Conjunto restrito de permissões que permite promoção automática de extensões criadas pela IA. |
| UI confiável | Partes do shell servidas e controladas pelo core: aprovações, permissões, gerenciador de extensões. |

## Não-objetivos da v1

- Múltiplos usuários, contas ou sincronização em nuvem.
- App nativo mobile ou desktop (Tauri, Electron). A UI é só web.
- macOS, Windows (inclusive WSL2) e Linux ARM64. Outras distros Linux x86-64 não são testadas.
- Acesso remoto à UI (fora de localhost).
- Distribuição de extensões via OCI e protocolo A2A.
- Bancos especializados no core (vetorial, grafo, séries temporais). Extensões podem trazer os seus.
- Fine-tuning, voz.
- Expurgo de eventos do log.

## Padrões e referências externas

Verificar a versão vigente de cada padrão no início da implementação e registrá-la no código.

| Item | Referência |
|---|---|
| MCP | https://modelcontextprotocol.io/specification |
| MCP Apps (UI) | https://github.com/modelcontextprotocol/ext-apps |
| SDK MCP Rust (`rmcp`) | https://github.com/modelcontextprotocol/rust-sdk |
| SDK MCP TypeScript | https://github.com/modelcontextprotocol/typescript-sdk |
| MCP Registry | https://registry.modelcontextprotocol.io |
| Agent Skills | https://agentskills.io |
| AGENTS.md | https://agents.md |
| ACP (Fase 4) | https://agentclientprotocol.com |
| Permissões do Deno | https://docs.deno.com/runtime/fundamentals/security/ |
| uv | https://docs.astral.sh/uv/ |
| Referência de sandbox | https://github.com/anthropic-experimental/sandbox-runtime (bubblewrap + proxy) |
| Referência de sandbox | https://github.com/openai/codex (`codex-rs`: Landlock/seccomp) |
| Agents Rule of Two | Meta AI, "Agents Rule of Two: A Practical Approach to AI Agent Security" (2025) |
| CaMeL | Google DeepMind, "Defeating Prompt Injections by Design" (2025) |
| OSV | https://osv.dev |
