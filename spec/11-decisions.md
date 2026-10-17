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

## ADR-013 — Corte da v1.0 (resolve ARQ-001)

- **Contexto.** O roadmap tinha gates por fase, mas nenhuma release associada. Os requisitos R4 e R5 (padrões da internet só com auditoria) dependem da Fase 3.
- **Decisão.** v0.1, v0.2 e v0.3 fecham as Fases 0, 1 e 2. A v1.0 exige as Fases 0–2 mais o núcleo da Fase 3 (importação de terceiros, auditoria, atualizações, Landlock e seccomp). Os demais itens da Fase 3 e a Fase 4 ficam para v1.x. Cada release exige os critérios nas duas máquinas reais (Fedora Atomic e macOS), CI verde e um teste por invariante. Detalhes em [10-roadmap.md](10-roadmap.md#releases).
- **Consequências.** "v1.0" significa uso diário com extensões de terceiros auditadas. Ubuntu na CI não substitui o Fedora.

## ADR-014 — Mediação de dados e fluxo entre sessões (resolve ARQ-002)

- **Contexto.** O harness lia o workspace direto (`AGENTS.md`), fora de `tool.result`, então a flag P não acendia, e a garantia dependia do harness se declarar. Revisando os outros canais, `kv` e `${ext_data}` de instâncias de sessão, o próprio workspace e extensões globais com estado também deixavam dados passarem de uma sessão a outra sem flags.
- **Decisão.** Nova invariante I11, aplicada por regras de capacidade e de propagação ([05-security.md](05-security.md#fluxo-entre-sessões)):
  1. o harness e extensões com escopo `tools` não leem o workspace, não têm rede nem segredos; `AGENTS.md` é lido via `fs-tools__read_file`;
  2. `kv` e `${ext_data}` são por sessão em instâncias de sessão;
  3. escrever no workspace a partir de sessão com U acende U no workspace, até o usuário limpar;
  4. (Fase 1) extensões globais têm marca d'água persistente de flags, e respostas de hooks acendem flags.
- **Consequências.** A contaminação passa a ser aplicada pelo core em todos os canais conhecidos. A flag de workspace e a marca d'água superestimam a contaminação, e o usuário as limpa explicitamente. Migração 0002.

## ADR-015 — Configuração inicial de modelos (resolve ARQ-003)

- **Contexto.** O exemplo do core usava `default_model = "anthropic/claude-sonnet"` sem tabela `models`, em conflito com o harness. Nomes de modelo mudam com o tempo e o core não pode interpretá-los.
- **Decisão.** `fictor init` grava `default_model = "main"` e a tabela `[ext.harness.models.main]` comentada. O usuário a preenche. Sem modelo válido, o harness registra `harness.error` com instrução e não chama o provider. O harness relê `[ext.harness]` a cada turno; o core relê seções `[ext.*]` a cada `config.get`.
- **Consequências.** Primeira execução previsível e sem nomes de modelo envelhecendo no binário. O core continua opaco a modelos.

## ADR-016 — Blobs só com bytes; MIME na referência (resolve ARQ-004)

- **Contexto.** `blobs.put` aceitava MIME, mas o armazenamento é por conteúdo, e o mesmo conteúdo pode chegar com MIMEs diferentes.
- **Decisão.** O blob não tem MIME. Quem referencia o blob carrega o tipo (`Part.mime`). A entrega HTTP usa só a assinatura dos bytes: PNG, JPEG, GIF e WebP inline; o resto como `application/octet-stream` em anexo. `mime` sai de `blobs.put`/`blobs.get`.
- **Consequências.** Sem conflitos nem metadados novos. O tipo declarado pelo cliente nunca decide como o navegador renderiza.

## ADR-017 — Captura e orçamento do model proxy (resolve ARQ-006 e ARQ-007)

- **Contexto.** Faltava o contrato para stream parcial, cancelamento, falha de disco e limite, e a semântica do orçamento.
- **Decisão.**
  - A requisição é gravada antes de sair. Cada pedaço da resposta é gravado antes de chegar ao cliente. Falha de captura ou limite de 256 MiB encerra o stream.
  - Um evento `model.call` por requisição, ao final, com `outcome` e `resp_complete`.
  - O orçamento conta requisições admitidas (inclusive falhas e retries) por dia civil local e por sessão. A reserva é transacional na tabela `budget_usage`. Detalhes em [02-core.md](02-core.md#model-proxy).
- **Consequências.** Todo conteúdo de modelo usado por uma extensão fica registrado. Retries consomem cota, e isso é intencional. Migração 0002.

## ADR-018 — Backend de segredos explícito (resolve ARQ-005)

- **Contexto.** O fallback automático para arquivo podia gravar em disco, sem aviso, segredos que o usuário esperava no keyring. Também não se distinguia keyring ausente de keyring bloqueado.
- **Decisão.** `[secrets] backend = "keyring" | "file"`, sem fallback. Keyring bloqueado ou com erro transitório faz a operação falhar (503 no model proxy). `secrets.toml` tem schema versionado, modo 0600 verificado e escrita atômica ([02-core.md](02-core.md#segredos)).
- **Consequências.** Nenhum segredo vai para disco sem decisão do usuário. No COSMIC sem Secret Service, o usuário escolhe `file` conscientemente.

## ADR-019 — Variáveis de ambiente reservadas (resolve ARQ-008)

- **Contexto.** O manifest podia declarar `PATH`, `HTTP_PROXY`, `NODE_OPTIONS` e outras variáveis definidas pelo supervisor ou que mudam o carregamento de código.
- **Decisão.** Lista de nomes e prefixos reservados no spec e no schema ([04-extensions.md](04-extensions.md#variáveis-de-ambiente-reservadas)). Colisão é erro bloqueante na validação, e o supervisor confere de novo no spawn. Não existe sobrescrita silenciosa.
- **Consequências.** O ambiente de rede, de certificados e de carregamento é sempre o do core.

## ADR-020 — Caminhos sensíveis e canal do kernel via TCP no Linux (resolve ARQ-009)

- **Contexto.** Não há como listar todos os sockets de agentes. No Linux, montar um diretório somente leitura não impede `connect()` em sockets dentro dele. No macOS o Seatbelt já bloqueia sockets Unix não listados.
- **Decisão.**
  - Lista de caminhos sensíveis, mais descoberta (`SSH_AUTH_SOCK`, `gpgconf --list-dirs` sem iniciar agente, Docker, Podman, D-Bus). Montagem que é, contém ou está contida num caminho sensível é recusada. Sem `gpgconf`, usar os defaults e avisar.
  - No Linux, o Kernel Protocol passa a usar TCP em `127.0.0.1:3129` dentro do namespace da instância, com `__sandbox-init` fazendo a ponte para o Unix socket (como já faz para o proxy). `FICTOR_KERNEL_SOCKET` vira `FICTOR_KERNEL_URL`.
  - Na Fase 3, o seccomp nega `socket(AF_UNIX)` à carga de trabalho.
- **Consequências.** Sockets fora da lista ficam inalcançáveis por estrutura no macOS agora, e no Linux a partir da Fase 3. Até lá é risco residual documentado. O sandbox Linux já implementado precisa trocar o bind de `/fx/kernel.sock` pela ponte TCP.

## ADR-021 — IPv6 na allowlist de rede (resolve ARQ-010)

- **Contexto.** A allowlist não representava IPv6 literal, e não havia regra para zonas e endereços mapeados.
- **Decisão.** IPv6 só como `[endereço]:porta`, normalizado pela RFC 5952. Zonas e IPv4 mapeado são recusados no manifest. No destino, IPv4 mapeado e NAT64 são avaliados como o IPv4 embutido, e destino com zona é negado. `*:porta`, CIDR e curingas no meio do nome continuam fora ([04-extensions.md](04-extensions.md#sintaxe-de-netallow)).
- **Consequências.** Uma única forma canônica por endereço. Faixas privadas IPv6 entram na mesma regra de destino não público.

## ADR-022 — HTTP para providers só em loopback literal (resolve ARQ-011)

- **Contexto.** Providers locais (Ollama, provider falso dos testes) usam HTTP. Liberar HTTP para outros hosts exporia chave e conteúdo em texto claro.
- **Decisão.** `base_url` com `http://` só para `127.0.0.1` ou `[::1]`. `localhost`, rede privada e outros hosts com HTTP são erro de configuração, e o core não sobe. Sem downgrade de HTTPS e sem opção de ignorar certificado.
- **Consequências.** Provider na rede local exige HTTPS ou túnel. O teste com provider falso continua possível.

## ADR-023 — Prefixos NAT64 (resolve ARQ-012; complementa o ADR-021)

- **Contexto.** O ADR-021 só tratava o prefixo bem conhecido `64:ff9b::/96`. Redes podem usar o prefixo de uso local `64:ff9b:1::/48` ou prefixos específicos com outros comprimentos. Nesses casos, o IPv4 embutido não pode ser identificado só pelo endereço.
- **Decisão.**
  - `64:ff9b::/96`: avaliar o IPv4 embutido (sem mudança).
  - `64:ff9b:1::/48`: tratado como destino não público inteiro.
  - Prefixos específicos: só por configuração explícita em `[egress] nat64_prefixes`, com extração conforme a RFC 6052. Nenhuma descoberta automática na aplicação da política; `fictor doctor` detecta via `ipv4only.arpa` e só sugere.
  - Detalhes em [02-core.md](02-core.md#nat64).
- **Consequências.** Cobertura determinística e testável. Numa rede com prefixo específico que o usuário não configurou, o IPv4 embutido não é avaliado; isso é risco residual documentado. Descoberta por DNS ou RA não decide política, porque esses dados podem ser forjados na rede local.

## ADR-024 — Limites de recebimento e de bundle (resolve ARQ-013)

- **Contexto.** Só a origem `ai` tinha teto de quantidade. Uma árvore local com muitos arquivos ou diretórios vazios podia esgotar memória ou tempo sem passar do teto em bytes.
- **Decisão.**
  - Limites constantes de entradas, bytes, tamanho por arquivo, profundidade, tamanho de caminho e tempo, para três momentos: recebimento da origem `ai`, recebimento das demais origens e bundle após dependências.
  - O percurso é iterativo, conta enquanto avança e para no primeiro limite. A ordenação só ocorre depois.
  - Diretórios de dependências e de VCS são ignorados sem serem percorridos. Diretórios vazios são descartados.
  - Nomes inválidos e colisões por maiúsculas/minúsculas ou NFC são recusados.
  - Tabela em [06-lifecycle.md](06-lifecycle.md#limites).
- **Consequências.** Memória e tempo limitados em todas as origens. O hash e o store ficam iguais em Linux e macOS. Uma pasta local de desenvolvimento com `node_modules/` instala sem custo extra. A verificação de colisão por NFC exige normalização Unicode no core.
