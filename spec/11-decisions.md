# 11 — Decisões (ADRs)

Formato: contexto, decisão, consequências. Para mudar uma decisão, adicionar um ADR novo que substitui o anterior. No ADR antigo, só se acrescenta uma linha **Status** logo abaixo do título, apontando para o novo; o texto original não muda.

## ADR-001 — Core em Rust, crate único, base de confiança mínima

- **Contexto.** O core concentra sandbox, segredos, política e registro. O gargalo de desempenho do sistema é a latência do modelo, não o core.
- **Decisão.** Rust, um crate, binário único. Meta de 5–8 mil linhas.
- **Consequências.** Syscalls de sandbox e binário estático por plataforma ficam simples. O core muda pouco e não é editado pela IA.

## ADR-002 — Extensões fora do processo; sem JS ou WASM embutido

- **Status:** o runtime padrão passou a ser o Node LTS pelo [ADR-033](#adr-033--node-lts-no-lugar-do-deno). O restante vale.
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

## ADR-010 — Plataforma

- **Status:** substituído pelo [ADR-030](#adr-030--só-linux-x86-64-alvo-atual-fedora-cosmic-atomic).
- **Decisão vigente.** Ver ADR-030.

## ADR-011 — Sem bancos especializados no core

- **Contexto.** Vetores, grafos e séries temporais servem a funcionalidades específicas.
- **Decisão.** O core usa SQLite com FTS5. Extensões que precisam de outra coisa trazem o próprio banco no `${ext_data}`.
- **Consequências.** Core simples. Grafo de código, por exemplo, vive no SQLite da extensão com CTEs recursivas.

## ADR-012 — Lock em arquivo JSON

- **Contexto.** O usuário pode querer versionar o conjunto de extensões.
- **Decisão.** `extensions/lock.json`, escrito só pelo instalador com escrita atômica. Propostas e histórico ficam no banco.
- **Consequências.** Legível e versionável. O core mantém o lock em memória e o recarrega só após escrever.

## ADR-013 — Corte da v1.0 (resolve ARQ-001)

- **Status:** v0.1 redefinida pelo [ADR-031](#adr-031--v01-autossuficiente-e-fluxo-de-desenvolvimento).
- **Contexto.** O roadmap tinha gates por fase, mas nenhuma release associada. Os requisitos R4 e R5 (padrões da internet só com auditoria) dependem da Fase 3.
- **Decisão.** v0.1, v0.2 e v0.3 fecham as Fases 0, 1 e 2. A v1.0 exige as Fases 0–2 mais o núcleo da Fase 3 (importação de terceiros, auditoria, atualizações, Landlock e seccomp). Os demais itens da Fase 3 e a Fase 4 ficam para v1.x. Cada release exige os critérios na máquina Fedora COSMIC Atomic do usuário, CI verde e um teste por invariante. Detalhes em [10-roadmap.md](10-roadmap.md#releases).
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

## ADR-020 — Caminhos sensíveis e canal do kernel via TCP (resolve ARQ-009)

- **Contexto.** Não há como listar todos os sockets de agentes. Montar um diretório somente leitura não impede `connect()` em sockets dentro dele.
- **Decisão.**
  - Lista de caminhos sensíveis, mais descoberta (`SSH_AUTH_SOCK`, `gpgconf --list-dirs` sem iniciar agente, Docker, Podman, D-Bus). Montagem que é, contém ou está contida num caminho sensível é recusada. Sem `gpgconf`, usar os defaults e avisar.
  - O Kernel Protocol usa TCP em `127.0.0.1:3129` dentro do namespace da instância, com `__sandbox-init` fazendo a ponte para o Unix socket (como já faz para o proxy). A variável é `FICTOR_KERNEL_URL`.
  - Na Fase 3, o seccomp nega `socket(AF_UNIX)` à carga de trabalho.
- **Consequências.** Sockets fora da lista ficam inalcançáveis por estrutura a partir da Fase 3. Até lá é risco residual documentado. O sandbox já implementado precisa trocar o bind direto de `/fx/kernel.sock` para a carga de trabalho pela ponte TCP.

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
  - Nomes que não sejam UTF-8 válido, ou que contenham caracteres de controle ou `\`, são recusados.
  - Tabela em [06-lifecycle.md](06-lifecycle.md#limites).
- **Consequências.** Memória e tempo limitados em todas as origens. Uma pasta local de desenvolvimento com `node_modules/` instala sem custo extra.

## ADR-025 — Extensões globais só a partir da Fase 1 (resolve ARQ-014)

- **Contexto.** Uma instância global recebe dados de várias sessões e pode gravar eventos em qualquer uma. Sem a marca d'água, prevista para a Fase 1, isso levaria conteúdo privado ou não confiável de uma sessão para outra como `trusted/public`.
- **Decisão.**
  - Na Fase 0, o instalador recusa bundles `scope: global` com processo (motivo `phase:global`). Bundles `runtime: none` continuam permitidos.
  - A partir da Fase 1, junto com a marca d'água: `events.append` de instância global numa sessão diferente de `sys` sai com a classificação default da extensão combinada com a marca e acende as flags da sessão. `sessions.input` e `events.read` globais seguem a mesma regra ([03-kernel-protocol.md](03-kernel-protocol.md#proveniência-dos-eventos)).
- **Consequências.** A Fase 0 só tem instâncias de sessão, cujos dados já foram contabilizados. As extensões first-party globais (`web`, `search`) chegam na Fase 1, quando a mediação existe.

## ADR-026 — SemVer completo no manifest (resolve ARQ-015)

- **Contexto.** A expressão do schema recusava `+build` válido e aceitava pré-releases inválidas, como `1.0.0-01`.
- **Decisão.** Usar a expressão oficial de semver.org, com até 64 caracteres. A ordem segue a precedência SemVer, que ignora `+build`; empates são desfeitos pela data de aprovação. Rollback continua usando a ordem de aprovação, não a de versão.
- **Consequências.** A comparação de versões, usada pelo watcher da Fase 3, fica bem definida. A chave do store `<version>-<hash12>` continua inequívoca, porque o hash vem depois do último hífen.

## ADR-027 — Combinações válidas de runtime, MCP e papel (resolve ARQ-016)

- **Contexto.** O schema aceitava manifests impossíveis, como `runtime: none` com `mcp: true` ou harness sem processo.
- **Decisão.** Tabela normativa em [04-extensions.md](04-extensions.md#combinações-válidas), aplicada no schema e na validação semântica:
  - `none` é só para skills, comandos, testes e evals;
  - `remote` exige MCP e é global, sem kernel, hooks nem permissões declaradas;
  - harness exige processo, `scope: session` e `mcp: false`, sem hooks, surfaces ou tools;
  - processo sem MCP precisa de pelo menos um escopo de kernel.
- **Consequências.** O supervisor nunca precisa inventar um processo nem um handshake. Os erros aparecem na validação, não no spawn.

## ADR-028 — Ambiente de verificação para código não aprovado (resolve ARQ-017)

- **Contexto.** O smoke e os testes rodam código ainda não aprovado. Conceder a ele os caminhos absolutos ou `~/` declarados permitiria ler ou alterar dados reais antes da decisão humana.
- **Decisão.**
  - Toda execução anterior à aprovação usa um ambiente de verificação: `FICTOR_HOME` temporário, templates apontando para diretórios temporários, caminhos absolutos e `~/` não concedidos, sem rede, model proxy negando tudo e segredos substituídos por honeytokens ([06-lifecycle.md](06-lifecycle.md#ambiente-de-verificação)).
  - Autores não podem depender desses recursos em `initialize`, `tools/list` ou `resources/list`.
  - A revisão mostra os caminhos não concedidos.
- **Consequências.** Bundles com caminhos absolutos passam pela verificação sem acesso aos dados reais. Uma extensão que leia esses caminhos já na inicialização falha no smoke e precisa ser corrigida pelo autor.

## ADR-029 — Contenção da árvore de processos (resolve ARQ-018)

- **Contexto.** Com `spawn: true`, um descendente pode chamar `setsid()`, trocar de grupo ou ficar órfão. Encerrar pelo grupo de processos não garante que a árvore inteira terminou.
- **Decisão.**
  - A árvore da instância é o namespace de PID criado pelo bubblewrap, com `__sandbox-init` como PID 1. Quando o PID 1 morre, o kernel mata todos os processos do namespace.
  - Encerrar a instância revoga os tokens, sinaliza a árvore e confirma pela saída do `bwrap`. Sem confirmação em 10 s, a instância vira `cleanup_failed` e os recursos ficam retidos.
  - `--die-with-parent` cobre a morte do core; o boot seguinte limpa sockets e diretórios que sobraram ([02-core.md](02-core.md#encerramento)).
- **Consequências.** Daemonização não escapa do encerramento. O critério 26 da Fase 0 verifica com fork duplo e `setsid()`.

## ADR-030 — Só Linux x86-64; alvo atual Fedora COSMIC Atomic

- **Status:** a menção a pacotes sobrepostos com `rpm-ostree` foi revogada pelo [ADR-034](#adr-034--desenvolvimento-em-toolbx-vite-como-ferramenta-de-desenvolvimento) e pelo requisito R8. O restante vale.
- **Contexto.** O Fictor é pessoal e roda na máquina do usuário, um desktop Fedora COSMIC Atomic x86-64. Uma única plataforma mantém um único backend de sandbox e um único conjunto de testes.
- **Decisão.**
  - Plataforma suportada: Linux x86-64. Alvo validado e único gate: Fedora COSMIC Atomic, na versão estável corrente, na máquina do usuário. Outras distros Linux x86-64 podem funcionar, mas não são testadas nem bloqueiam release.
  - O core falha na compilação fora de `target_os = "linux"` + `target_arch = "x86_64"`. Não há código, testes nem CI para outros sistemas operacionais ou arquiteturas.
  - O desenvolvimento acontece no próprio Fedora COSMIC Atomic.
  - Características do Fedora Atomic que viram requisitos: `/usr` imutável; `/home`, `/opt`, `/srv`, `/mnt`, `/root` e `/usr/local` são symlinks para `/var/...`; SELinux em modo enforcing; toolchains do usuário ficam em `$HOME` ou em pacotes sobrepostos com `rpm-ostree` ([05-security.md](05-security.md#linux-bubblewrap)).
- **Consequências.** Código, testes e jobs de CI de outras plataformas saem do repositório. A CI roda Ubuntu 22.04 x86-64 e um container Fedora; o gate é a máquina do usuário.

## ADR-031 — v0.1 autossuficiente e fluxo de desenvolvimento

- **Status:** as toolchains no sandbox foram substituídas pelo ambiente toolbx do [ADR-034](#adr-034--desenvolvimento-em-toolbx-vite-como-ferramenta-de-desenvolvimento). O restante vale.
- **Contexto.** O usuário quer chegar o mais cedo possível a uma versão que permita continuar desenvolvendo o Fictor de dentro do próprio Fictor.
- **Decisão.**
  - **v0.1 = marco de autossuficiência.** Fase 0 completa, mais compactação no harness (antecipada da Fase 1), toolchains de desenvolvimento no sandbox, guarda de migração com backup e separação entre a instância de uso e as builds de teste ([10-roadmap.md](10-roadmap.md#marco-de-autossuficiência-v01)).
  - **Toolchains.** `[sandbox.toolchains]` monta, só leitura, caminhos de toolchains do usuário (rustup, cargo, deno) e define variáveis para extensões com `permissions.toolchains: true` ([04-extensions.md](04-extensions.md#permissões)). Caches graváveis ficam no workspace. Credenciais de registros continuam inacessíveis.
  - **O core não se substitui.** O Fictor compila builds novas do próprio core dentro do workspace. Instalar o binário e reiniciar o serviço é ação do usuário, fora do Fictor; nenhum sandbox tem escrita em `~/.local/bin`. Builds de teste usam `FICTOR_HOME` temporário.
  - **Push fica com o usuário.** O agente faz commits locais. `git push` acontece fora do Fictor, depois da revisão. Nenhuma credencial de git ou SSH entra no sandbox.
- **Consequências.** O caminho até usar o Fictor no dia a dia fica curto e explícito. A partir da v0.1, o Fictor desenvolve o Fictor, com o usuário controlando instalação, push e migrações.

## ADR-032 — Gerenciador de runtimes e `fictor update`

- **Contexto.** A instalação de uso precisa funcionar num Fedora COSMIC Atomic limpo, baixando só o binário (R8). Versões novas dos runtimes não podem exigir build nova do core.
- **Decisão.**
  - O core sabe instalar, verificar, ativar e reverter runtimes. As versões são dados no lock (seção `runtimes`), não código ([02-core.md](02-core.md#runtimes)).
  - As fontes ficam no config, em `[runtimes.<nome>]`, com dois tipos: `nodejs` (índice oficial do nodejs.org, canal `lts`, `SHASUMS256.txt`) e `github-release` (asset mais arquivo de checksum da mesma release).
  - O core baixa só dos hosts da fonte. A extração roda num sandbox sem rede (`fictor __extract`). Antes de ativar, o smoke das extensões ativas roda com a versão candidata. Toda ativação exige aprovação humana, as 3 últimas versões ficam guardadas e há rollback.
  - `fictor init` instala o Node LTS. O uv só é instalado quando a primeira extensão `python` aparece.
  - `fictor update` verifica runtimes, extensões e releases novas do core:
    - "Aprovar tudo" cobre só itens sem falhas e sem ampliação de permissão;
    - cada aplicação vira um lote, registrado no evento `update.batch`, com rollback do lote inteiro;
    - `fictor update --core`, só pela CLI, troca o binário em `~/.local/bin` e guarda o anterior.
  - As extensões padrão viajam dentro do binário como origem `builtin` ([06-lifecycle.md](06-lifecycle.md#origens)).
- **Consequências.** Instalar é baixar um binário. Atualizar Node ou uv não toca o core. Em troca, confia-se no que o upstream publica no momento da atualização; checksum, smoke, aprovação e rollback mitigam esse risco.

## ADR-033 — Node LTS no lugar do Deno

- **Contexto.** A Cloudflare comprou a Deno Land em outubro de 2026. Segundo o que foi divulgado, o desenvolvimento oficial do runtime termina em cerca de um ano. Nenhuma extensão tinha sido escrita ainda.
- **Decisão.**
  - O runtime `deno` sai. `node`, na versão LTS do gerenciador de runtimes, é o runtime JavaScript.
  - O modelo de permissões do Node (`--permission` com `--allow-fs-read`, `--allow-fs-write`, `--allow-child-process`, `--allow-worker`, `--allow-net`) é a defesa em profundidade. Addons nativos e WASI nunca são liberados.
  - O código first-party usa só APIs web padrão e módulos `node:`, para continuar portável.
  - As extensões padrão são distribuídas como um único `.mjs` empacotado.
- **Consequências.** Pacotes npm e servidores MCP de terceiros rodam nativamente. Perde-se a allowlist de rede por host do Deno; o egress proxy continua aplicando a allowlist. Pacotes com addons nativos só rodam no tier `container`.

## ADR-034 — Desenvolvimento em toolbx; Vite+ como ferramenta de desenvolvimento

- **Contexto.** A base imutável não pode receber pacotes sobrepostos (R8). Desenvolver o Fictor exige Rust, compilador C, git, Node e ferramentas de TypeScript. O `[sandbox.toolchains]` existia só para levar essas ferramentas ao sandbox do host.
- **Decisão.**
  - O ambiente de desenvolvimento é um container toolbx definido em `dev/Containerfile`. Ele parte da imagem `fedora-toolbox` da versão alvo e instala, via `dnf`, `rust`, `cargo`, `clippy`, `rustfmt`, `gcc`, `git`, `nodejs`, `npm` e `bubblewrap`. O Fictor não automatiza nada disso.
  - O Vite+ é dependência npm de desenvolvimento do repositório, com `vp check`, `vp test`, `vp build`, `vp pack` e `vp run`. O `vp env` não é usado: o Node vem do container.
  - As extensões padrão são empacotadas com `vp pack` num único `.mjs` e embutidas no binário durante a build.
  - Para a autossuficiência, uma instância de desenvolvimento roda dentro do toolbx, com `FICTOR_HOME=~/.local/share/fictor-dev` e portas 7360/7361. Os sandboxes dela montam o `/usr` do container.
  - `[sandbox.toolchains]` e `permissions.toolchains` saem. Variáveis de projeto para os comandos (como `CARGO_HOME`) vêm de `<workspace>/.fictor/env`, aplicado por `fs-tools` e `shell-net`.
  - Ferramentas para outros projetos na instalação de uso ficam para a Fase 3, com o tier `container` usando uma imagem por workspace.
- **Consequências.** O host fica limpo, e as ferramentas de desenvolvimento ficam num único lugar. O bubblewrap dentro do toolbx precisa funcionar; isso vira critério de aceitação. Plano de saída do Vite+: chamar Vite, Vitest, Oxlint, Oxfmt e tsdown diretamente.
