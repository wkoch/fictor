# Pendências para o arquiteto

Nenhuma pendência arquitetural aberta em 2026-10-18. Resolução do spec não significa implementação concluída.

## ARQ-019 — Recebimento inválido antes da identidade do manifest

- **Status: resolvida em 2026-10-18 — [ADR-035](../spec/11-decisions.md#adr-035--propostas-duráveis-antes-da-identidade-resolve-arq-019).**
- **Referência:** `spec/06-lifecycle.md`, recebimento e estados da proposta;
  `spec/schemas/0001_init.sql`, tabela `proposals`; `core/src/store/proposals.rs`.
- **Dúvida:** limites, symlinks, nomes inválidos e YAML inválido podem ser
  detectados antes de haver `id`/`version` válidos. O pipeline exige uma proposta
  `failed`, mas o schema exige identidade não nula e não define uma representação
  para recebimentos sem identidade.
- **Necessário:** ADR com a representação persistida (identidade opcional ou
  registro separado), eventual migração, motivos/metadados mínimos e recuperação
  de diretórios `.receipt-*` após interrupção do processo.
- **Impacto:** esses recebimentos são recusados sem execução e a cópia temporária
  é removida, mas não geram proposta durável. Nenhuma identidade sentinela foi
  inventada. Falhas após identificar o bundle continuam registradas e auditadas.
- **Resolução:** proposta registrada antes de abrir a origem; `ext_id` e `version`
  nulos em conjunto até validar o manifest; migração 0003 sem alterar migrações
  anteriores. Falhas têm motivo estável e evento atômico. Recuperação encerra
  tentativas interrompidas e limpa temporários sem seguir links nem inventar
  registros para órfãos legados. Contrato em `spec/06-lifecycle.md` e
  `spec/03-kernel-protocol.md`; critérios 35–37 da Fase 0.
- **Entrega ao implementador:** copiar/aplicar a migração especificada, adaptar
  leituras e transições de propostas, recebimento, auditoria, recuperação e testes.
  O código desses itens permanece pendente em M0.5.


## Histórico resolvido

Registradas em 2026-10-17 durante a implementação. As pendências ARQ-001–018
foram resolvidas pelo arquiteto nos ADRs 013–029. Os ADRs 030/031 definem
Linux x86-64, Fedora COSMIC Atomic e a prioridade da v0.1 autossuficiente.
As descrições de dúvida, necessidade e impacto das ARQ-001–011 ficam preservadas
como histórico do registro original. Resolução arquitetural não
significa implementação concluída; o progresso consta em `docs/implementation.md`.

## ARQ-001 — Corte e gate da V1.0

- **Status: resolvida em 2026-10-17 — [ADR-013](../spec/11-decisions.md).** Corte da v1.0 e gates por release definidos no roadmap.

- **Referência:** `spec/10-roadmap.md`, Fases 0–4; `spec/README.md`, não objetivos da v1.
- **Dúvida:** quais fases e entregas são obrigatórias para chamar uma release de V1.0?
  O roadmap define gates por fase, mas não associa uma fase à release.
- **Necessário:** definir o corte, gates obrigatórios por plataforma e itens que podem ficar depois.
- **Impacto:** impede declarar V1.0 concluída; não bloqueia a Fase 0.

## ARQ-002 — Leituras diretas pelo harness e flag P

- **Status: resolvida em 2026-10-17 — [ADR-014](../spec/11-decisions.md).** I11, acesso mediado ao workspace e isolamento de estado por sessão.

- **Referência:** `spec/07-harness.md`, manifest e montagem de contexto;
  `spec/03-kernel-protocol.md`, proveniência dos eventos;
  `spec/05-security.md`, flags e Rule of Two.
- **Dúvida:** o harness recebe leitura de todo `${workspace}` e lê `AGENTS.md` diretamente.
  Essas leituras não passam por `tool.result`; eventos escritos pelo harness são
  `trusted/public` e não acendem flags. Como o core deve contabilizar acesso privado
  feito diretamente pelo harness para aplicar a Rule of Two?
- **Necessário:** definir se o acesso concedido já acende P, se a leitura deve passar
  por uma primitiva mediada, ou se existe outra regra explícita de contaminação.
  A garantia não pode depender de declaração voluntária do harness.
- **Impacto:** resolver antes de integrar acesso ao workspace e iniciar o harness
  em M0.5/M0.8. Ainda não há execução de extensão na implementação.

## ARQ-003 — Configuração inicial de modelos do harness

- **Status: resolvida em 2026-10-17 — [ADR-015](../spec/11-decisions.md).** Modelo inicial `main`, com configuração comentada a preencher.

- **Referência:** `spec/02-core.md`, exemplo de `[ext.harness]`;
  `spec/07-harness.md`, configuração e seleção por chave de `models`.
- **Dúvida:** o primeiro exemplo usa `default_model = "anthropic/claude-sonnet"`
  sem uma tabela `models`; o harness exige chave de `models`, como `sonnet`.
- **Necessário:** fornecer configuração inicial canônica, incluindo as entradas
  de modelos ou um fluxo explícito de configuração antes da primeira conversa.
- **Impacto:** bootstrap segue literalmente o exemplo do core e mantém `ext` opaco.
  Resolver antes de M0.8; o core não deve interpretar nomes de modelos.

## ARQ-004 — MIME de blobs endereçados por conteúdo

- **Status: resolvida em 2026-10-17 — [ADR-016](../spec/11-decisions.md).** Blobs guardam apenas bytes; MIME pertence à referência.

- **Referência:** `spec/03-kernel-protocol.md`, `blobs.put`/`blobs.get`;
  `spec/02-core.md`, blobs; `spec/08-shell.md`, download de anexos.
- **Dúvida:** `put` recebe MIME opcional e `get` retorna MIME, mas o armazenamento
  especificado guarda só bytes pelo hash. O mesmo conteúdo pode ser enviado com
  MIME diferente. Não está definido se MIME é inferido, por referência ou persistido.
- **Necessário:** definir a fonte de verdade e o comportamento para conflitos,
  incluindo um tipo seguro para conteúdo desconhecido. Se houver metadados
  persistidos, definir seu formato/migração.
- **Impacto:** bytes, hashes e limites estão implementados. Resolver antes dos
  métodos do Kernel Protocol e da entrega HTTP (M0.5/M0.7).

## ARQ-005 — Formato do fallback de segredos e backend bloqueado

- **Status: resolvida em 2026-10-17 — [ADR-018](../spec/11-decisions.md).** Backend explícito keyring/file sem fallback e schema 1 de secrets.toml.

- **Referência:** `spec/02-core.md`, Segredos; `spec/05-security.md`, Segredos.
- **Dúvida:** o spec fixa `secrets.toml` e modo 0600, mas não seu schema. Também não
  define se um keyring existente, mas bloqueado/temporariamente indisponível, permite fallback.
- **Necessário:** definir formato persistido e distinguir backend ausente de erro
  transitório do keyring bloqueado. Não criar uma cópia em texto de segredos do keyring silenciosamente.
- **Impacto:** M0.4 pode implementar o backend nativo. Fallback em disco permanece sem implementar.

## ARQ-006 — Captura parcial e limite dos streams do model proxy

- **Status: resolvida em 2026-10-17 — [ADR-017](../spec/11-decisions.md).** Captura antes da entrega e evento final com outcome e resp_complete.

- **Referência:** `spec/02-core.md`, Model proxy e Blobs; `spec/03-kernel-protocol.md`, `model.call`.
- **Dúvida:** streaming deve passar sem buffer e request/response devem ser gravados
  em blobs, cujo limite é 256 MiB. O evento não representa captura parcial/truncada.
  Qual é o contrato quando há cancelamento, falha de transporte/disco ou estouro do limite?
- **Necessário:** definir o que gravar, o que o cliente recebe e como distinguir
  resposta íntegra de parcial, incluindo blobs da requisição se a resposta não começar.
- **Impacto:** bloqueia concluir auditoria e erros do model proxy em M0.4. Não impede implementar egress.

## ARQ-007 — Contagem e persistência do orçamento

- **Status: resolvida em 2026-10-17 — [ADR-017](../spec/11-decisions.md).** Reserva transacional durável por dia civil local e por sessão.

- **Referência:** `spec/02-core.md`, Model proxy, `budget.*`.
- **Dúvida:** o dia é UTC ou local? O orçamento conta tentativas admitidas ou
  chamadas concluídas? Falhas, retries e chamadas interrompidas consomem cota?
  Qual registro persiste a reserva para sobreviver a reinício sem ultrapassar limites?
- **Necessário:** definir semântica de contagem, fonte de verdade durável e reserva
  concorrente. Se houver novo formato/evento/tabela, especificá-lo.
- **Impacto:** bloqueia o orçamento definitivo e a ativação do model proxy em M0.4.

## ARQ-008 — Colisão entre ambiente declarado e ambiente do core

- **Status: resolvida em 2026-10-17 — [ADR-019](../spec/11-decisions.md).** Nomes e prefixos reservados; colisão bloqueia validação e spawn.

- **Referência:** `spec/04-extensions.md`, Permissões; `spec/02-core.md`, Supervisor/Spawn.
- **Dúvida:** só `FICTOR_*` é reservado no manifest, mas `HOME`, `PATH`, `HTTP_PROXY`,
  `HTTPS_PROXY`, `NO_PROXY` e outras variáveis são determinadas pelo supervisor.
  `permissions.env` e `permissions.secrets[].env` podem tentar sobrescrevê-las.
- **Necessário:** definir nomes reservados e resultado da colisão na validação.
- **Impacto:** resolver antes de aceitar manifests no supervisor (M0.5). O launcher
  atual recebe ambiente construído pelo core e fixa HOME/tmp/PATH/locale/bypass de proxy.

## ARQ-009 — Descoberta de sockets de agentes em caminhos personalizados

- **Status: resolvida em 2026-10-17 — [ADR-020](../spec/11-decisions.md).** Descoberta de caminhos sensíveis e ponte TCP do kernel no Linux.

- **Referência:** `spec/05-security.md`, regras comuns do sandbox.
- **Dúvida:** SSH_AUTH_SOCK informa o socket SSH, mas GPG_AGENT_INFO normalmente
  não existe no GnuPG atual. Há caminhos customizados além dos diretórios padrão.
  Qual mecanismo confiável fornece a lista completa de sockets proibidos ao supervisor?
- **Necessário:** definir descoberta (por exemplo `gpgconf --list-dirs`, sem iniciar
  agentes) e comportamento se não for possível identificar endpoints personalizados.
- **Impacto:** o launcher bloqueia sockets indicados pelo ambiente, Docker e as
  árvores padrão do GPG, inclusive antes de os sockets existirem. Resolver descoberta
  personalizada antes de ativar grants arbitrários em extensões no M0.5. A documentação
  oficial recomenda [gpgconf para localizar sockets](https://wiki.gnupg.org/AgentForwarding).

## ARQ-010 — Sintaxe IPv6 na allowlist

- **Status: resolvida em 2026-10-17 — [ADR-021](../spec/11-decisions.md).** IPv6 literal com porta, normalização e regras para mapeados/NAT64.

- **Referência:** `spec/02-core.md`, destinos IP e porta explícita; `spec/schemas/extension.schema.json`, `permissions.net.allow`.
- **Dúvida:** a regra de IPs inclui destinos privados/loopback em geral, mas o regex
  do manifest não representa IPv6 literal. Deve aceitar `[IPv6]:porta`? Como tratar
  zonas de interface e normalização de IPv4 mapeado?
- **Necessário:** definir a sintaxe e atualizar o schema/protocolo antes de implementá-la.
- **Impacto:** o egress reconhece e nega IPv6 literal sem regra válida; IPv6 público
  obtido por DNS é validado normalmente. `*:porta` também não é aceito, porque o
  schema atual permite somente `*` simples ou domínio/subdomínio com porta opcional.

## ARQ-011 — Exceção HTTP para providers locais

- **Status: resolvida em 2026-10-17 — [ADR-022](../spec/11-decisions.md).** HTTP somente nos literais 127.0.0.1 e [::1], validado no boot.

- **Referência:** `spec/02-core.md`, Model proxy exige TLS, mas o exemplo Ollama e
  `AGENTS.md` usam `http://127.0.0.1:<porta>` para providers locais/falsos.
- **Dúvida:** a exceção abrange só IP loopback literal, `localhost`, rede privada
  ou algum opt-in explícito? Configurar base_url HTTP remoto permite expor a chave
  do core e o conteúdo privado em texto claro.
- **Necessário:** definir o limite e sua validação, sem downgrade automático.
- **Impacto:** o preparador de requisições aceita HTTP somente com IP loopback
  literal e rejeita as demais origens HTTP. O model proxy completo ainda não foi
  ativado; resolver antes de permitir qualquer exceção mais ampla.

## ARQ-012 — Prefixos NAT64 específicos da rede

- **Status: resolvida em 2026-10-17 — [ADR-023](../spec/11-decisions.md).** Prefixos explícitos RFC 6052, classificação local /48 e diagnóstico RFC 7050 sem alteração automática de política.
- **Referência:** ADR-021; `spec/02-core.md`, normalização de destinos de rede.
- **Dúvida:** NAT64 não especifica só o prefixo bem conhecido `64:ff9b::/96`.
  Há prefixos específicos da rede, com outros comprimentos, cujo IPv4 embutido
  não pode ser identificado apenas olhando o endereço IPv6.
- **Necessário:** explicitar se o contrato cobre somente o prefixo bem conhecido;
  caso cubra prefixos locais, definir configuração/descoberta confiável e como
  a validação deve tratá-los antes da conexão.
- **Implementação atual:** prefixos configurados nos comprimentos RFC 6052 extraem
  e verificam o IPv4 embutido. O /48 local permanece não público. `doctor` sugere
  prefixos descobertos, sem aceitá-los automaticamente. Testes usam DNS falso.
- **Impacto resolvido:** prefixos configurados são cobertos e testados conforme
  ADR-023. Prefixos desconhecidos permanecem o risco residual explicitado pelo ADR.

## ARQ-013 — Limites de quantidade na importação local

- **Status: resolvida em 2026-10-17 — [ADR-024](../spec/11-decisions.md).** Tetos fixos por perfil, incluindo entradas, bytes, arquivos, profundidade, caminho e tempo.
- **Referência:** `spec/06-lifecycle.md`, Recebimento; `spec/04-extensions.md`, bundle.
- **Dúvida:** a origem IA tem teto de 500 arquivos/5 MiB antes das dependências,
  mas a origem local só tem teto de 200 MiB em bytes. Árvores com muitos arquivos
  vazios/diretórios podem exceder memória/tempo sem ultrapassar o teto em bytes.
- **Necessário:** fixar limites de entradas (arquivos + diretórios) para origem
  local e para o bundle após resolver dependências, ou definir comportamento
  normativo de ordenação/inspeção com memória e tempo limitados sem esse teto.
- **Implementação atual:** `BundleProfile` seleciona constantes normativas e um
  `BundleBudget` compartilha o prazo entre operações. Percurso iterativo, contagem
  antes de ordenar e colisão NFC/minúsculas estão cobertos por testes.
- **Impacto resolvido:** os tetos normativos agora são aplicados e testados no
  recebimento e na inspeção após dependências. O restante do instalador segue em M0.5.


## ARQ-014 — Escrita global em sessões antes da marca d'água

- **Status: resolvida em 2026-10-17 — [ADR-025](../spec/11-decisions.md).** Na Fase 0, o instalador recusa processos globais com `phase:global`; bundles sem processo continuam permitidos.
- **Referência:** I11; `spec/03-kernel-protocol.md`, `events.write`; roadmap Fase 1, marca d'água global.
- **Dúvida:** extensões globais podem ler dados de várias sessões e escrever eventos em outra sessão com proveniência `trusted/public`. Sem a marca d'água global, adiada para a Fase 1, isso pode levar conteúdo privado/não confiável entre sessões sem contabilização.
- **Necessário:** definir quais operações globais ficam habilitadas na Fase 0 e como atribuir flags antes da marca d'água.
- **Implementação atual:** o transporte autentica identidades globais, mas restringe seus appends a `sys`. O supervisor não ativa instâncias globais até existir a mediação. Sessões só escrevem na própria sessão. Métodos de fases posteriores retornam erro explícito.
- **Impacto:** ativação global permanece bloqueada; extensões por sessão e smoke isolado podem avançar.

## ARQ-015 — Semver textual versus regex do schema

- **Status: resolvida em 2026-10-17 — [ADR-026](../spec/11-decisions.md).** Expressão oficial SemVer, até 64 caracteres; precedência ignora build e empate usa data de aprovação.
- **Referência:** `spec/04-extensions.md`, versão semver; `spec/schemas/extension.schema.json`, `version`.
- **Dúvida:** a expressão do schema rejeita sufixo `+build` válido em SemVer e aceita pré-releases como `1.0.0-01` e `1.0.0-alpha..x`.
- **Necessário:** alinhar a definição e o schema antes de depender de ordenação de versões.
- **Implementação:** validar pelo schema atualizado; ordenação SemVer do watcher continua na Fase 3. A resolução não antecipa o watcher.

## ARQ-016 — Runtime sem processo com MCP habilitado

- **Status: resolvida em 2026-10-17 — [ADR-027](../spec/11-decisions.md).** Tabela normativa de runtime/MCP/papel aplicada no schema e na validação semântica.
- **Referência:** `spec/04-extensions.md`, runtime `none`; schema do manifest, `mcp` e `role`.
- **Dúvida:** o schema admite `runtime.kind: none` com `mcp: true` (ou `role: harness`), embora não exista processo para realizar o handshake ou o loop do harness.
- **Necessário:** definir as combinações válidas e atualizar as regras semânticas.
- **Implementação:** conferir as combinações na validação, antes do spawn. Nenhum executável é inventado; bundles sem processo e sem MCP dispensam handshake.


## ARQ-017 — Raízes de filesystem no smoke de código não aprovado

- **Status: resolvida em 2026-10-17 — [ADR-028](../spec/11-decisions.md).** Ambiente de verificação descartável, sem conceder caminhos absolutos ou `~/`, com revisão dos grants omitidos.
- **Referência:** `spec/06-lifecycle.md`, smoke sem rede e com honeytokens; templates e grants absolutos do manifest.
- **Dúvida:** o spec substitui segredos e rede, mas não define como substituir diretórios absolutos/`~/` declarados por dados sintéticos. Conceder esses caminhos reais ao código ainda não aprovado permitiria ler ou alterar dados antes da decisão humana.
- **Necessário:** definir mapeamento de grants absolutos para raízes descartáveis e comportamento para dependências de arquivos reais.
- **Implementação:** smoke mantém bundle, workspace, ext_data, store, configuração e banco próprios. Deve omitir grants absolutos/`~/` e listá-los na revisão. Providers e segredos reais não são carregados; a validação completa dessa adaptação permanece pendente em Linux.

## ARQ-018 — Contenção de descendentes após daemonização

- **Status: resolvida em 2026-10-17 — [ADR-029](../spec/11-decisions.md).** Namespace de PID com `__sandbox-init` como PID 1; confirmar saída do bwrap antes de liberar recursos.
- **Referência:** `spec/02-core.md`, encerramento; `spec/05-security.md`, bubblewrap; critério 26 da Fase 0.
- **Dúvida original:** um grupo POSIX não prova que toda a árvore terminou quando descendentes fazem `setsid()` ou trocam de grupo.
- **Necessário definido:** o namespace contém toda a árvore; a morte do PID 1 encerra seus processos. `--die-with-parent` cobre a morte do core. Sem confirmação em 10 s, usar `cleanup_failed` e reter recursos.
- **Implementação:** conferir encerramento e limpeza por namespace no backend Linux e executar o teste adversarial de fork duplo/`setsid()`, incluindo morte do core com SIGKILL. Testes e gate no Fedora ainda pendentes.
