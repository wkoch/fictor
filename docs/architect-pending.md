# Pendências para o arquiteto

ARQ-020–029 resolvidas pelos ADRs 036–045. ARQ-030 resolvida pelo ADR-048,
com implementação reservada ao M0.9. ARQ-031 resolvida pelo ADR-047.
Resolução do spec não significa implementação concluída.

## ARQ-031 — Última tentativa de promoção após regressão do relógio civil

- **Status: resolvida em 2026-10-18 — [ADR-047](../spec/11-decisions.md#adr-047--ordem-durável-das-tentativas-de-promoção-resolve-arq-031).**
- **Referências:** `spec/02-core.md`, instalação local online, definição de `promotion` em `ext.install.status` (linhas 767–768); `spec/06-lifecycle.md`, promoção/repetição após `aborted`; `spec/schemas/0004_promotion_journal.sql`; `core/src/store/installations.rs`, `installation_snapshot`.
- **Dúvida:** o status deve escolher a última tentativa por `(created_at, operation_id)`, mas o writer usa relógio civil em `created_at`. Após uma tentativa `aborted`, uma nova tentativa explícita criada com o relógio recuado pode ter ULID maior e timestamp menor. A consulta normativa escolhe a tentativa antiga; a admissão de promoção também usa esse snapshot para deduplicar `prepared`/`committed`. O ULID do writer é monotônico, inclusive após reinício a partir do último evento persistido, mas substituir a ordenação por ULID contraria o contrato explícito.
- **Reprodução proposta:** criar e abortar uma promoção A; recuar o relógio civil; admitir B para a mesma proposta sem mudar a base; consultar enquanto B está `prepared` e depois de `committed`. Com `created_at(B) < created_at(A)`, a ordenação atual apresenta A. A análise foi feita no código; não foi alterado o relógio da máquina nem executado esse cenário.
- **Necessário:** definir como a ordem de criação permanece autoritativa com regressão do relógio, incluindo tentativas legadas. Opções a decidir são ajustar a ordenação ou definir timestamps lógicos limitados pelo histórico e seu efeito no evento imutável da preparação. O clamp não é aplicado implicitamente: intenção e evento usam o mesmo `created_at`, e eventos documentam Unix ms. Também esclarecer como status e deduplicação tratam um `prepared`/`committed` mais novo que a tentativa escolhida pela tupla.
- **Impacto:** a consulta pode informar `aborted` apesar de existir uma nova publicação e deixar de devolver prontamente o seu ID. Mantida a consulta definida pelo spec; nenhuma ordem alternativa, clamp de timestamp ou reescrita do histórico foi implementada sem ADR.
- **Resolução:** ordem pelo ID monotônico do evento de preparação, com associação e sequência validadas; timestamps civis permanecem inalterados. Status e deduplicação usam a mesma seleção. Legado válido usa eventos já existentes; corrupção falha sem reconstrução heurística.
- **Entrega:** implementar critérios 74–75 com relógio falso e reinício, incluindo B preparada/confirmada depois de A abortada; não alterar o relógio real. Resolução documental não significa implementação concluída.

## ARQ-030 — Contratos administrativos do M0.9 e durabilidade de rollback

- **Status: resolvida em 2026-10-18 — [ADR-048](../spec/11-decisions.md#adr-048--administração-e-manutenção-recuperável-do-m09-resolve-arq-030). Implementar somente no M0.9.**
- **Referências:** `spec/02-core.md`, CLI/runtimes/update; `spec/06-lifecycle.md`, rollback; ADRs 036/045.
- **Dúvida:** seleção de versão anterior e commit conjunto de rollback com `ext.rolled_back` não têm journal próprio; `promotion_intents` exige proposta e não deve receber proposta artificial. Runtime/update em lote e login também precisam métodos administrativos, autoridade e resultados definidos.
- **Necessário:** ADR antes dos handlers do M0.9, definindo seleção/durabilidade/recuperação de rollback, lotes de update e runtimes, nonce/revisão e login de uso único. Manter `update --core` exclusivo da CLI e sem caminho por UI/extensão.
- **Impacto:** não inventar esses handlers, reutilizar journal de proposta à força nem executar esses itens fora da ordem do roadmap. Resolver no início da preparação arquitetural do M0.9.
- **Resolução:** [contrato M0.9](../spec/12-maintenance.md) fixa planos/revisão/nonce, seleção de anterior, journal conjunto do lote separado de propostas, rollback com CAS dos itens, Python explícito, pins, login local efêmero e substituição segura do executável exclusivamente pela CLI. Inclui schemas persistidos, envelopes, eventos, recuperação e legado.
- **Entrega:** futura migração aditiva e handlers apenas no M0.9. Critérios 76–81; sem código, migração executável ou commit nesta resolução. Implementação e aceitação continuam pendentes.

## ARQ-029 — Contrato administrativo das mutações da Fase 0

- **Status: resolvida em 2026-10-18 — [ADR-045](../spec/11-decisions.md#adr-045--mutações-administrativas-e-instalação-local-online-resolve-arq-029).**
- **Referências:** `spec/02-core.md`, CLI, Reabilitação humana e Canal administrativo mínimo; ADRs 038/039/041.
- **Dúvida:** a CLI encaminha mutações ao core ativo e `ext reset-crashes` deve funcionar online. Entretanto, o canal mínimo define somente `ext.list` e determina que outros métodos exigem contrato próprio. Não há método/envelope/parâmetros/resultados de reset, enable/disable ou instalação autorizados para esse canal. A semântica de comandos e o transporte não determinam por si sós seu protocolo de mutação.
- **Necessário:** ADR com os métodos administrativos da Fase 0 que podem mutar estado, campos exatos, autoridade/decisão humana, erros e limites; especificar seleção de versão/sessão no reset, sem permitir comandos equivalentes por Kernel Protocol. Aprovação de proposta e segredo pelo TTY precisam conservar suas fronteiras, caso façam parte desse contrato.
- **Resolução:** ADR-045 define habilitação, reset, instalação local em quatro operações e segredos online. Revisão vinculada a nonce/hash/base/overrides, trabalho longo observado por status, efeitos incertos sem retry. Critérios 66–70; implementação e testes ainda pendentes.
- **Escopo restante:** operações do M0.9 rastreadas em ARQ-030; não autorizadas implicitamente por este contrato.

## ARQ-028 — Grants sobre mounts internos e fontes de pseudo-filesystems

- **Status: resolvida em 2026-10-18 — [ADR-044](../spec/11-decisions.md#adr-044--destinos-internos-e-origens-de-montagens-do-sandbox-resolve-arq-028).**
- **Referência:** I2/I4/I11; `spec/05-security.md`, regras comuns, origem
  protegida dos controles e perfil bubblewrap; `core/src/sandbox/mod.rs`,
  `validate_grant`; `core/src/sandbox/linux.rs`, ordem dos mounts.
- **Dúvida original:** o perfil gera proc/dev privados e caminhos internos em `/fx`, mas
  grants explícitos são aplicados depois e não há contrato reservando esses
  destinos. A revisão estática encontrou um grant host `/proc` que não é recusado
  pelas verificações de prefixos/sensíveis e é renderizado sobre o proc gerado.
  Além de substituir a árvore privada de processos, uma fonte procfs montada
  sob outro nome pode oferecer magic links para raízes/FDs do processo do host.
  Identidade dev/ino e coordenadas de bind/submount não demonstram separação
  dessas referências dinâmicas da árvore privada do core.
- **Necessário originalmente:** ADR definindo destinos internos que não podem ser sobrepostos,
  ancestrais/descendentes abrangidos e tratamento de fontes procfs/pseudo-FS
  (inclusive aliases) em grants. Fixar a recusa ou prova exigida antes do spawn,
  a relação com mounts implícitos legítimos e critérios com dados falsos, sem
  conceder acesso aos processos/arquivos do host para fazer o teste passar.
- **Implementação ao abrir a pendência:** novos controles por descritor e prova de binds comuns
  não alteram essa política. A atestação anterior ao workload deve detectar troca
  das fontes aprovadas; não transforma uma fonte inadequada em segura.
  Não foi executada tentativa de leitura de segredos ou memória do core.
- **Impacto ao abrir a pendência:** a conformidade do perfil geral e o gate de M0.5 permanecem abertos.
  A parte afetada aguarda ADR, conforme a regra 4 de AGENTS.md; as demais entregas
  podem avançar sem ampliar grants ou modificar o spec.
- **Resolução:** Plano único reserva destinos internos, protege bootstrap antes do init e confere a árvore final. Imports ordinários restritos a ext2/3/4, btrfs, xfs e tmpfs; overlay só nas bases RO fixas do sistema/Toolbx e bootstrap já coberto. Recusar magic links na resolução original e pseudoFS/aliases/submounts inadequados. /tmp e aliases de roteamento conservam filhos de dados autorizados e disjuntos.
- **Entrega ao implementador:** Aplicar a política ao perfil, renderer e prova/barreira existentes, inclusive recursos implícitos e smoke; não ampliar grants nem confiar só na atestação de um init já substituído. Critérios 61–65; implementação e gate continuam pendentes.
- **Progresso em 2026-10-18:** plano único, reservas/equivalências, resolução original sem magic links, classificação por FD e atestação de filesystem/aliases implementados. Matrizes reais usam árvores fictícias e namespaces próprios. Proteção do bootstrap e bibliotecas antes de executar init, integração da barreira durável e gate de release continuam pendentes; a atestação pelo próprio init não fecha essa lacuna.

## ARQ-027 — Correlação de IDs no limite de mensagem do Kernel Protocol

- **Status: resolvida em 2026-10-18 — [ADR-043](../spec/11-decisions.md#adr-043--ids-limitados-e-respostas-correlacionadas-no-kernel-protocol-resolve-arq-027).**
- **Referência:** `spec/03-kernel-protocol.md`, transporte (JSON-RPC 2.0 e mensagem
  máxima de 16 MiB); [JSON-RPC 2.0, seções 4 e 5](https://www.jsonrpc.org/specification),
  consultado em 2026-10-18; `core/src/kernel/transport.rs`, `write_value`.
- **Dúvida original:** o limite atual admite uma requisição cujo ID ocupa quase todo o
  frame, mas o envelope de erro com esse mesmo ID pode exceder 16 MiB. JSON-RPC
  exige repetir o ID conhecido. No socket real, após `kernel.hello` válido,
  `{"jsonrpc":"2.0","id":"<x repetido 16.777.177 vezes>","method":"x"}`
  mede 16.777.215 bytes; com LF, cabe exatamente em 16.777.216 bytes. O erro
  `METHOD_NOT_FOUND` correlacionado excede o limite em 39 bytes, e o fallback
  `TOO_LARGE` correlacionado em 32 bytes, antes do LF. `write_value` então envia
  o fallback de 74 bytes com `id: null`, embora o ID original tenha sido detectado.
  Não é possível preservar o ID e o erro obrigatório dentro do limite para todos
  os IDs hoje admitidos.
- **Necessário originalmente:** ADR definindo um limite/formato de ID que reserve espaço para
  o envelope de erro, ou a semântica de falha de transporte quando a resposta
  correlacionada não couber. Definir validação antes do dispatch, resposta ou
  encerramento permitido e o tratamento de efeitos já admitidos. A decisão deve
  preservar o limite de 16 MiB e esclarecer a compatibilidade com JSON-RPC.
- **Impacto ao abrir a pendência:** o cliente pode continuar aguardando uma requisição que recebeu
  erro com outro ID. O comportamento foi reproduzido com credenciais falsas e
  socket local no Toolbx Fedora 44/Bazzite; a asserção de correlação falhou.
  Não foi criado teto de ID, aumentado o frame nem alterado o protocolo sem ADR.
  O teste temporário de investigação foi removido; transcript em
  `.fictor/logs/kernel-large-id-before-transcript.log`.
- **Resolução:** ID String até 256 bytes UTF-8 decodificados ou Number de token até 256 bytes, com eco sem arredondamento; Null distinto de ausência. Excesso encerra antes de hello/dispatch. Resposta grande usa TOO_LARGE com o mesmo ID; falha de entrega não troca ID, desfaz efeitos nem autoriza retry. Um objeto por frame, sem batches; 16 MiB exclui LF.
- **Entrega ao implementador:** Aplicar admissão e writer do Kernel, mantendo MCP/admin/WS separados; SDK futuro conclui pendências e não repete chamadas. Critérios 57–60; implementação e testes do produto pendentes.
- **Progresso em 2026-10-18:** admissão, parser estrito e writer limitado implementados em `869ce81`, com testes de IDs/UTF-8/números opacos, batches, correlação de erros, efeitos e falha de entrega. SDK ainda não existe nesta fase; suas obrigações permanecem para M0.8. Gate de release continua pendente.

## ARQ-026 — Destinos de links dos arquivos de controle do core

- **Status: resolvida em 2026-10-18 — [ADR-042](../spec/11-decisions.md#adr-042--origem-protegida-dos-arquivos-de-controle-resolve-arq-026).**
- **Referência:** I11, origem de `config.get`, perfil de sandbox e arquivos globais `config.toml`/`AGENTS.md`.
- **Dúvida resolvida:** links para workspace/ext_data permitiam modificar conteúdo entregue a outra sessão como trusted/public; exigir somente alvo regular não comprovava origem protegida.
- **Resolução:** nomes diretos no home privado ancorado, sem symlinks/hardlinks ou montagens intermediárias; validar objeto, UID, modos e estabilidade a cada leitura. Recusar grants que exponham aliases da árvore privada, inclusive antes da criação dos controles. Falhas não viram cache, defaults ou ausência; legado exige revisão humana e inode novo, sem reparo automático.
- **Entrega ao implementador:** aplicar o mesmo contrato no boot, init e config.get; proteger aliases na construção do perfil e implementar os erros e critérios 51–56. Nenhum código do implementador foi incorporado nesta resolução; testes do produto e gate permanecem pendentes.

## ARQ-025 — Disponibilidade e estado de `fictor ext list`

- **Status: resolvida em 2026-10-18 — [ADR-041](../spec/11-decisions.md).**
- **Referência:** [CLI](../spec/02-core.md#listagem-de-extensões) e lock do ciclo de vida.
- **Dúvida resolvida:** a listagem funciona online e offline; “estado” nesta CLI é somente habilitação administrativa, nunca saúde de processos.
- **Resolução:** snapshot validado de ID/chave/versão/`enabled`, coordenado com o journal. Offline exige posse exclusiva e SQLite read-only considerando WAL; intenção pendente ou versão incompatível falha sem migrar/reconciliar. Online usa `ext.list` pelo contrato administrativo mínimo, sem fallback para arquivos. Critérios 47–50.
- **Entrega ao implementador:** implementar CLI e handler administrativo, mantendo a consulta sem mutações de estado da aplicação; testes e gate de release continuam pendentes.

## ARQ-020 — Recuperação da promoção entre filesystem, lock e evento

- **Status: resolvida em 2026-10-18 — [ADR-036](../spec/11-decisions.md).**
- **Referência:** [spec/06-lifecycle.md](../spec/06-lifecycle.md); contrato necessário para completar M0.5.
- **Resolução:** Journal, base fixada na revisão e compromisso após lock durável; snapshots reconciliados sem reexecução. Migração 0004 e critérios 38–39.
- **Entrega ao implementador:** adaptar código e automatizar os critérios; resolução arquitetural não declara implementação ou gate de release concluídos.

## ARQ-021 — Formato e aplicação dos overrides humanos

- **Status: resolvida em 2026-10-18 — [ADR-037](../spec/11-decisions.md).**
- **Referência:** [spec/06-lifecycle.md](../spec/06-lifecycle.md); contrato necessário para completar M0.5.
- **Resolução:** Schema de patch esparso; substituição por folha, subconjunto conservador e resultado único para sandbox, proxies, catálogo e política. Persistência atômica da decisão; critérios 40–41.
- **Entrega ao implementador:** adaptar código e automatizar os critérios; resolução arquitetural não declara implementação ou gate de release concluídos.

## ARQ-022 — Identidade e posse para limpeza de instâncias no boot

- **Status: resolvida em 2026-10-18 — [ADR-038](../spec/11-decisions.md).**
- **Referência:** [spec/02-core.md](../spec/02-core.md); contrato necessário para completar M0.5.
- **Resolução:** Posse exclusiva do home, journal versionado, barreira antes do workload e prova de término do launcher/PID 1; retenção conservadora de registros incompletos/legados. Critérios 42–43.
- **Entrega ao implementador:** adaptar código e automatizar os critérios; resolução arquitetural não declara implementação ou gate de release concluídos.

## ARQ-023 — Escopo do crash loop e reabilitação humana

- **Status: resolvida em 2026-10-18 — [ADR-039](../spec/11-decisions.md).**
- **Referência:** [spec/02-core.md](../spec/02-core.md); contrato necessário para completar M0.5.
- **Resolução:** Estado por extensão/chave/sessão, backoff lazy sem replay, bloqueio durável e reset humano explícito separado de enabled. Migração 0005 e critérios 44–45.
- **Entrega ao implementador:** adaptar código e automatizar os critérios; resolução arquitetural não declara implementação ou gate de release concluídos.

## ARQ-024 — Sintaxe e fronteira dos registros de dependências

- **Status: resolvida em 2026-10-18 — [ADR-040](../spec/11-decisions.md).**
- **Referência:** [spec/06-lifecycle.md](../spec/06-lifecycle.md#registros-de-dependências), etapa de dependências; configuração `installer.registries`.
- **Resolução:** autoridades exatas com gramática e normalização definidas, preservando porta explícita. Metadados, artefatos e redirects obedecem à mesma lista pelo proxy; conteúdo da candidata nunca a amplia. Registros locais de teste exigem autorização exata. Critério 46.
- **Entrega ao implementador:** adaptar validação/configuração e testes da etapa; sem nova capacidade de rede nem declaração de entrega concluída.

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
  Recebimento, migração e recuperação foram implementados em M0.5; o diagnóstico
  no Toolbx/Bazzite consta em `verification.md`. O gate no COSMIC Atomic continua
  pendente; resolução arquitetural e testes locais não constituem release.


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

- **Status: resolvida em 2026-10-17 — [ADR-029](../spec/11-decisions.md).** Namespace de PID com `__sandbox-init` como PID 1; confirmação de término reforçada pelo ADR-038 antes de liberar recursos.
- **Referência:** `spec/02-core.md`, encerramento; `spec/05-security.md`, bubblewrap; critério 26 da Fase 0.
- **Dúvida original:** um grupo POSIX não prova que toda a árvore terminou quando descendentes fazem `setsid()` ou trocam de grupo.
- **Necessário definido:** o namespace contém toda a árvore; a morte do PID 1 encerra seus processos. `--die-with-parent` cobre a morte do core. Sem confirmação em 10 s, usar `cleanup_failed` e reter recursos.
- **Implementação:** conferir encerramento e limpeza por namespace no backend Linux e executar o teste adversarial de fork duplo/`setsid()`, incluindo morte do core com SIGKILL. Testes e gate no Fedora ainda pendentes.
