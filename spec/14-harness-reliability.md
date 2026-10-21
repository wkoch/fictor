# 14 — Contratos de confiabilidade do harness

ADR-050, 2026-10-20. Normativo para o harness padrão/SDK/tools first-party no M0.8, exceto seções marcadas Fase 2 ou Fase 4+. Complementa 03/07/09 e ADRs 046/049. Não muda isolamento, autorização, schema SQL ou o formato das APIs dos providers no core.

## Terminais e admissão de chamadas (M0.8)

O adapter mantém saída em construção separada de HMessage admitida. Deltas servem para apresentação; nunca executam tools. Uma tentativa termina exatamente uma vez com:

| terminal | Significado | Tools admitidas |
|---|---|---|
| complete | Resposta final normal, sem chamadas | nenhuma |
| tool_calls | Resposta completa contendo chamadas válidas | todas, depois de gravar assistant.message |
| output_limit | Limite de geração, inclusive se parte dos argumentos parece válida | nenhuma |
| cancelled | Cancelamento local explícito | nenhuma |
| error | Transporte, provider, protocolo ou terminal desconhecido | nenhuma |

Mapear apenas terminais explicitamente reconhecidos pelo adapter: Anthropic end_turn/stop_sequence → complete, tool_use → tool_calls, max_tokens → output_limit; Chat Completions stop → complete, tool_calls → tool_calls, length → output_limit, content_filter → error/provider_rejected. Outros valores falham como protocol. O perfil M0.8 de Chat Completions admite uma única escolha (n=1); choices extras não são mescladas. Tool calls usam o campo tools/tool_calls de Chat Completions; não converter silenciosamente para o protocolo legado functions/function_call.

Exigir fim lógico normal do protocolo, não apenas EOF: Anthropic message_stop após conteúdo completo; Chat Completions marcador [DONE] após finish_reason válido. Perfil incompatível exige versão explícita de adapter, não fallback por heurística. Usage pode chegar depois do finish_reason e antes do fim lógico. EOF/erro/cancelamento antes do fim descarta todas as chamadas daquela tentativa, mesmo se uma terminou antes das outras.

Antes de admitir tool_calls, validar IDs não vazios e únicos na resposta, nomes e argumentos JSON completos com raiz objeto; recusar nomes duplicados de propriedades JSON, IDs já usados no caminho da sessão e combinação incompatível entre terminal e chamadas. Deltas que repetem fragmentos do mesmo índice da chamada são montagem incremental, não nova chamada. Não reparar JSON truncado, inventar campo, executar subconjunto válido de resposta inválida ou completar argumentos com outra tentativa.

A política e validação de cada tools.call continuam no core; admissão do adapter não concede permissão. A resposta normalizada é gravada antes de iniciar qualquer chamada. Falha de persistência impede execução. Na reconstrução, resposta sem todos os resultados não autoriza repetir efeitos; vale a regra de turno interrompido do harness.

assistant.message.stop_reason usa os cinco terminais acima para respostas de modelo do harness padrão; blocked permanece reservado à interrupção por hook. Mensagens incompletas podem conservar texto/reasoning parcial para diagnóstico, mas têm tool_call_ids vazio, são apresentadas como parciais e NÃO entram no próximo contexto como resposta completa. O histórico anterior permanece legível, sem reescrita nem atribuição retroativa de terminal.

## Falhas e retries (M0.8)

ErrorKind = rate_limit | provider_unavailable | transport | context_limit | provider_rejected | protocol | budget | cancelled | unknown.

Classificar por status e campos estruturados reconhecidos na versão do adapter. Erro fictor_budget_exceeded → budget; 429 ordinário → rate_limit; 5xx → provider_unavailable; reset/timeout de transporte → transport. context_limit exige código estruturado documentado no adapter. Mensagem textual/regex não basta para disparar compactação. Corpo malformado não vira resposta de sucesso; usar protocol/unknown. Preservar somente código/status sanitizados, nunca headers de autenticação ou corpo de erro bruto nos eventos de diagnóstico.

Permitir até três retries adicionais, com esperas de 2, 4 e 8 segundos, apenas para rate_limit/provider_unavailable/transport e somente antes de receber qualquer delta de texto, reasoning ou tool call. Os retries reutilizam os mesmos bytes de requisição e configuração; cancelamento/budget encerra também a espera. Cada envio passa novamente pelo proxy e conta no orçamento. Todos os envios, inclusive retries e compactação, contam em max_iterations, que limita requisições de modelo por turno, não apenas respostas bem-sucedidas.

Depois de delta parcial não há retry automático. Também não repetir automaticamente output_limit, context_limit, provider_rejected, protocol, budget, cancelled ou unknown; não mudar provider, remover controles de cache ou aumentar limites para tentar passar. A compactação preventiva já contratada continua antes do envio; erro de contexto encerra a tentativa com diagnóstico, sem loop de compactação corretiva implícito.

Retry de modelo não é retry de ferramenta. Timeout/EOF depois de uma tool admitida significa resultado possivelmente desconhecido, sem reenvio automático. Encerrar por falha/cancelamento/limite não invoca turn.end para iniciar continuação automática; aguardar nova entrada. Na Fase 1, as até três continuações de turn.end compartilham o contador max_iterations da entrada inicial, sem reiniciar orçamento.

## Registro por tentativa (M0.8)

Os registros são declarações diagnósticas do harness, não atestações de confiança. O core conserva captura model.call, orçamento e política; não interpreta os payloads abaixo.

Tipos comuns: EventId = ULID retornado pelo core; BlobRef conforme 03; hashes de conteúdo são sha256 dos bytes UTF-8 ou binários exatos, sem normalização textual. Objetos abaixo não admitem campos extras na versão 1. Arrays vazios são explícitos; campos com ? podem faltar; null só onde indicado.

Antes de cada envio, gravar um blob JSON UTF-8 com SnapshotV1 e anexar harness.request. Sua persistência precede a requisição. SnapshotV1:

- schema: 1.
- harness: {ext_id: string, store_key: string, entry_sha256: BlobRef}. Identidade obtida do próprio bundle/entry empacotado em execução, não de um catálogo ativo que pode ter mudado. store_key é a chave versão-hash da árvore em execução. Não percorrer outros bundles para inferir identidade.
- model: {key: string, provider: string, api: string, model: string, context_window: integer, max_output_tokens: integer, thinking_budget: integer, prompt_cache: string}.
- limits: {max_iterations: integer, compaction_threshold: number, retry_delays_ms: integer[]}. Valores efetivamente usados, com defaults resolvidos.
- context_head_id: EventId | null; compaction_event_id: EventId | null.
- request_sha256: BlobRef. Hash dos bytes finais do corpo HTTP antes de enviar; não é referência a blob necessariamente existente. A captura autoritativa dos bytes continua no proxy.
- tools: object[]. Definições exatamente expostas ao modelo nesta requisição, depois dos hooks e antes da codificação específica do provider.
- skills: {ext_id: string, name: string, path: string, exposed: boolean}[]. Snapshot do catálogo visto; exposed indica presença do índice de nome/descrição no contexto final.
- hooks: {point: string, ext_ids: string[]}[]. Participantes efetivamente invocados na montagem; vazio na Fase 0. Não inferir execução somente de assinatura no catálogo.
- sources: {role: "system" | "instructions" | "workspace_instructions" | "skill" | "hook", sha256: BlobRef, event_id: EventId | null}[]. Hash dos bytes consumidos e evento de origem quando existir. Conteúdo não entra duplicado nesta ficha.
- environment: {platform: "linux", arch: "x86_64", runtime_version: string}. Versão do Node deste processo; sem dump de ambiente, hostname, credenciais ou config global.

O harness só copia campos enumerados, não serializa config.toml, headers, env ou segredos. A ficha pode conter nomes/caminhos privados e obedece aos canais/flags da sessão; não é exportação pública. Mudanças humanas de config entram no turno seguinte como já definido; seleção de modelo/hooks e contexto final são registrados por tentativa. Limites e os bytes dos retries não mudam durante a mesma tentativa lógica. Captura falha/parcial do proxy não é declarada completa pela ficha do harness.

Eventos, payloads schema 1:

| Kind | Payload |
|---|---|
| harness.request | {schema: 1, input_event_id: EventId, purpose: "turn" | "compaction", attempt: integer, retry_of: EventId | null, snapshot: BlobRef} |
| harness.response | {schema: 1, request_event_id: EventId, terminal: "complete" | "tool_calls" | "output_limit" | "cancelled" | "error", error_kind: ErrorKind | null, http_status: integer | null, provider_code: string | null, assistant_event_id: EventId | null, usage?: {input_tokens: integer, output_tokens: integer, cache_read_tokens?: integer, cache_write_tokens?: integer}} |
| harness.skill_loaded | {schema: 1, input_event_id: EventId, call_id: string, ext_id: string, name: string, path: string, content_sha256: BlobRef, local_tool_event_id: EventId} |

attempt começa em 1 por requisição lógica, cresce até 4; retry_of aponta sempre ao primeiro harness.request da sequência. input_event_id identifica a entrada original, inclusive continuações e compactação. Falha antes da admissão no proxy ainda recebe harness.response se o processo estiver vivo; erro local anterior a harness.request usa harness.error. Uma queda pode deixar request sem response: isso significa tentativa sem desfecho conhecido, nunca permissão para retomá-la.

usage segue ADR-046; presença em response e assistant.message é a mesma medição, não duas parcelas. response é a fonte por tentativa para agregação do harness novo; em histórico antigo usar assistant.message, sem somar ambos. Não inventar usage para falhas sem medição. Para compactação, assistant_event_id pode ser null: resumo entra em harness.compaction, não como conversa normal.

harness.skill_loaded é gravado após harness.local_tool e antes de entregar o corpo ao modelo. O catálogo distingue disponível de exposta; o evento distingue carregada. Ler só nome/descrição não é carregamento. Falha de leitura/ambiguidade não produz loaded. Nomes de skills duplicados entre extensões fazem load_skill falhar indicando os candidatos; não escolher pelo primeiro resultado. O path fixa a árvore aprovada e content_sha256 fixa os bytes lidos; não conceder permissões nem alegar utilidade causal.

Todos esses eventos ficam fora da projeção de conversa, salvo os dados de tools já previstos. Blob maior que o teto existente ou falha ao persistir impede envio; não truncar a ficha silenciosamente. Leitores aceitam ausência desses eventos em legado e indicam rastreabilidade incompleta, sem reconstruir o passado a partir do lock/config atual.

## Resultados de ferramentas first-party (M0.8)

fs-tools e shell-net devolvem, além do content MCP existente, structuredContent com ToolObservationV1. O gateway já expõe isso como structured; o core não interpreta o objeto.

ToolObservationV1 = {schema: 1, status: "ok" | "error", truncated: boolean, recovery: Recovery, exit_code: integer | null, error_code: string | null}.

Recovery = {kind: "none"} | {kind: "read_file", path: string, offset: integer} | {kind: "refine_query"} | {kind: "unavailable"}.

status=error implica isError=true. error_code é null em ok; em erro usar invalid_input, not_found, ambiguous_match, permission_denied, timeout, cancelled, command_failed, io ou unsupported. Mensagem legível fica em content e não inclui segredos. exit_code só é inteiro para comando concluído; sinal/timeout/erro de spawn usa null. Código zero significa sucesso do comando, não verificação da tarefa.

- read_file informa truncated=true quando restam linhas; recovery fornece o mesmo path validado e próximo offset 1-based. Não confundir leitura paginada com arquivo integral. Nova leitura observa o arquivo atual, não promete snapshot estável.
- list_dir/glob/grep que atingirem limite consultam evidência de item adicional antes de afirmar truncamento; truncados usam refine_query. Busca sem correspondência é ok, não erro. Caminhos/offsets para matches continuam em content.
- bash/bash_network conservam início/fim no teto existente e mostram separador de omissão. Sem cópia integral persistida, recovery=unavailable; não fabricar caminho de recuperação nem repetir comando para recuperar saída.
- Resultado completo usa recovery=none. Escrita/edição conserva os parâmetros e a correspondência inequívoca existentes; o trecho retornado não é prova de build/testes aprovados.

O harness apresenta status/truncamento ao modelo e à UI sem remover a proveniência do resultado. ToolObservationV1 informa observação, não autoridade; extensões de terceiros não são obrigadas a produzi-lo e ausência não significa que sua saída seja completa.

## Entrega entre subagentes (Fase 2)

Perfil do harness padrão, sem mudar o envelope de sessions.delegate/complete. A tool local delegate aceita, além de prompt/title/model já existentes, constraints?: string[], expected_artifacts?: string[], checks?: string[]. O pai serializa no prompt um objeto JSON HandoffRequestV1: {schema: 1, kind: "fictor.handoff", objective: string, constraints: string[], expected_artifacts: string[], checks: string[]}. objective vem de prompt; demais defaults são arrays vazios. Dados não se tornam confiáveis por estarem nesse formato.

O filho responde em sessions.complete.text com JSON HandoffResultV1: {schema: 1, kind: "fictor.handoff_result", outcome: "completed" | "blocked" | "interrupted", summary: string, artifacts: {path: string, sha256: BlobRef}[], checks: {name: string, status: "passed" | "failed" | "inconclusive" | "verifier_error", evidence: string}[]}.

paths são relativos ao workspace; pai acessa e confere bytes/hashes somente por tools.call autorizado. evidence é texto diagnóstico do filho (comandos/resultados), não autorização para consultar eventos de outra sessão. O pai não usa IDs alegados pelo filho para contornar escopos. O core devolve text e propaga flags como antes, sem interpretar o JSON.

Pai valida shape, compara entregas esperadas, trata checks ausentes como inconclusive e verifica artefatos antes de afirmar resultado verificado. completed não substitui essas verificações. Resposta legada em texto ou formato inválido é exibida como relato não verificado; não forçar retry automático. Timeout/cancelamento continua interrompido, mesmo se houver alterações no workspace. O resultado persistido de delegate permanece em harness.local_tool.

## Avaliação comparável (Fase 2)

Baseline/candidata usam mesmos casos, fixtures, modelo/parâmetros, permissões, critérios/scorer e budgets, salvo o componente declarado em comparação. Registrar diferenças intencionais; outras diferenças tornam a comparação inconclusiva e impedem promoção automática, sem impedir revisão humana.

Em eval_results.metrics, adotar MetricsV1: {schema: 1, model_calls: integer, duration_ms: integer, tokens: {input: integer | null, output: integer | null}, usage_complete: boolean, failure_kind: "none" | "provider" | "infrastructure" | "protocol" | "context" | "tool" | "policy" | "verification" | "budget" | "unknown", evidence_event_ids: string[], request_event_ids: string[], comparison: {component: string, fixture_sha256: BlobRef | null, scorer_sha256: BlobRef, comparable: boolean, reason: string | null}}.

model_calls conta model.call do caso e descendentes, incluindo compactação, retries, auxiliares e juiz; nenhum evento é contado duas vezes. Sessão de execução do juiz é associada pelo runner, não por alegação do candidato. duration_ms é tempo total monotônico observado pelo runner, incluindo checagens. Tokens vêm de response para harness novo, com fallback legado e sem dupla contagem; se qualquer chamada não tem usage suficiente, os totais correspondentes são null e usage_complete=false. Falha de medição não é zero.

O runner aplica max_seconds ao caso e checagens, e observa max_model_calls agregado. Ao atingir o limite não inicia novo trabalho e cancela o pendente; concorrência pode produzir excedente já admitido, que conta e reprova o caso por budget. Não prometer reserva atômica financeira ou limite agregado de segurança novo no Rust. Limites por sessão/dia do proxy continuam obrigatórios.

failure_kind indica a causa primária comprovada pelo runner, usando unknown quando houver ambiguidade; evidências preservam causas adicionais nos checks existentes. Bloqueio correto da política pode fazer passed=false para a tarefa sem ser falha de segurança. Não retirar falhas de infraestrutura do denominador; repetição gera outra trial registrada. Erro do verificador é verifier_error nos checks e infrastructure na causa primária, não sucesso.

Ficha/scorer/fixture ausentes ou baseline inconclusiva não passam silenciosamente pelo gate. pass^k continua consistência em todas as trials, não pass@k. Custos monetários são relatórios opcionais de extensão com fonte/data das tarifas, não novo campo obrigatório ou orçamento Rust. Campanhas com provider real exigem autorização/orçamento próprios; testes automatizados continuam falsos e sem chaves/rede externa.

## Seleção e teste final (Fase 4+)

Experimentos de evolução separam descoberta, validação usada na seleção e teste final intocado. Ao inspecionar o final para orientar nova mudança, ele deixa de ser final e deve ser substituído por outro conjunto independente antes de alegar generalização. Registrar resultados por tarefa, custo de todos os candidatos e hipóteses ligadas à evidência. Reavaliar a combinação de patches, mesmo se cada um passou sozinho. Avaliador, conjunto final e política ficam fora das mutações permitidas ao candidato. O pipeline do ADR-049 permanece a única via de promoção.
