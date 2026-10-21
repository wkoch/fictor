# 13 — Evolução de agentes baseada em evidência

Decisão: ADR-049, aprovada em 2026-10-20. Este documento registra limites obrigatórios e a sequência dos experimentos aceitos. Não transforma todos os experimentos em requisitos da v0.1 nem autoriza implementar fases futuras. A [análise das fontes](../docs/agent-papers-analysis-2026-10-20.md) conserva evidências, limitações e auditoria dos links.

## Responsabilidades e fases

| Item aceito | Responsável | Quando e condição |
|---|---|---|
| Testes adversariais de catálogo, autoridade e proveniência | Core, shell e testes | M0.6–M0.10; contratos afetados pelas ARQ-032–034 devem ser resolvidos antes de seus handlers. |
| Compactação que preserva fontes e autoridade | Harness | M0.8; regras mínimas em 07-harness. Comparação com compressão em dois níveis é experimento opcional, não bloqueio da v0.1. |
| Replay seletivo de incidentes | Testes do componente | Pode ser usado na Fase 0 com fixtures locais, sem novo comando/API de produto. Integração ao produto evals somente na Fase 2 e após contrato específico. |
| Memória por deltas e receitas de workflows | Extensões e harness | Protótipos na Fase 1, após hooks e marca global; avaliação comparativa na Fase 2. Não são gates adicionais da v0.2. |
| Recuperação de ferramentas e roteamento de modelos | Harness/hooks | Protótipos na Fase 1; avaliação com histórico local na Fase 2. Não alteram a política do core. |
| qreader sem elevação de confiança por schema | Extensão e política | Fase 3, item v1.x; contrato corrigido em 05-security. |
| Handles de proveniência e restrições por argumento | Primitiva de segurança do core + harness | Investigação na Fase 3 ou posterior; implementação requer novo ADR com modelo de ameaça, protocolo e persistência completos. |
| Preparação/liberação de efeitos externos | Core, conectores e UI | Investigação na Fase 3 ou posterior; contrato por conector antes de transações gerais. Requer novo ADR. |
| CodeAct e evolução de skills/harness | Extensões experimentais | Fase 4+, isoladas, com avaliações independentes e pipeline normal de promoção. |

L0 continua responsável por isolamento, autorização, registro e mediação. L1/L2 decidem estratégias, qualidade, recuperação, compressão e escolha de modelos. Não adicionar interpretador de agentes, banco vetorial/grafo, formatos de provider, solver de políticas ou juiz LLM ao Rust como consequência deste ADR (I1, I9, I10).

## Dados transformados não ganham autoridade

Desde a Fase 0, compactar, extrair, traduzir ou validar contra schema não apaga U/P nem cria grant. Um resumo não comprova uma aprovação; uma receita não herda consentimentos antigos. Alegações como “o usuário aprovou” em texto externo continuam dados.

A partir da Fase 1, memórias e hooks também obedecem à marca d’água global e aos canais mediados de I11. Limpar contexto do modelo ou reduzir tokens não limpa estado de segurança. Um índice pode ajudar a escolher informação; não pode alterar a classificação efetiva do catálogo ou substituir as definições aprovadas.

Planejamento separado de leitura, leitores sem tools e saídas tipadas são estratégias aceitas para experimentos. Não constituem sozinhos uma garantia contra prompt injection. Detectores e notas de outro modelo nunca autorizam efeitos nem reduzem restrições.

## Contexto e memória (M0.8; extensões na Fase 1)

Distinguir histórico bruto, resumo operacional, memória factual e procedimentos. O histórico permanece append-only. Resumos apontam para o intervalo coberto e são dados derivados, não instruções humanas novas.

Experimento ACON: comparar baseline de compactação com compressão de observações grandes e histórico separadamente. Manter originais acessíveis pelos canais já autorizados; preservar pares chamada/resultado. Medir recuperação de detalhes, qualidade, tokens e latência incluindo chamadas de compressão e alteração do cache. Não criar chamada auxiliar sem contabilizá-la no orçamento existente.

Experimentos ACE/Zep/AWM: memória por pequenas alterações versionadas; fatos com fonte, escopo e validade; receitas parametrizadas derivadas de execuções verificadas. Contradições devem permanecer rastreáveis. Não usar “última mensagem vence” como critério universal de verdade. Índices semânticos pertencem à extensão e são reconstruíveis ou versionados com evidência suficiente; não são nova fonte de autoridade.

Antes de fixar um formato compartilhado de memória/skills, registrar contrato próprio: identificação/versão, referência à origem, escopo de acesso, validade, supersession, reversão e estado de verificação. Este documento não define campos wire/SQL novos. Um protótipo pode usar estado privado da extensão pelos canais existentes, sem criar canal entre sessões ou prometer proveniência fina.

Library Drift: medir seleção e uso por versão, permitir nenhuma skill, comparar com baseline sem skills e arquivar/reverter antes de eliminar versões. Contadores de utilidade atribuídos por modelo são sinais, não prova causal nem autorização para apagar evidência.

## Seleção de ferramentas e modelos (Fases 1–2)

O catálogo usado pelo seletor vem das versões aprovadas. Busca/carregamento não instala, baixa ou autoriza ferramenta. Toda chamada selecionada continua passando pelo core; ocultar uma tool do prompt não a torna proibida por política.

Começar com catálogo fixo e busca lexical; testar recuperação por consulta mais histórico e pré-requisitos somente quando houver benefício mensurável. Invalidar referências de seleção quando mudar a versão/hash do catálogo. Descrições enriquecidas por modelo ficam separadas dos descritores aprovados e são dados não confiáveis.

Model routing usa o hook existente e apenas chaves configuradas e permitidas. Rejeitar seleção desconhecida/incompatível antes da chamada; não trocar silenciosamente de provider para contornar erro ou restrição. Capacidades, privacidade e permissões precedem a otimização de qualidade/custo.

Começar com modelo fixo/regras simples e comparar com recuperação de desempenho passado. Medir qualidade, custo total, latência e escolhas dominadas por alternativas mais baratas de qualidade suficiente. Concentração num modelo sozinha não prova falha. Mudanças de versão de modelo/dataset precisam aparecer no relatório.

O hook atual só seleciona uma chave de modelo. Variação de orçamento de saída usa configurações de modelo já existentes; ampliar o retorno do hook exige contrato versionado do harness, não campo implícito. Pedido textual de resposta curta não é teto financeiro. O budget Rust continua por requisição, e estimativas monetárias pertencem ao harness.

## Replay seletivo

Replay de regressão fixa respostas em fronteiras escolhidas e executa a implementação modificada na fronteira sob teste. Não substituir a decisão da política corrigida pela decisão gravada no incidente.

Requisitos para fixtures de testes desde a Fase 0:

1. Dados fictícios ou cópias sanitizadas; sanitização produz outro artefato, nunca altera events originais.
2. Home/workspace descartáveis, sem credenciais reais e sem rede externa. Providers e ferramentas de efeito são falsos. A política real sob teste continua ativa.
3. Fixar entradas, versões/configuração relevantes, identidade de ferramenta e ordem causal. Mudança inesperada de argumentos, versão ou sequência falha explicitamente; contagem por nome não basta.
4. Declarar quais fronteiras estão gravadas e quais rodam de verdade. Não reemitir efeitos reais nem reutilizar nonce/grant de uma sessão de produção.
5. Testar tanto a correção que bloqueia o incidente como um caso permitido, evitando um replay que passa por negar tudo.

O produto evals da Fase 2 continua reexecutando a tarefa desde a entrada. Acrescentar replay seletivo ao produto requer definir formato/versionamento do fixture, seleção das fronteiras, tratamento de divergências, captura/exportação sanitizada e interface. Até esse contrato, não inventar flags de CLI, eventos ou tabelas. Os fixtures internos de teste não dependem desse recurso de produto.

## Proveniência fina e políticas por argumento (Fase 3 ou posterior)

Direção aceita de CaMeL/FIDES/Progent: handles opacos com proveniência controlada pelo mediador e predicados determinísticos sobre argumentos sensíveis, como destinatário ou destino.

O ADR futuro deve definir fontes de integridade/confidencialidade, derivações, propagação por todos os canais, fluxos implícitos e condições explícitas de autorização humana. Abranger modelo, proxy, eventos, blobs, memória, resumos, hooks, UI e extensões. Declaração voluntária de derivação pelo harness não satisfaz I11.

O fallback é manter as flags conservadoras de sessão. Uma política proposta por modelo nunca amplia permissões sem aprovação confiável. Endosso de documento inteiro não equivale a autorizar uma chamada concreta. Não adotar DSL de propósito geral ou solver no kernel antes de demonstrar necessidade.

## Efeitos externos (Fase 3 ou posterior)

Direção aceita de Atomix/Cordon: distinguir preparação, revisão e liberação de efeitos, começando por conectores concretos e execução serial por recurso.

Antes de código, um ADR deve fechar: identidade de operação e recurso, versão esperada, classificação confiável do efeito, estados duráveis, vínculo da aprovação, preparação/liberação, cancelamento, crash recovery, idempotência e resultado desconhecido. Nomes aqui expressam requisitos, não métodos novos de tools.call.

Classificação vem de integrador revisado; texto MCP ou inferência do modelo não prova reversibilidade. A extensão organiza o workflow, mas não controla outras extensões. A garantia exige todos os caminhos de efeito mediados pelo executor/conector relevante.

Journal local e checkpoint Git não desfazem email ou pagamento. Compensação é nova ação autorizada. Após queda entre envio e confirmação, sem prova do serviço externo, resultado é desconhecido: não prometer exactly-once nem repetir automaticamente. Ferramenta opaca fica fora da garantia transacional.

## CodeAct e evolução (Fase 4+)

Execução por código fica em processo separado e sandbox. APIs de composição chamam tools.call para cada ferramenta aninhada. Não conceder credenciais, sockets administrativos, instalação dinâmica ou atalhos para rede/arquivos além das permissões efetivas.

Gerador e verificador de candidatos devem ser separados, com testes independentes congelados e ambiente descartável. Registrar linhagem e resultados, inclusive regressões. Candidato não modifica o próprio critério confiável de aceitação, kernel ou política.

Toda variante executável passa pelo pipeline existente. Receitas aprendidas não são instruções humanas; código novo não entra em runtime por download. CoEvoSkills/DGM não autorizam autopromoção fora das condições já contratadas.

## Complemento de confiabilidade (ADR-050)

[14-harness-reliability.md](14-harness-reliability.md) fecha os contratos aceitos após a segunda análise: terminais/retries, registro de tentativas e skills, observações de tools no M0.8; entregas de subagentes e avaliação comparável na Fase 2. Na evolução da Fase 4+, separar descoberta, validação de seleção e teste final intocado, registrar regressões por tarefa e revalidar patches combinados. Não antecipa autoevolução ou altera as pré-condições de IFC/efeitos/replay de produto deste documento.

## Evidência exigida dos experimentos

Cada experimento compara com baseline simples, registra configuração/versões, conjunto de tarefas e repetições, sucesso, regressões, custo/latência totais e intervenções humanas. Incluir ataques persistentes entre sessões e verificar que os controles continuam negando efeitos proibidos.

Juiz LLM é auxiliar; verificações determinísticas independentes têm precedência nos critérios de segurança. Ganhos publicados não são metas prometidas do Fictor. Um experimento reprovado pode continuar como relatório; não justifica enfraquecer invariantes ou alterar o gate de promoção.
