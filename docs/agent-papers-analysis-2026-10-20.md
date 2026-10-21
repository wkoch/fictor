# Papers sobre agentes: aplicação ao Fictor

Data: 2026-10-20. Status: análise aceita pelo usuário e registrada no [ADR-049](../spec/11-decisions.md#adr-049--melhorias-de-agentes-por-camada-e-preservação-de-autoridade) e em [13-agent-evolution.md](../spec/13-agent-evolution.md). O restante deste relatório preserva a análise anterior à decisão; os contratos atualizados do spec prevalecem. Experimentos respeitam suas fases; a aprovação não resolve automaticamente ARQ-032–034.

## Conclusão

A arquitetura atual continua adequada. Rust deve mediar autoridade, proveniência e efeitos; harness e extensões devem experimentar planejamento, contexto, memória, composição de ferramentas e escolha de modelos. Os trabalhos não justificam colocar um interpretador de agentes, banco semântico ou avaliador LLM no kernel.

Há duas famílias que podem exigir novas primitivas confiáveis: controle de fluxo por valor/argumento e preparação/liberação de efeitos externos. Um mod pode demonstrar utilidade, mas não oferecer sozinho essas garantias contra outros componentes maliciosos.

Prioridade imediata: fechar os contratos pendentes de M0.6 e melhorar testes adversariais. Depois, avaliar compressão, replay seletivo e memória simples. IFC fino, transações multietapas e evolução automática ficam para discussão posterior, preservando a prioridade v0.1.

## Comparação com o spec atual

Leitura arquitetural, não auditoria da implementação.

| Tema | Já especificado | Consequência da pesquisa |
|---|---|---|
| Autoridade | I3/I8, tools.call no core, aprovações humanas | Preservar. Resolver ARQ-033 antes da integração executável; aprovação deve corresponder à chamada efetivamente admitida. |
| Fluxo de informação | I11, flags U/P cumulativas, workspace e marca global na Fase 1 | Boa base conservadora. Não substituir por rótulos autodeclarados pelo modelo. |
| Catálogo MCP | Hash das definições fixado; mudança desativa extensão | Já cobre parte importante de rug pull. Acrescentar cenários adversariais aos testes, não criar outra arquitetura de catálogo. |
| qreader | Fase 3; saída de schema restrito pode receber trusted | Revisar significado de trusted: boolean/enum/data reduz expressividade, mas pode estar errado e dirigir efeito perigoso. |
| Contexto | Compactação M0.8, hooks, cache ADR-046 | Experimentar compressão em dois níveis no harness; medir custo incluindo compressor e perda de cache. |
| Evals | Fase 2; novas execuções desde a entrada | Replay seletivo é modalidade complementar, ainda não contratada; não chamar os evals atuais de replay. |
| Código e skills | I7, instalação aprovada, skills em bundles, shell em sandbox | Aprendizado gera candidatos para o pipeline existente. Não introduzir instalação paralela. |
| Manutenção | Journals de promoção/administração, ADR-048 | Não equivalem a transações distribuídas nem desfazem efeitos externos. |

Referências locais: [segurança](../spec/05-security.md), [harness](../spec/07-harness.md), [evals](../spec/09-evals.md), [extensões](../spec/04-extensions.md), [roadmap](../spec/10-roadmap.md), [pendências](architect-pending.md).

Na leitura de 20/10, ARQ-032, ARQ-033 e ARQ-034 estão pendentes: casamento de regras/fallback plan, aprovações duráveis e limpeza de flags de workspaces sobrepostos. Esta pesquisa não as resolve. Em especial, os estudos de IFC reforçam a necessidade de evitar descontaminação acidental na ARQ-034.

## Segurança: dados não concedem autoridade

| Trabalho primário | Contribuição e limite | Aplicação proposta |
|---|---|---|
| [CaMeL](https://arxiv.org/html/2503.18813v1) | Separa planejamento de dados externos e verifica fluxos num interpretador. Depende de política, proveniência e hipóteses sobre entradas confiáveis; dois LLMs isoladamente não bastam. | Harness experimental com referências opacas e leitor sem tools. Executor separado; nenhum Python no Rust. |
| [FIDES](https://arxiv.org/html/2505.23643v2) | Rótulos de integridade/confidencialidade, expansão seletiva e variáveis ocultas. Não-interferência de integridade não equivale a confidencialidade completa: explicit secrecy não elimina vazamento implícito. | Futuro contrato de handles e política por argumento, se benefício justificar. Rótulos atribuídos e propagados em fronteiras confiáveis. |
| [PRUDENTIA](https://arxiv.org/html/2602.11416) | Planejamento consciente da política e avaliação por intervenção humana. Título real: Optimizing Agent Planning for Security and Autonomy. Resultados dependem de humanos capazes de reconhecer ações maliciosas. | Expor motivos de bloqueio ao harness; medir aprovações por tarefa concluída. Evitar endosso genérico de documento como instrução confiável. |
| [Progent](https://arxiv.org/html/2504.11703v1) | Políticas determinísticas sobre ferramentas/argumentos. Os autores reconhecem perda de garantias ao gerar/atualizar políticas por LLM. | Considerar predicados pequenos para destinatário/destino/argumentos. Modelo propõe; autoridade existente decide. Não importar solver ou DSL geral sem necessidade. |
| [Design Patterns](https://arxiv.org/html/2506.08837v1) | Modos como plano prévio, dual LLM e execução restrita trocam generalidade por contenção. Não há padrão universal. | Harnesses especializados: resumir sem efeitos; envio com destinatário fixado por humano antes de ler conteúdo externo. |
| [MCP Threat Modeling](https://arxiv.org/html/2603.22489v1) | Descrições maliciosas, parâmetros pouco visíveis e fronteiras entre clientes/servidores. Estudo limitado às versões e cenários avaliados. | Fixtures de poisoning, nomes semelhantes, argumentos ocultos e catálogo alterado após aprovação; UI mostra identidade efetiva. |
| [Securing MCP](https://arxiv.org/html/2512.06556v1) | Assinaturas, revisão LLM e heurísticas. Simulação e detalhes editoriais/metodológicos insuficientes desaconselham usar seus números como base decisória. | Assinatura comprova origem/bytes, não benignidade. Detector LLM só informa, nunca desativa o controle obrigatório. |

**Revisão concreta recomendada:** o qreader de spec/05-security.md precisa distinguir saída de formato limitado, veracidade e autorização. Um resultado “approved=true” ou uma data falsa pode controlar uma ação sem conter instruções textuais. Preservar U/P e exigir política sobre o uso do resultado. Não existe motivo para antecipar o qreader da Fase 3; existe motivo para corrigir a promessa antes de implementá-lo.

IFC fino não é apenas acrescentar um campo ao JSON. Exige cobrir eventos, blobs, memória, resumos, hooks, modelos, proxies e efeitos. Um harness que calcula valores arbitrariamente pode omitir sua derivação. Sem mediação completa, descrever a solução como mitigação e manter o fallback conservador da sessão.

## Execução, efeitos e replay

| Trabalho primário | Contribuição e limite | Aplicação proposta |
|---|---|---|
| [Atomix](https://arxiv.org/html/2602.14849v2) | Separa execução, progresso por recurso e efetivação. Depende da classificação correta dos efeitos; exclui exactly-once completo após crash. | Começar, futuramente, com identidade de operação, versão esperada e execução serial por recurso; adapters revisados classificam efeitos. |
| [Cordon](https://arxiv.org/html/2606.17573v1) | Prepara alterações e efeitos, valida dependências/autoridade e só então libera. Cobertura restrita a operações mediadas e observáveis. | Workspace de preparação e preview consolidado; conectores com prepare/release explícitos. Ferramenta opaca não recebe garantia transacional. |
| [Chronicle](https://arxiv.org/pdf/2609.20625) | Replay seletivo fixa algumas fronteiras e reexecuta a que mudou. Avaliação pequena com modelos simulados; contagem por nome não captura toda divergência causal. | Fixtures sanitizadas de incidentes; verificar entradas e ordem causal. Provider/tools falsos, home descartável, nenhuma reemissão de efeito real. |
| [CodeAct](https://arxiv.org/html/2402.01030) | Código executável permite laços e composição; ganhos variam entre modelos/tarefas. Não é mecanismo de segurança. | Extensão executora e harness opcional; cada ferramenta aninhada passa por tools.call, sem credenciais ou acesso ao socket admin. |

[ACID for AI Agents](https://codex.danielvaughan.com/2026/09/08/acid-agent-semantic-transactions-agentic-reliability-codex-cli/) e [Cut-Point Replay](https://agentpatterns.ai/verification/cut-point-replay-agent-regression-tests/) são sínteses úteis, não evidência independente. O primeiro reúne ACID-Agent, Mnemosyne e MemTxn, cujos abstracts/identidades foram conferidos, sem revisão integral adicional. O segundo foi confrontado com Chronicle.

Contrato futuro de efeitos deve explicitar estados como preparado, liberado, confirmado e resultado desconhecido. Idempotência depende também do serviço externo. Após crash entre envio e resposta, repetir cegamente pode duplicar efeito; compensação é outra ação, não apagamento do passado. Hooks posteriores e Git não desfazem email enviado.

Replay de regressão pode começar nos testes existentes, sem antecipar o produto evals da Fase 2. O runner e fixtures ficam fora do kernel; Rust só precisa tornar verificáveis suas próprias fronteiras e registros. Histórico auditável não é automaticamente execução reproduzível.

## Contexto, memória e skills

| Trabalho primário | Contribuição e limite | Aplicação proposta |
|---|---|---|
| [ACON](https://arxiv.org/html/2510.00615) | Comprime observações e histórico separadamente; ajusta compressor usando falhas. Compressão continua sendo lossy. | Harness: limites distintos, fontes recuperáveis e avaliação do custo total. Cache e compressão resolvem problemas diferentes. |
| [ACE](https://arxiv.org/html/2510.04618) | Reflexão/curadoria aplica deltas a lições identificáveis, evitando reescrita monolítica. Depende da qualidade do refletor e pode acumular instruções nocivas. | Extensão com lições versionadas, origem, seleção e reversão; comparar com memória simples antes de adicionar agentes por turno. |
| [Zep](https://arxiv.org/html/2501.13956v1) | Memória temporal com episódios, fatos e recuperação híbrida. Extrações podem estar erradas; resultados são dos autores do produto. | Primeiro provenance, validade e supersession. Grafo/indexador é extensão, nunca banco especializado no core. |
| [Agent Workflow Memory](https://arxiv.org/html/2409.07429) | Extrai rotinas reutilizáveis; evidência concentrada em navegação web. | Receitas parametrizadas de execuções verificadas. Não reutilizar autorizações, destinatários e IDs históricos automaticamente. |
| [Dynamic Agent Skills](https://arxiv.org/html/2607.10113) | Survey, não algoritmo novo: aquisição, admissão, armazenamento, recuperação e manutenção. | Aproveitar pipeline existente; distinguir receita/instrução de código executável, mantendo controles de ambos. |
| [Library Drift](https://arxiv.org/html/2605.19576) | Crescimento da biblioteca pode piorar seleção; propõe evidência por skill e aposentadoria. Avaliação limitada a um benchmark/modelo. | Registrar uso/versão, permitir “nenhuma skill”, arquivar e reverter. Não copiar limites numéricos universais. |
| [CoEvoSkills](https://arxiv.org/html/2604.01687) | Gerador/verificador separados; há oracle oculto que devolve pass/fail. Não é aprendizado totalmente sem ground truth. | Laboratório isolado com testes externos congelados; resultado produz proposta, não promoção automática. |
| [Darwin Gödel Machine](https://arxiv.org/html/2505.22954) | Busca empírica entre variantes de agentes; custo elevado e risco de overfitting. Não constitui prova formal de melhoria. | Mod posterior para variantes de harness/tools, com linhagem e pipeline de revisão. Não altera kernel ou avaliador confiável. |

Separar quatro coisas: histórico bruto, resumo operacional, memória factual e procedimentos. Aprender algo de uma página não transforma essa informação em instrução humana. O ataque persistente mais importante é página maliciosa → resumo → “lição” → prompt privilegiado de outra sessão.

Envelope de origem/versão/escopo/validade é uma direção de projeto, não novo schema aprovado aqui. A marca d’água global já prevista preserva contaminação conservadoramente; uma extensão de memória não pode se declarar limpa após resumir.

## Seleção de ferramentas e modelos

| Trabalho primário | Contribuição e limite | Aplicação proposta |
|---|---|---|
| [Dynamic ReAct](https://arxiv.org/html/2509.20386v1) | Compara busca, seleção/carregamento e metatools. Catálogo proprietário e tradeoffs de chamadas, contexto e cache. | Índice do catálogo aprovado, seleção no harness/extensão. Começar com busca lexical; carregar schema não concede permissão. |
| [Dynamic Tool Dependency Retrieval](https://arxiv.org/html/2512.17052v3) | Seleciona próximas tools pela consulta e histórico, via grafo/clustering ou classificador. Requer trajetórias demonstrativas; benchmarks têm dependências relativamente curtas. | Não recuperar só semelhança textual: incluir pré-requisitos. Fallback quando o índice omite ferramenta necessária; invalidar por versão do catálogo. |
| [Past Performance Retrieval](https://aclanthology.org/2026.eacl-srw.22/) | Recupera desempenho passado de consultas semelhantes. Baseline kNN simples é competitivo; precisa de dados relevantes para os modelos candidatos. | Hook model.route com histórico local de evals; comparar primeiro contra modelo fixo e regras simples. |
| [R2-Router](https://proceedings.mlr.press/v306/xue26h.html) | Escolhe modelo e orçamento de comprimento de resposta. Resultados de benchmark não garantem economia no uso real. | Harness escolhe modelo/configuração permitidos. Pedido textual de resposta curta não é limite financeiro rígido. |
| [When Routing Collapses](https://arxiv.org/html/2602.03478) | Erros no ranking favorecem o modelo mais caro; propõe aprendizado orientado à decisão e métrica de escolhas dominadas. | Medir qualidade/custo e frequência por modelo; concentração isolada não prova colapso. Validar se havia opção mais barata suficiente. |

Rust não precisa conhecer tokens, formato de chat ou “dificuldade” da tarefa. O budget atual conta requisições; roteamento não o converte em teto monetário. Custos estimados no harness devem incluir entrada, saída, cache e chamadas auxiliares. Restrições de provider, privacidade e capacidades vêm antes da otimização de qualidade.

Para poucas tools, o catálogo fixo pode ser melhor. Para muitas, medir recall de ferramenta necessária, sucesso final, latência e custo — não apenas quantidade de schemas removidos. Enriquecimento de descrições por modelo é índice auxiliar não confiável, nunca substituição da definição aprovada.

## Ordem sugerida e experimentos

1. **M0.6:** resolver ARQ-032–034. Acrescentar casos de aprovação obsoleta, flags adquiridas durante espera, catálogo alterado e ferramentas com nomes semelhantes. Não ampliar agora a política para uma DSL.
2. **M0.8 / harness:** comparar compactação simples com compressão de observações + histórico. Medir sucesso, custo total, recuperação de detalhes e preservação de U/P; manter ADR-046.
3. **Testes próximos / produto Fase 2:** replay seletivo de incidentes com limites falsos. Verificar regressões de política sem depender do modelo repetir o ataque.
4. **Fases 1–2, quando os mecanismos correspondentes existirem:** memória por deltas, receitas verificadas, recuperação de tools e roteamento simples. Baselines sem memória/skill/router são obrigatórios para demonstrar ganho.
5. **Fase 3 ou posterior, sujeito a ADR:** revisar qreader; pilotar handles rotulados e políticas por argumento. Avaliar prepare/release e resultado desconhecido para conectores concretos antes de transações gerais.
6. **Mods experimentais posteriores:** CodeAct, CoEvoSkills e DGM, sempre com isolamento, testes independentes e promoção existente.

Critérios comuns: sucesso em tarefas próprias, custo e latência totais, intervenções humanas, regressão por versão e ataques persistidos entre sessões. Ganho publicado não é ganho demonstrado no Fictor. Nenhum benchmark foi reproduzido nesta análise.

## Auditoria das referências recebidas

Todos os 39 links foram considerados; links redundantes foram agrupados por trabalho. Falha de acesso pela ferramenta não prova inexistência da página.

- CaMeL: arXiv e Liner acessíveis; sotaverified inacessível. Base técnica: original.
- FIDES: ambos links alphaXiv falharam; recuperado original arXiv v2.
- PRUDENTIA: PDF identificado e HTML equivalente lido; título real indicado acima.
- Progent: arXiv e Liner acessíveis; Moonlight falhou.
- Design Patterns: Willison e Aktagon acessíveis; identificado original arXiv2506.08837.
- Ambos papers MCP: originais HTML acessíveis.
- Atomix: links ICLR/alphaXiv falharam; original arXiv v2 confirmado. Vínculo específico com a página ICLR não confirmado.
- Cordon: Emergent Mind acessível; original arXiv conferido.
- ACID: blog acessível; escopo de leitura dos trabalhos adicionais limitado como informado acima.
- Chronicle: PDF acessível; alphaXiv.md falhou. Cut-Point Replay acessível e confrontado com o original.
- ACON: Microsoft acessível e informa ICML 2026; link rotulado ICLR e awesomepapers falharam. Original arXiv lido.
- ACE: página ICLR falhou; original arXiv2510.04618 recuperado.
- Zep: Aktagon acessível; original é de janeiro de 2025, não julho de 2026.
- Agent Workflow Memory: ICML acessível; sotaverified falhou; original conferido.
- Dynamic Agent Skills: arXiv e Hugging Face acessíveis, mesmo survey.
- Library Drift: alphaXiv acessível; utilizado original arXiv, não AI Overview.
- EvoSkills: link resolve para título atual CoEvoSkills, v3 de 10/08/2026.
- Darwin Gödel Machine: DAIR acessível; original conferido.
- Dynamic ReAct e DTDR: HTMLs fornecidos acessíveis.
- CodeAct: Hugging Face e Beancount acessíveis; mecanismo confrontado com original de 2024.
- Past Performance Retrieval: ACL acessível com barra final.
- R2-Router: página ICML fornecida falhou; publicação confirmada nos proceedings PMLR v306.
- When Routing Collapses: arXiv acessível.

Foram lidos mecanismos, evidências e limitações relevantes dos originais recuperados; isso não significa leitura integral de todos os apêndices, revisão de código dos autores ou reprodução experimental. Reviews não foram contadas como confirmações independentes.
