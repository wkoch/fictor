# Harnesses: análise complementar dos papers

Data de consulta: 2026-10-20. Status: recomendações aceitas e registradas no [ADR-050](../spec/11-decisions.md#adr-050--admissão-de-respostas-e-evidência-de-execução-do-harness) e em [14-harness-reliability.md](../spec/14-harness-reliability.md). O restante preserva a análise anterior à decisão; o spec atualizado prevalece. Complementa a [análise anterior](agent-papers-analysis-2026-10-20.md) e compara com o [ADR-049 e plano aceito](../spec/13-agent-evolution.md). Nenhum benchmark foi reproduzido; nenhuma implementação foi auditada integralmente.

## Resultado para o Fictor

Não há justificativa nova para ampliar o kernel Rust. Os estudos reforçam loop pequeno, estado reconstruível, histórico preservado, interfaces de extensão e estratégias de qualidade fora da base de confiança. No Fictor, “harness” na literatura frequentemente abrange tanto nosso L1 quanto serviços L0/L2; não copiar essa terminologia como uma proposta de fundir camadas.

O delta mais útil é tornar cada execução explicável e cada melhoria comparável:

1. Identificar a configuração efetivamente usada, não apenas o nome do modelo.
2. Distinguir skills disponíveis, expostas no contexto e realmente carregadas.
3. Fechar o contrato de erro/streaming do adapter antes de admitir tools.
4. Melhorar observações das ferramentas e a evidência de conclusão.
5. Definir entregas verificáveis entre subagentes, com orçamento agregado.
6. Evoluir candidatos offline com diagnóstico, validação de seleção e teste final independente.

As propostas abaixo são inferências arquiteturais nossas. O aceite do ADR-049 não significa que novos eventos, formatos ou mudanças de protocolo deste relatório estejam aprovados.

## Estudos de arquitetura e surveys

| Trabalho | Contribuição e limites | Uso no Fictor |
|---|---|---|
| [The Empire, Long Divided, Must Unite — 2608.23953](https://arxiv.org/html/2608.23953) | Leitura de três harnesses encontra loop simples, registro de sessão, compatibilidade de modelos como dados, contexto progressivo e pontos de extensão. Casos pequenos, com difusão/reuso entre projetos; não prova arquitetura universal. Examina falhas de normalização e classificação de erros. | Já alinhado a I5/I6, adapters e skills sob demanda. Novidade: testes de fronteiras do adapter, configuração versionada e distinção entre registro operacional e prova verificável por terceiro. |
| [Harness Engineering: Anatomy… Eleven Systems — 2609.00006](https://arxiv.org/html/2609.00006) | Estudo de código, não benchmark comparativo. Organiza subsistemas e padrões; medidas de desempenho são de terceiros. Uma das bases analisadas vem de snapshot não oficial, reduzindo reprodutibilidade. Ausência de um framework no corpus não prova inutilidade universal. | Usar como checklist de responsabilidades. Não copiar recomendações de subagentes in-process ou segurança opcional: conflitam com as fronteiras do Fictor. Não remover tools estruturadas só por existir baseline bash. |
| [Agent Harness for LLM Agents: A Survey — v3](https://www.preprints.org/manuscript/202604.0428/v3) | Taxonomia de loop, tools, contexto, estado, hooks e avaliação. Mistura papers, documentação e blogs; versão explicitamente não revisada por pares. Completude de componentes não demonstra causalmente confiabilidade. | Conferir se cada responsabilidade tem dono e teste. Não criar seis subsistemas novos: o spec já distribui essas funções entre core, harness, SDK e evals. |
| [From Question Answering to Task Completion — 2606.20683](https://arxiv.org/html/2606.20683) | Survey de observação, contexto, controle, ação, estado e verificação/governança. Ressalta interação entre tarefa, modelo e runtime, sem demonstrar uma configuração única vencedora. | Avaliar conclusão de tarefas e seus artefatos, não somente a última resposta textual. Separar evidência funcional de decisão de autorização. |

A verificabilidade externa sugerida por Empire não é requisito imediato do runtime pessoal. Nosso append-only protege o histórico nos caminhos mediados; não equivale a prova criptográfica contra um host ou administrador comprometido. Hash chain/exportação assinada só justificariam trabalho após um requisito concreto de verificação externa e modelo de ameaça próprio.

## Implementação do harness, tools e skills

| Trabalho | Contribuição e limites | Uso no Fictor |
|---|---|---|
| [OpenHands Software Agent SDK — proceedings MLSys](https://proceedings.mlsys.org/paper_files/paper/2026/hash/8ae9cf363ea625161f885b798c1f1f78-Abstract-Conference.html) | Configuração imutável separada do estado, eventos, execução incremental e compactação como visão. Estudo operacional posterior inclui mudanças de infraestrutura juntas; redução de erros não isola cada mecanismo. O [arXiv v1](https://arxiv.org/html/2511.03690v1) é anterior e não contém todos esses resultados. | Configuração efetiva identificável, reconstrução testada e falhas do sistema separadas das falhas da tarefa. Não importar execução in-process, distribuição de segredos ou infraestrutura de containers como requisito. |
| [Code as Agent Harness — 2605.18747](https://arxiv.org/html/2605.18747) | Survey/posição sobre código como ação, controle e artefato de coordenação. Testes e execução dão feedback, mas não resolvem sincronização, segurança ou verificação incompleta. | Contratos de entrega com artefato, versão, checagens e evidência. Não é motivo para pôr interpretador no Rust nem dispensar instalação aprovada. |
| [Harnessing Agent Skills — 2606.20631](https://arxiv.org/html/2606.20631) | Arquitetura de referência e mapeamento documental de oito sistemas; não experimento de ganho causal. Propõe ativação progressiva e inventário de skills participantes por execução. Participação não comprova influência causal. | Registrar instalada/disponível/exposta/carregada/excluída, identidade/versão e motivo. Permissões continuam independentes da skill; carregá-la não concede autoridade. |
| [SWE-agent — 2405.15793v3](https://arxiv.org/html/2405.15793v3) | Interfaces de observação/ação, busca resumida e feedback de edição influenciam desempenho. Evidência em modelos e tarefas de 2024; tamanho ideal de janela não é constante universal. | Evoluir fs-tools: resultados delimitados, truncamento explícito, localização recuperável e erros acionáveis. Manter edição com correspondência inequívoca; não adicionar fuzzy matching silencioso para elevar sucesso. |
| [Natural-Language Agent Harnesses — PDF atual](https://arxiv.org/pdf/2603.25723) | Documentos orientam papéis, etapas, estado e recuperação, interpretados por runtime LLM. No PDF consultado, o baseline com o mesmo texto como prompt supera NLAH nas três linhas principais; componentes adicionais têm efeitos mistos e handoffs perdem informação. A [v1 fornecida](https://arxiv.org/html/2603.25723v1) tem outro conjunto experimental. | Mod de workflow textual é experimento, não substituto do kernel. Primeiro comparar com prompt simples. Persistir objetivos, restrições e evidências; testar completude das entregas entre agentes. |

O spec já tem leitura numerada, offset/limit, edição por trecho único, truncamento de bash e tools.call mediado. A melhoria proposta é a qualidade e rastreabilidade desses retornos, não substituir o catálogo inteiro.

## Medição e comparação

| Trabalho | Contribuição e limites | Uso no Fictor |
|---|---|---|
| [The Scaffold Effect — 2607.22585](https://arxiv.org/html/2607.22585) | Dois modelos, três harnesses e 50 tarefas; custo varia muito e diferenças de sucesso podem ficar dentro da incerteza. Limites de turnos e defaults não são perfeitamente equivalentes. | Comparar par harness–modelo, custo por tarefa resolvida, latência e falhas. Não adotar o multiplicador de custo publicado como promessa de economia. |
| [Stop Comparing… Without Disclosing the Harness — 2605.23950](https://arxiv.org/html/2605.23950) | Position paper com experimento cruzado; vários componentes variam juntos. Propõe divulgar dimensões de execução/contexto/tools/governança. Nem toda métrica proposta foi medida. | Ficha versionada por execução. Modelo fixo para comparar harness; harness fixo para comparar modelos; depois grade cruzada para identificar interação. |
| [Holistic Agent Leaderboard — 2510.11977](https://arxiv.org/html/2510.11977) | Infraestrutura separa agente, benchmark e avaliador e permite inspecionar trajetórias. Custo limitou repetições/intervalos de confiança em grande parte das avaliações. | Avaliador fora do alcance do candidato; análise de trajetórias além da nota. Usar eventos existentes, sem impor serviço cloud ou Docker. |
| [Baselines Before Architecture — 2607.13085](https://arxiv.org/html/2607.13085) | Estudo de pentesting, não coding genérico. Sistemas especializados publicados não foram rerodados; parte da comparação muda modelo e orçamento juntos. | Baseline simples comparável antes de arquitetura complexa. Separar primeira tentativa, união de sucessos entre tentativas e custo total. Não concluir que arquitetura ou segurança são dispensáveis. |

Os evals atuais já possuem baseline/candidata, trials, pass^k e métricas. Faltam detalhes suficientes para atribuir uma diferença à mudança pretendida e para contabilizar toda a infraestrutura auxiliar. Isso pede refinamento do contrato de evals, não renomear pass^k para pass@k: consistência em todas as tentativas e sucesso em ao menos uma tentativa são medidas distintas.

## Evolução automática e meta-harnesses

| Trabalho | Contribuição e limites | Uso no Fictor |
|---|---|---|
| [Meta-Harness — 2603.28052](https://arxiv.org/html/2603.28052) | Busca sobre candidatos com acesso a resultados/traces. Ablation em uma tarefa favorece trace original sobre só resumos; proponente forte e custo de busca limitam generalização. | Índice de diagnóstico com ligação ao trace original autorizado. Contabilizar geração e rejeição, não só custo do vencedor. |
| [Agentic Harness Engineering — 2604.25850](https://arxiv.org/html/2604.25850) | Componentes editáveis, corpus de observabilidade e manifesto de efeitos esperados. Previsão de regressões tem recall baixo no estudo; governança permanece incompleta. | Hipótese verificável por patch e avaliação específica de regressões. Explicação convincente do modelo não substitui experimento. |
| [Self-Harness — 2606.09498](https://arxiv.org/html/2606.09498) | Modelo fixo agrupa falhas e propõe mudanças pequenas. O conjunto chamado held-out é reutilizado na seleção; total de sucessos pode esconder tarefas que regrediram. | Três conjuntos: descoberta, validação de seleção, teste final intocado. Resultados por tarefa e revalidação de patches combinados. |
| [Live-SWE-agent — 2511.13646v3](https://arxiv.org/html/2511.13646v3) | Cria scripts auxiliares durante tarefas; a implementação estudada não modifica o loop básico. Persistência e evolução integral são objetivos mais amplos que o mecanismo demonstrado. | Distinguir script no workspace executado sob permissões existentes de nova extensão/catalogação. Reuso permanente segue pipeline; nenhum privilégio nasce da geração de código. |
| [Autogenesis — 2604.15034](https://arxiv.org/html/2604.15034) | Proposta, avaliação, publicação e adoção de recursos são separadas. Recuperação pressupõe mediação e cobre estado interno, não efeitos externos; avaliação não prova superioridade com custo equivalente. | Reaproveitar versões/journals existentes. Registrar versão efetivamente usada; adoção na próxima sessão é baseline mais simples que trocar harness em execução. Não importar protocolo paralelo. |
| [Automated Design of Agentic Systems — 2408.08435v2](https://arxiv.org/html/2408.08435v2) | Meta-agente gera código e mantém arquivo de candidatos. Avaliação é QA de passo único; interação complexa, custo e robustez permanecem extensões futuras. | Inspiração para busca offline, não prova de autoalteração segura de runtime persistente. |
| [The Last Harness You’ll Ever Build — 2604.21003](https://arxiv.org/html/2604.21003) | Formaliza ciclos de execução/avaliação/evolução e meta-evolução. Não apresenta resultados empíricos que demonstrem convergência universal. | Experimento posterior já coberto pelo ADR-049. Não justifica priorizar meta-evolução ou deixar o candidato alterar seu avaliador confiável. |

## Propostas concretas adicionais ao ADR-049

### A. Contrato de adapter e término — preparar para M0.8

O spec normaliza HMessage, captura respostas no proxy e prevê retries, mas não fecha toda a distinção entre resposta completa, stream interrompido e argumentos parciais. Proponho que o harness normalize causas tipadas: indisponibilidade/rate limit, limite de contexto, limite de saída, cancelamento, erro de protocolo e falha desconhecida. Isso fica no adapter, sem ensinar APIs de modelo ao Rust.

Antes de código, definir quais terminais admitem chamadas, o que acontece com tool_calls incompletos e qual retry é seguro após resposta parcial. Não reconstruir JSON para “consertar” argumentos truncados. Falha desconhecida não deve disparar compactação ou efeito. Testar provider falso com interrupção no meio de argumentos, chamadas duplicadas, erro após texto parcial, overflow real e erro de limite reformatado. Retry de modelo e retry de efeito são coisas diferentes.

### B. Ficha da execução e skills participantes — M0.8/Fase 2

Ficha reconstruível: versão/hash do harness, adapter, prompts/configuração efetiva, modelo/provider/parâmetros, catálogo, skills/hooks ativos, políticas de contexto/cache, budgets/retries, ambiente/fixture e verificador. Guardar referências/hashes quando apropriado, nunca valores de segredos.

Configuração pode mudar entre turnos; a ficha deve identificar o que realmente valeu naquele turno/chamada, não alegar snapshot único se o código relê config. Disponível, exposta e carregada são estados diferentes de skill. Uma skill carregada pode não ter sido útil; registrar participação não prova causalidade.

Começar no harness e artefatos dos testes. Se adotarmos eventos persistidos compartilhados, definir campos/versionamento em spec/03 antes de implementar. Um envelope extensível não dispensa contrato de dados.

### C. Observação e evidência de conclusão — M0.8

Resultados devem deixar claro sucesso, erro, conteúdo parcial/truncado e como recuperar a parte omitida por canais autorizados. Não confundir código de saída zero com satisfação da tarefa. O harness deve separar “concluído”, “interrompido”, “bloqueado por política” e “não verificado”, com evidência adequada à tarefa.

Evitar juiz extra obrigatório a cada turno. Usar primeiro verificações determinísticas existentes. Stop guards para ciclos repetidos ou ausência de progresso podem ser experimentados com limite finito; não prolongar turnos ilimitadamente até obter nota positiva.

### D. Contratos de handoff — Fase 2

Definir entrada e entrega: objetivo, restrições, versão dos artefatos, evidência esperada e motivo de término. Manter referência ao material original em vez de confiar só num resumo. Medir perda de informação e custo total dos filhos, sem reduzir a propagação de flags já prevista.

O resultado textual de sessions.complete não deve sozinho significar que um artefato foi verificado. Mudanças de payload persistido/wire exigem contrato; a análise não autoriza o implementador a inventá-las.

### E. Comparação justa e falhas classificadas — Fase 2

Manter modelo, conjunto de tarefas, permissões e orçamento comparáveis. Classificar falhas de provider, infraestrutura, protocolo, contexto, execução de tool, política e verificação. Um bloqueio correto de segurança não é defeito do kernel, mas ainda pode impedir a conclusão da tarefa: mostrar ambas as dimensões, sem excluir silenciosamente casos do denominador.

Registrar custo de compressor, roteador, verificador, retries e subagentes. Medir incerteza/repetição e custo por sucesso; observar que escolha de baseline pode alterar a conclusão. Testes oficiais continuam com provider falso/sem chaves reais; campanhas de qualidade com modelos reais precisam de autorização e orçamento separados, não viram teste de CI.

### F. Evolução offline com evidência — Fase 4+

Manifesto de hipótese por candidato: falha observada, evidência, mecanismo suspeito, componente alterado, resultado esperado, riscos e resultado medido. Estado de diagnóstico não vira instrução confiável nem declassifica dados.

Usar descoberta, validação de seleção e teste final independente; registrar regressões por tarefa e avaliar a composição dos patches. Publicar candidato não é adotá-lo. Começar com nova versão para novas sessões; mudanças durante sessão exigiriam regra explícita. Preserve o gate/pipeline do Fictor, sem criar autopromoção paralela.

## O que já está coberto e não deve ser duplicado

- I5/I6, eventos/blobs e compactação como projeção: reforçados por Empire/OpenHands.
- Cache e compatibilidade por adapter: ADR-046; falta apenas completar contratos de falha/capacidade.
- Skills sob demanda e ferramentas estruturadas: spec/07 já contém a base.
- Memória, seleção de tools, routing, replay e evolução isolada: ADR-049.
- Segurança no core e instalação pelo pipeline: não substituíveis por prompt, workflow textual, score ou verificador LLM.
- Agentes separados e sandbox obrigatório: não importar recomendações in-process/YOLO de outros produtos.

Não proponho novo framework obrigatório, reescrita do harness, banco semântico no Rust, cadeia criptográfica de eventos agora ou migração para OpenHands. A prioridade continua v0.1; refinamentos de contrato de M0.8 vêm antes dos laboratórios de evolução.

## Cobertura e versões das 31 referências

Todos os links foram considerados em 20 trabalhos/grupos. Usamos originais para mecanismos; resumos não são confirmações independentes. Falha da ferramenta não prova que a página inexiste.

| Links fornecidos | Leitura/resultado |
|---|---|
| Empire PDF + Takara | Original HTML equivalente lido; Takara inacessível. |
| Eleven Systems Emergent Mind + PDF | Emergent Mind e original HTML acessíveis. Estudo descritivo; não reproduzimos a auditoria de código. |
| OpenHands MLSys oral + proceedings + arXiv v1 | Oral bloqueado pela ferramenta; proceedings/PDF e v1 acessíveis. Versões têm estudos diferentes. |
| Survey Preprints v3 | Texto acessível; redireciona para página atual marcada v3. |
| From Question Answering PDF | Original HTML equivalente acessível. |
| Code as Agent Harness awesomepapers | Indexador acessível; original HTML usado. |
| Harnessing Agent Skills PDF | PDF/HTML originais acessíveis. |
| Scaffold Effect ICML | Link e alternativa poster inacessíveis; original identificado como 2607.22585. Vínculo com essa página de conferência não confirmado. |
| Stop Comparing alphaXiv | Acessível; original HTML conferido. |
| HAL ICLR | Acessível, identidade confirmada; original 2510.11977. |
| Baselines PDF | Identidade e HTML original conferidos. |
| SWE-agent hyper.ai | Inacessível; original arXiv v3 recuperado. |
| Meta-Harness papers.cool + PDF | Ficha acessível e original HTML equivalente v1 lido. |
| AHE alphaXiv + deeplearn + Moonlight + Vaughan | alphaXiv falhou; deeplearn ficha acessível; Moonlight extraiu só título/apresentação comercial; Vaughan acessível. Base técnica: original arXiv atual v4. |
| Self-Harness Buteau + Modelwire | Buteau acessível com www/barra final; Modelwire falhou. Original identificado: 2606.09498, v3. |
| Live-SWE abs + HTML v3 | Original v3 solicitado lido. |
| Autogenesis abs | Original atual HTML v6, de 08/10/2026, lido. |
| ADAS ICLR | Página falhou; original 2408.08435v2 identificado e lido. |
| Last Harness alphaXiv | Acessível; base técnica no original arXiv v3. |
| Natural-Language PDF + HTML v1 | Ambos acessíveis, revisões experimentais diferentes. Não combinar números da v1 com resultados do PDF atual. |

Leitura focada em mecanismos, avaliação e limitações, não em todos os apêndices ou no código de cada projeto. Algumas páginas têm metadados cronológicos inconsistentes; identidade/versão e data de consulta são mais úteis que inferir cronologia pelo snippet. Nenhum ganho publicado é promessa de resultado no Fictor.
