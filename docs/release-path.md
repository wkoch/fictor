# Caminho até a v1.0

Atualizado em 2026-10-20, após a implementação e validação local do ADR-047 na `main`.
O **M0.5 tem implementação local concluída, com gates pendentes**, ainda antes do agente funcional
e autossuficiente da v0.1. O código já tem store, sandbox, proxies, segredos e
partes do supervisor, Kernel Protocol e instalador; conversa e interface web
ainda não estão disponíveis. Detalhes em [implementation.md](implementation.md).
O M0.6 começou com precedência de política, marcação U de workspace e proveniência;
integração e aprovações aguardam os contratos registrados em ARQ-032–034.

| Release | Escopo obrigatório | Critérios ativos no roadmap | Trabalho principal restante |
|---|---|---:|---|
| v0.1 | Fase 0 completa | 81 | Gates do M0.5; política/aprovações; servidor e shell; SDK, harness e tools; runtimes, atualização e rollback; aceitação e autossuficiência. |
| v0.2 | Fase 1 completa | 10 | Autoextensão, promoção controlada, hooks, surfaces, hot swap e estado global mediado. |
| v0.3 | Fase 2 completa | 4 | Evals, checkpoints/rewind, subagentes, árvore de sessões e demais entregas da fase. |
| v1.0 | Núcleo da Fase 3 | 5 | Origens de terceiros, normalização, MCP remoto, auditoria, atualizações acompanhadas e Landlock/seccomp. |
| **Total** | Fases 0–2 e núcleo da Fase 3 | **100** | Critérios normativos totais, com partes já implementadas ou testadas. |

Fonte: [roadmap](../spec/10-roadmap.md). A Fase 1 nº 8 foi movida para a Fase 0
nº 27 e não entra duas vezes. Os ADRs 036–048 ampliaram a Fase 0 de 37 para 81
critérios. A contagem não mede percentual concluído: os critérios têm tamanhos
diferentes e não enumeram cada item de implementação.

## Estimativa de progresso — 2026-10-18

Estimativa por esforço técnico total, com incerteza sobre as etapas ainda sem
implementação:

| Alvo | Progresso estimado | Esforço restante |
|---|---:|---:|
| v0.1 autossuficiente | 45–55% | 45–55% |
| v1.0 | 20–30% | 70–80% |

A base de confiança está avançada e o M0.5 tem fluxos locais integrados. Até a v0.1
ainda faltam política/aprovações, servidor/shell, SDK/harness/tools, runtimes,
atualizações/rollback e aceitação de autossuficiência. Até a v1.0 somam-se
autoextensão/surfaces/hooks, evals/checkpoints/subagentes e terceiros/auditoria/
Landlock/seccomp. A contagem de 100 critérios contém itens de tamanhos diferentes;
essas faixas são julgamento de engenharia. Uma data exige medir a cadência nas
próximas entregas e considerar os gates COSMIC/CI e decisões arquiteturais.

## Próxima sequência

1. Concluir os gates de aceitação do M0.5. ARQ-031 está resolvida e o ADR-047 implementado/testado com relógio falso e reinício. SIGKILL e boot real já têm provas para instâncias e promoção. Os fluxos dos
   [ADRs 036–042](../spec/11-decisions.md) estão integrados: promoção, aprovação,
   journal/barreira de instâncias, crash loop, listagem, controles protegidos e
   autoridades exatas. ARQ-020–026 estão resolvidas; falta concluir sua aceitação.
2. Concluir [ADR-043](../spec/11-decisions.md#adr-043--ids-limitados-e-respostas-correlacionadas-no-kernel-protocol-resolve-arq-027)
   (obrigações futuras do SDK; transporte do Kernel implementado) e [ADR-044](../spec/11-decisions.md#adr-044--destinos-internos-e-origens-de-montagens-do-sandbox-resolve-arq-028)
   (bootstrap protegido antes do init, com bases/bibliotecas na TCB instalada).
   ARQ-027/028 resolvidas; o gate dos critérios 57–65 continua pendente.
3. Concluir a aceitação do ADR-045, critérios 66–70: handlers, CLI e publicação já têm testes. Implementar o contrato da ARQ-030 (ADR-048) somente no M0.9. O marco de código atual é M0.6, com primitivas e testes dirigidos; as partes afetadas por ARQ-032–034 aguardam ADR. Seguir M0.6–M0.10: política e aprovações; servidor e shell; SDK/harness/tools;
   instalação autossuficiente; testes ponta a ponta e roteiro no COSMIC Atomic.
4. Após aceitar a Fase 0, entregar as Fases 1–2 e o núcleo da Fase 3, nessa ordem.

O próximo objetivo de uso é a **v0.1 autossuficiente**. O escopo da v1.0 inclui
as outras três etapas da tabela. Ainda não há data confiável em dias; as faixas de esforço acima serão revisadas conforme as entregas restantes forem medidas.

## Evidência e release

A base tem diagnóstico de **556 testes principais passando no Toolbx Fedora 44 sobre Bazzite**,
com dados falsos e endpoints locais; consulte [verification.md](verification.md).
Esse resultado não representa 556 critérios de produto aceitos.

Cada release ainda exige aceitação no Fedora COSMIC Atomic do usuário, CI
Ubuntu/Fedora, testes associados a I1–I11 e revisão dos riscos residuais. Os gates
no COSMIC e na CI remota continuam pendentes; o [mapa de invariantes](invariants.md)
registra as lacunas funcionais. O trabalho integrável segue diretamente na `main`,
conforme o [fluxo de Git](implementation.md#fluxo-de-git).
