# Caminho até a v1.0

Atualizado em 2026-10-18, após as entregas dos contratos do M0.5 na `main`
(`28981ed`). O projeto está no **M0.5 parcial**, ainda antes do agente funcional
e autossuficiente da v0.1. O código já tem store, sandbox, proxies, segredos e
partes do supervisor, Kernel Protocol e instalador; conversa e interface web
ainda não estão disponíveis. Detalhes em [implementation.md](implementation.md).

| Release | Escopo obrigatório | Critérios ativos no roadmap | Trabalho principal restante |
|---|---|---:|---|
| v0.1 | Fase 0 completa | 56 | Fechar M0.5; política/aprovações; servidor e shell; SDK, harness e tools; runtimes, atualização e rollback; aceitação e autossuficiência. |
| v0.2 | Fase 1 completa | 10 | Autoextensão, promoção controlada, hooks, surfaces, hot swap e estado global mediado. |
| v0.3 | Fase 2 completa | 4 | Evals, checkpoints/rewind, subagentes, árvore de sessões e demais entregas da fase. |
| v1.0 | Núcleo da Fase 3 | 5 | Origens de terceiros, normalização, MCP remoto, auditoria, atualizações acompanhadas e Landlock/seccomp. |
| **Total** | Fases 0–2 e núcleo da Fase 3 | **75** | Critérios normativos totais, com partes já implementadas ou testadas. |

Fonte: [roadmap](../spec/10-roadmap.md). A Fase 1 nº 8 foi movida para a Fase 0
nº 27 e não entra duas vezes. Os ADRs 036–042 ampliaram a Fase 0 de 37 para 56
critérios. A contagem não mede percentual concluído: os critérios têm tamanhos
diferentes e não enumeram cada item de implementação.

## Próxima sequência

1. Fechar os contratos dos [ADRs 036–042](../spec/11-decisions.md): promoção
   recuperável com aprovação persistida, posse/recuperação de instâncias, crash
   loop e listagem administrativa. Migrações/FULL, autoridades exatas, overrides
   efetivos e leitura protegida dos controles já têm entregas no produto; falta
   integrar os fluxos completos. ARQ-020–026 estão resolvidas no spec; o M0.5
   permanece parcial.
2. Resolver [ARQ-027](architect-pending.md#arq-027--correlação-de-ids-no-limite-de-mensagem-do-kernel-protocol)
   (IDs no limite de mensagem) e
   [ARQ-028](architect-pending.md#arq-028--grants-sobre-mounts-internos-e-fontes-de-pseudo-filesystems)
   (mounts internos e pseudo-filesystems). Essas partes aguardam ADR, conforme
   a regra 4 de [AGENTS.md](../AGENTS.md).
3. Seguir M0.6–M0.10: política e aprovações; servidor e shell; SDK/harness/tools;
   instalação autossuficiente; testes ponta a ponta e roteiro no COSMIC Atomic.
4. Após aceitar a Fase 0, entregar as Fases 1–2 e o núcleo da Fase 3, nessa ordem.

O próximo objetivo de uso é a **v0.1 autossuficiente**. O escopo da v1.0 inclui
as outras três etapas da tabela. Não há estimativa confiável em dias ou percentual
sem decompor e medir as entregas restantes.

## Evidência e release

A base tem diagnóstico de **369 testes passando no Toolbx Fedora 44 sobre Bazzite**,
com dados falsos e endpoints locais; consulte [verification.md](verification.md).
Esse resultado não representa 369 critérios de produto aceitos.

Cada release ainda exige aceitação no Fedora COSMIC Atomic do usuário, CI
Ubuntu/Fedora, testes associados a I1–I11 e revisão dos riscos residuais. Os gates
no COSMIC e na CI remota continuam pendentes; o [mapa de invariantes](invariants.md)
registra as lacunas funcionais. O trabalho integrável segue diretamente na `main`,
conforme o [fluxo de Git](implementation.md#fluxo-de-git).
