# 09 — Evals (Fase 2)

Objetivo: impedir que uma extensão nova (em especial harness e hooks de contexto) piore o agente. O benchmark principal é o histórico do próprio usuário.

## Conceitos

- **Caso**: uma tarefa com workspace inicial, entrada e checagens.
- **Trial**: uma execução de um caso. Modelos variam, então cada caso roda `k` vezes.
- **pass^k**: o caso passa nas `k` trials. Mede consistência, não sorte.
- **Baseline**: a versão ativa. **Candidata**: a versão proposta.

As execuções são re-execuções a partir da entrada, não replays determinísticos das respostas antigas.

Replay seletivo é uma evolução aceita pelo ADR-049: fixa fronteiras gravadas e reexecuta a que está sob teste. Fixtures internos de regressão podem ser usados desde a Fase 0, conforme [requisitos de isolamento e divergência](13-agent-evolution.md#replay-seletivo). A integração ao produto evals é posterior ao contrato de formato, captura e interface; não altera implicitamente `case.yaml`, a CLI ou as tabelas deste arquivo. Replay não substitui trials de qualidade com novas execuções.

## Onde ficam os casos

| Local | Origem |
|---|---|
| `<bundle>/evals/<case_id>/` | escritos junto com a extensão |
| `$FICTOR_HOME/evals/<case_id>/` | criados pelo usuário com "salvar sessão como eval" |

## Formato do caso

```text
<case_id>/
├── case.yaml
├── fixture.tar.zst      workspace inicial (opcional)
└── rubric.md            critérios para o juiz (opcional)
```

```yaml
id: fix-failing-test
description: Corrigir o teste que falha em src/parser.rs
input: "Os testes do parser estão falhando. Corrija."
fixture: fixture.tar.zst
model: sonnet                 # chave de [ext.harness.models]; default = default_model
trials: 3
budget:
  max_model_calls: 30
  max_seconds: 600
checks:
  - type: command             # roda no sandbox de fs-tools, no workspace final
    run: ["cargo", "test", "--offline"]
    expect_exit: 0
  - type: file_matches
    path: src/parser.rs
    regex: "fn parse_header"
  - type: file_absent
    path: src/parser_old.rs
  - type: tool_called         # verificado nos eventos da sessão
    name: fs-tools__edit_file
    min: 1
  - type: tool_not_called
    name: shell-net__bash_network
  - type: judge
    rubric: rubric.md
    min_score: 4              # escala 1–5
```

## Execução

`fictor eval run <ext_id>[@<chave>] [--baseline <chave>] [--cases <glob>]`. O pipeline de promoção usa o mesmo runner.

Para cada caso, versão (baseline e candidata) e trial:

1. Extrair `fixture` num diretório temporário novo, que vira o workspace.
2. Criar uma sessão `kind = eval`, modo `auto`, com `ext_overrides = {<ext_id>: <chave>}`.
3. Enviar `input` como `user.message` e esperar o harness ficar ocioso (turno terminado e fila vazia) ou o orçamento estourar.
4. Rodar as checagens. A trial passa se todas passarem.
5. Registrar o resultado e apagar o workspace temporário.

Regras das sessões `kind = eval`:

- Toda decisão `ask` vira `deny` com motivo "eval". Não há humano no loop.
- `ext_overrides` faz o supervisor e o gateway usarem a versão indicada só nessa sessão. Para extensões globais sobrescritas, o supervisor sobe uma instância separada, chaveada por `(ext_id, chave)`.
- Sessões de eval ficam arquivadas e fora da lista principal do shell.

### Juiz

Chamada de modelo (configurada em `[evals] judge_model`) com a rubrica, a entrada, o diff final do workspace e a última resposta do assistente. Saída JSON validada: `{score: 1..5, rationale: string}`. O juiz recebe o conteúdo como dado e não tem tools.

## Métricas

Por caso e versão: pass^k, taxa de trials aprovadas, média de chamadas ao modelo, média de duração e tokens. Aplicar [MetricsV1 e comparação justa](14-harness-reliability.md#avaliação-comparável-fase-2): incluir auxiliares, retries, juiz e descendentes; usage por tentativa sem somar novamente assistant.message. Ausência de medição não é zero.

O runner registra e verifica fixture/scorer/configuração efetiva; diferenças não declaradas ou medição incompleta tornam a comparação inconclusiva para promoção automática. O gate abaixo conserva os limiares e usa a contagem total definida no ADR-050. Bloqueio de política e falha funcional são dimensões distintas; nenhuma falha desaparece do denominador.

## Gate de promoção

Default, configurável em `[evals]`:

1. Sem regressão: todo caso com pass^k verdadeiro na baseline continua verdadeiro na candidata.
2. Taxa média de trials aprovadas da candidata ≥ a da baseline.
3. Média de chamadas ao modelo da candidata ≤ 1,25 × a da baseline.

Gate reprovado impede promoção automática e aparece na revisão. O humano pode aprovar mesmo assim.

## Salvar sessão como eval

Ação no shell sobre uma sessão:

1. `input` = primeira mensagem do usuário.
2. `fixture` = snapshot do workspace no início da sessão (exige a extensão `checkpoints`) ou um diretório indicado pelo usuário.
3. Checagens: o usuário escolhe entre as sugeridas (testes do projeto, arquivos alterados) e uma rubrica que o modelo rascunha e o usuário edita.

## Armazenamento (Fase 2)

O número definitivo da migração será o próximo livre ao implementar esta fase; 0003 já pertence aos receipts da Fase 0. MetricsV1 usa a coluna JSON abaixo, sem tabela nova. Histórico sem schema/metrics completos é legado incompleto, nunca atualizado para simular medição retroativa.

```sql
CREATE TABLE eval_runs (
  id          TEXT PRIMARY KEY,
  ext_id      TEXT NOT NULL,
  candidate   TEXT NOT NULL,          -- chave do lock
  baseline    TEXT,
  proposal_id TEXT REFERENCES proposals(id),
  status      TEXT NOT NULL CHECK (status IN ('running','passed','failed','error')),
  summary     TEXT,                   -- JSON com métricas agregadas e resultado do gate
  created_at  INTEGER NOT NULL,
  finished_at INTEGER
);

CREATE TABLE eval_results (
  run_id     TEXT NOT NULL REFERENCES eval_runs(id),
  case_id    TEXT NOT NULL,
  version    TEXT NOT NULL,           -- chave do lock
  trial      INTEGER NOT NULL,
  session_id TEXT REFERENCES sessions(id),
  passed     INTEGER NOT NULL,
  checks     TEXT NOT NULL,           -- JSON por checagem
  metrics    TEXT NOT NULL,           -- JSON MetricsV1 (ADR-050); legado permanece legível
  PRIMARY KEY (run_id, case_id, version, trial)
);
```

## Modo sombra (Fase 3)

Opcional por extensão. Por N dias, cada entrada real numa sessão também roda num fork `kind = eval` com a candidata e uma cópia do workspace. O juiz compara as respostas finais. O relatório agregado aparece na proposta.

## Benchmarks públicos

SWE-bench Verified, Terminal-Bench e similares servem só para checar a sanidade do harness. Não fazem parte do gate.
