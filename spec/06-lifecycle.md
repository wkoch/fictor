# 06 — Ciclo de vida das extensões

Um único pipeline para todo código que entra no store: escrito pela IA, instalado de um caminho local ou importado da internet. Código escrito pela própria IA não é confiável por padrão, porque pode ter sido escrito sob influência de conteúdo injetado.

## Origens

| `source.kind` | Como chega | Fase |
|---|---|---|
| `local` | `fictor ext install <caminho>` ou `fictor init --first-party` | 0 |
| `ai` | Kernel `ext.propose` (tool `propose_extension` do harness) | 1 |
| `git` | `fictor ext add git <url> [--ref] [--subdir]` | 3 |
| `mcp` | `fictor ext add mcp <nome no MCP Registry \| npm:pkg \| pypi:pkg \| url>` | 3 |
| `skill` | `fictor ext add skill <url do repositório>[#subdir]` | 3 |
| `claude-plugin` | `fictor ext add claude-plugin <url>` | 3 |

## Estados da proposta

```text
received ──► checking ──► checked ──► approved ──► promoted
                 │            │
                 ▼            ▼
               failed      rejected
```

- `failed`: erro objetivo nas checagens (schema inválido, smoke test falhou, teste falhou). Pode ser reenviada como proposta nova.
- `rejected`: decisão humana.
- `approved` por `user` ou `auto:dev-profile`.

Toda transição grava evento `ext.*` na sessão `sys` e notifica o shell (`proposal.updated`).

## Etapas

### 1. Recebimento

- Criar `quarantine/<proposal_id>/` e gravar os arquivos. Rejeitar symlinks, caminhos absolutos, `..`, arquivos especiais e limites excedidos (IA: 500 arquivos e 5 MiB antes das dependências; total do bundle: 200 MiB).
- Origens remotas (Fase 3): o core resolve a referência para um SHA de commit (`git ls-remote`) ou versão exata de pacote e baixa nessa versão. O download roda num sandbox com rede só para o host de origem.
- Registrar a proposta (`proposals`), com `tainted = 1` se veio de sessão com U.

### 2. Normalização

- Se não houver `fictor.yaml` (origens externas), gerar o manifest pela tabela de [04-extensions.md](04-extensions.md#importação-de-formatos-externos-fase-3), com classificação restritiva.
- Validar o manifest contra [schemas/extension.schema.json](schemas/extension.schema.json) e as regras semânticas: templates válidos para o escopo, `role: harness` com `scope: session` e sem `hooks`, `hooks_api` presente quando há hooks, nomes de commands e surfaces únicos.
- Se já existe versão ativa com o mesmo `id`, a proposta é uma atualização (`update_of` = chave ativa).

### 3. Dependências

Roda num sandbox com escrita na quarentena e rede só para os registros em `[installer] registries` (default: `jsr.io`, `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`, `deno.land`).

| Runtime | Comando | Exigência |
|---|---|---|
| `deno` | `deno install` (vendor) | `deno.lock` gerado ou existente |
| `node` | `npm ci --ignore-scripts` | `package-lock.json` obrigatório |
| `python` | `uv pip install --target .pydeps -r requirements.lock` | lockfile com hashes (`uv export --format requirements-txt`) |

Scripts de instalação de pacotes nunca rodam. Ao final, gerar a lista de pacotes resolvidos `(ecossistema, nome, versão)`.

### 4. Hash

O hash do bundle cobre todos os arquivos, inclusive dependências vendorizadas:

```text
para cada arquivo regular, em ordem bytewise do caminho relativo (separador "/"), exceto .git/:
    linha = caminho + "\0" + modo + "\0" + hex(sha256(conteúdo)) + "\n"     # modo = "755" se executável, senão "644"
bundle_hash = "sha256:" + hex(sha256(concatenação das linhas))
chave_store = <version> + "-" + primeiros 12 hex do bundle_hash
```

### 5. Checagens determinísticas

| Checagem | Fase | Resultado |
|---|---|---|
| Schema e regras semânticas do manifest | 0 | bloqueia |
| Smoke test: subir no sandbox **sem rede** e com segredos substituídos por honeytokens; `initialize`, `tools/list`, `resources/list` em até 15 s | 0 | bloqueia |
| Hooks declarados têm tool `hook_*` correspondente; surfaces declaradas têm resource correspondente | 0 | bloqueia |
| Resumo de permissões | 0 | informativo |
| Diff de permissões contra a versão ativa (expansões destacadas) | 1 | informativo |
| Testes (`tests.command`) no sandbox com as permissões do manifest, sem rede, timeout 300 s | 1 | bloqueia |
| Varredura de padrões de risco: `eval`, `new Function`, `child_process`, `Deno.Command`, `subprocess`, `os.system`, `fetch`/`WebSocket` com URL literal, blobs base64 > 1 KiB, linhas > 1000 caracteres, caracteres bidi e de largura zero, comentários HTML em `SKILL.md` | 1 | informativo |
| Dependências novas (fora das já presentes em bundles ativos e de `[installer] trusted_packages`) | 1 | informativo; impede promoção automática |
| Vulnerabilidades conhecidas das dependências (OSV) | 3 | informativo; `critical` bloqueia |
| Segredos no código (formatos conhecidos de chave) | 3 | informativo |
| Capacidades inferidas × declaradas: hosts e caminhos literais no código fora de `net.allow`/`fs` | 3 | informativo |
| Execução comportamental com honeytokens e registro de tentativas de rede negadas | 3 | informativo |

O smoke test produz a lista de tools que será fixada no lock.

### 6. Auditoria por IA (Fase 3)

Extensão first-party `auditor` (global, sem rede, `models` configurados em `[ext.auditor]`, nenhuma outra tool). O instalador chama a tool `auditor__audit` com:

```ts
{
  manifest: object,
  files: { path: string; text: string }[],     // até 200 KiB por arquivo, 2 MiB por chamada (em lotes se maior)
  diff?: string,                               // diff unificado contra a versão ativa, em atualizações
  checks: object,                              // resultados das checagens determinísticas
  packages: { ecosystem: string; name: string; version: string }[]
}
```

O prompt do auditor trata todo o conteúdo como dado. Qualquer texto dirigido a uma IA dentro do código ou das skills é reportado como `prompt-injection-attempt`. Em atualizações, a revisão foca no diff. Para extensões com rede e segredos, rodar com dois modelos distintos e usar o maior risco.

Relatório (validado contra este schema e gravado em blob):

```json
{
  "risk": "low | medium | high | critical",
  "summary": "string",
  "capabilities_observed": {
    "network": ["host"], "filesystem": ["caminho"], "processes": ["comando"], "env": ["VAR"]
  },
  "undeclared_capabilities": ["string"],
  "findings": [
    {
      "severity": "info | low | medium | high | critical",
      "category": "exfiltration | obfuscation | prompt-injection-attempt | undeclared-network | dangerous-exec | vulnerable-dependency | secret | other",
      "file": "caminho",
      "line": 0,
      "evidence": "até 300 caracteres",
      "explanation": "string"
    }
  ],
  "recommendation": "approve | approve-with-restrictions | reject"
}
```

O relatório é sinal para o humano. Ele nunca aprova sozinho.

### 7. Evals (Fase 2)

Para propostas de `role: harness` e de extensões com hooks `context.assemble`, `model.route` ou `prompt.submit`, rodar os evals ([09-evals.md](09-evals.md)) contra a versão ativa. O gate reprovado impede promoção automática e aparece na revisão.

### 8. Decisão

Promoção automática (`auto:dev-profile`) só se **todas** as condições valerem:

- `source.kind` ∈ {`ai`, `local`};
- `source.kind = ai` ⇒ a proposta não está `tainted`;
- o manifest cabe no **perfil dev**:
  - `role: extension`, sem `hooks`;
  - `permissions.net.allow`, `models` e `secrets` vazios;
  - `fs.write` ⊆ {`${ext_data}`, subcaminhos de `${ext_data}`}; `fs.read` ⊆ {`${workspace}`, `${ext_data}`} e subcaminhos;
  - `kernel` ⊆ {`kv`, `ui`, `timers`, `blobs`}, mais `events.read` se `scope: session`;
  - `isolation: os`;
- nenhuma dependência nova;
- todas as checagens bloqueantes passaram.

Qualquer outro caso exige aprovação humana na tela de revisão ([08-shell.md](08-shell.md#gerenciador-de-extensões)) ou `fictor proposal approve`. Na revisão o humano PODE restringir permissões e ajustar a classificação de tools; os ajustes ficam em `overrides` no lock e o bundle não muda.

Origens `git`, `mcp`, `skill` e `claude-plugin` nunca são promovidas automaticamente.

### 9. Promoção

1. Copiar a quarentena para `store/<id>/<chave>/` e remover permissão de escrita (arquivos 0444/0555, diretórios 0555).
2. Atualizar o lock: gravar `lock.json.tmp`, fsync, rename.
3. Executar o hot swap ([02-core.md](02-core.md#troca-de-versão-hot-swap)).
4. Gravar `ext.promoted` e remover a quarentena.

## Lock

`extensions/lock.json` é a fonte de verdade das extensões ativas. Só o instalador escreve nele.

```json
{
  "schema": 1,
  "extensions": {
    "tdd-autopilot": {
      "enabled": true,
      "active": "0.3.1-1a2b3c4d5e6f",
      "versions": {
        "0.3.1-1a2b3c4d5e6f": {
          "version": "0.3.1",
          "hash": "sha256:…",
          "path": "store/tdd-autopilot/0.3.1-1a2b3c4d5e6f",
          "source": { "kind": "ai", "proposal_id": "01J…", "session_id": "01J…" },
          "approved": { "by": "auto:dev-profile", "at": "2026-10-17T18:00:00Z", "approval_id": null },
          "overrides": { "permissions": {}, "tools": {} },
          "privileges": [],
          "tools": [ { "name": "run_tests", "description": "…", "inputSchema": {} } ],
          "tools_hash": "sha256:…",
          "packages": [ { "ecosystem": "jsr", "name": "@std/path", "version": "1.0.8" } ],
          "audit": null
        }
      }
    }
  }
}
```

- `source` para origens remotas inclui `url`, `ref` pedido e `sha` resolvido (ou `package` e `version`).
- `privileges` só é editável por humano. Valor conhecido: `structured_output_trust` ([05-security.md](05-security.md#leitor-em-quarentena-fase-3)).

## Fixação das tools

`tools_hash` = sha256 da serialização JSON canônica (RFC 8785) da lista de tools devolvida por `tools/list`, ordenada por `name`, com os campos `name`, `title`, `description`, `inputSchema`, `outputSchema`, `annotations` e `_meta`.

A cada inicialização da extensão e a cada `notifications/tools/list_changed`, o core recalcula e compara. Divergência desativa a extensão ([02-core.md](02-core.md#conexão)). Isso bloqueia servidores que mudam descrições depois de aprovados.

## Atualizações (Fase 3)

- Timer interno do instalador, diário às 09:00 locais.
- `git`: listar tags (`git ls-remote --tags`) e propor a maior tag semver acima da ativa; com `track: branch`, propor o commit novo da branch.
- `mcp`/npm/PyPI: consultar a versão mais recente no registro.
- Cada novidade vira proposta com `update_of`. A auditoria recebe o diff. O shell mostra um contador de atualizações pendentes.
- Atualizações de terceiros nunca são promovidas automaticamente.

## Rollback, desativação e remoção

| Ação | Efeito |
|---|---|
| `fictor ext rollback <id> [--to <chave>]` / botão no gerenciador | `active` volta para a chave anterior (ou a indicada). Hot swap. Evento `ext.rolled_back`. |
| `fictor ext disable <id>` | `enabled: false`. Instâncias encerradas, tools somem, timers param. |
| `fictor ext remove <id>` | Sai do lock. Store e `data/<id>` ficam até `fictor gc` / `--purge-data`. |

As versões antigas ficam no store; `fictor gc` mantém as 5 mais recentes por extensão.
