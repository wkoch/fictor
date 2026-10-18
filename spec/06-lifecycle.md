# 06 — Ciclo de vida das extensões

Um único pipeline para todo código que entra no store: escrito pela IA, instalado de um caminho local ou importado da internet. Código escrito pela própria IA não é confiável por padrão, porque pode ter sido escrito sob influência de conteúdo injetado.

## Origens

| `source.kind` | Como chega | Fase |
|---|---|---|
| `builtin` | Extensões padrão embutidas no binário (`harness`, `fs-tools`, `shell-net`), instaladas por `fictor init` e atualizadas por `fictor update` quando o binário traz versão nova | 0 |
| `local` | `fictor ext install <caminho>` | 0 |
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

- Percorrer a origem de forma iterativa e copiar para `quarantine/<proposal_id>/`.
- **Ignorados**: não são percorridos, não contam nos limites e aparecem na lista de ignorados da proposta. São eles `.git/` em qualquer nível, `__pycache__/` em qualquer nível e, na raiz do bundle, `node_modules/`, `vendor/`, `.pydeps/` e `.venv/`. Dependências sempre vêm da etapa 3.
- **Recusados** (proposta `failed`): symlinks; arquivos especiais; caminhos absolutos ou com `..`; nomes que não sejam UTF-8 válido ou que contenham caracteres de controle ou `\`.
- Diretórios vazios não entram no bundle.
- O percurso conta entradas e bytes enquanto avança e para no primeiro limite excedido ([Limites](#limites)). A ordenação para o hash só acontece depois, com o percurso já dentro dos limites; assim, memória e tempo ficam limitados pelos tetos.
- Origens remotas (Fase 3): o core resolve a referência para um SHA de commit (`git ls-remote`) ou versão exata de pacote e baixa nessa versão. O download roda num sandbox com rede só para o host de origem.
- Registrar a proposta (`proposals`), com `tainted = 1` se veio de sessão com U.

### 2. Normalização

- Se não houver `fictor.yaml` (origens externas), gerar o manifest pela tabela de [04-extensions.md](04-extensions.md#importação-de-formatos-externos-fase-3), com classificação restritiva.
- Validar o manifest contra [schemas/extension.schema.json](schemas/extension.schema.json) e as regras semânticas, todas bloqueantes:
  - templates válidos para o escopo e regras de escopo de kernel e de acesso a dados ([04-extensions.md](04-extensions.md#escopo-e-templates-de-caminho));
  - combinações de `runtime`, `mcp`, `role`, `scope`, `kernel`, `hooks`, `surfaces` e `tools` ([04-extensions.md](04-extensions.md#combinações-válidas)); `hooks_api` presente quando há hooks;
  - nenhum nome reservado em `permissions.env` ou `permissions.secrets[].env`, e nenhum nome repetido entre os dois ([04-extensions.md](04-extensions.md#variáveis-de-ambiente-reservadas));
  - `net.allow` válido semanticamente, com IPv6 normalizado ([04-extensions.md](04-extensions.md#sintaxe-de-netallow));
  - `secrets` não vazio exige `net.allow` não vazio e sem `*` ([05-security.md](05-security.md#segredos));
  - nomes de commands e surfaces únicos.
- Se já existe versão ativa com o mesmo `id`, a proposta é uma atualização (`update_of` = chave ativa).

### 3. Dependências

Roda num sandbox com escrita na quarentena e rede só para os registros em `[installer] registries` (default: `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`). Bundles que já trazem o código empacotado num único arquivo, sem `package.json` com dependências, pulam esta etapa.

| Runtime | Comando | Exigência |
|---|---|---|
| `node` | `npm ci --ignore-scripts` | `package-lock.json` obrigatório |
| `python` | `uv pip install --target .pydeps -r requirements.lock` | lockfile com hashes (`uv export --format requirements-txt`) |

Scripts de instalação de pacotes nunca rodam. Ao final, percorrer de novo o bundle com os limites de "bundle após dependências" e gerar a lista de pacotes resolvidos `(ecossistema, nome, versão)`.

### Limites

Constantes do core, não configuráveis. Mudar exige ADR.

| Momento | Entradas (arquivos + diretórios) | Bytes totais | Por arquivo | Profundidade | Caminho | Tempo |
|---|---|---|---|---|---|---|
| Recebimento, origem `ai` | 500 | 5 MiB | 5 MiB | 16 | 512 bytes | 30 s |
| Recebimento, demais origens | 5 000 | 50 MiB | 50 MiB | 32 | 1 024 bytes | 60 s |
| Bundle após dependências | 50 000 | 200 MiB | 100 MiB | 64 | 1 024 bytes | 600 s para resolver e percorrer |

- Profundidade = número de componentes do caminho relativo. Caminho = tamanho em bytes UTF-8 do caminho relativo.
- Excedido: proposta `failed` com motivo `limit:entries`, `limit:bytes`, `limit:file_size`, `limit:depth`, `limit:path_length` ou `limit:time`.
- Valem também para `ext.propose` (origem `ai`), antes de gravar qualquer arquivo.

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
| Smoke test no [ambiente de verificação](#ambiente-de-verificação): `initialize`, `tools/list`, `resources/list` em até 15 s | 0 | bloqueia |
| Hooks declarados têm tool `hook_*` correspondente; surfaces declaradas têm resource correspondente | 0 | bloqueia |
| Resumo de permissões | 0 | informativo |
| Diff de permissões contra a versão ativa (expansões destacadas) | 1 | informativo |
| Testes (`tests.command`) no ambiente de verificação, timeout 300 s | 1 | bloqueia |
| Varredura de padrões de risco: `eval`, `new Function`, `child_process`, `process.binding`, `subprocess`, `os.system`, `fetch`/`WebSocket` com URL literal, blobs base64 > 1 KiB, linhas > 1000 caracteres, caracteres bidi e de largura zero, comentários HTML em `SKILL.md` | 1 | informativo |
| Dependências novas (fora das já presentes em bundles ativos e de `[installer] trusted_packages`) | 1 | informativo; impede promoção automática |
| Vulnerabilidades conhecidas das dependências (OSV) | 3 | informativo; `critical` bloqueia |
| Segredos no código (formatos conhecidos de chave) | 3 | informativo |
| Capacidades inferidas × declaradas: hosts e caminhos literais no código fora de `net.allow`/`fs` | 3 | informativo |
| Execução comportamental no ambiente de verificação, com registro de tentativas de rede negadas e de honeytokens que apareçam em requisições | 3 | informativo |

O smoke test produz a lista de tools que será fixada no lock.

#### Ambiente de verificação

Código ainda não aprovado (smoke, testes, execução comportamental e evals de candidatas) nunca toca dados reais. Ele roda com o sandbox normal do manifest, com estas substituições:

| Recurso | No ambiente de verificação |
|---|---|
| `FICTOR_HOME` | Temporário próprio: config mínima, banco novo e store só com o bundle verificado. Apagado ao fim. |
| `${workspace}` | Diretório temporário vazio, ou cópia de `tests/fixtures/workspace/` do bundle, se existir. |
| `${ext_data}`, `${tmp}` | Temporários vazios. |
| `${store}` | O store temporário. |
| Caminhos absolutos e `~/` de `fs.read`/`fs.write` | Não concedidos: o caminho não existe no namespace. Não há substituição por dados sintéticos. |
| `sandbox.home_ro_files` | Não montados. |
| Rede | Nenhuma: o proxy nega tudo e registra as tentativas. |
| Model proxy | Nega tudo com 403 `{"error": "fictor_preapproval"}`. |
| Segredos | Honeytokens aleatórios. Um honeytoken numa requisição negada vira achado. |
| Kernel Protocol | Servido sobre o banco temporário. |

Regra para autores: `initialize`, `tools/list` e `resources/list` não podem depender de caminhos absolutos, rede, modelo ou segredos. O acesso a esses recursos acontece nas chamadas de tool. A tela de revisão lista os caminhos que não foram concedidos durante a verificação.

Evals de candidatas ([09-evals.md](09-evals.md)) seguem a mesma regra para caminhos absolutos e segredos. O acesso a modelos é a exceção, porque é o objeto da medição.

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

Origem `builtin`: promovida automaticamente quando o hash do bundle confere com o registrado no próprio binário, porque tem a mesma confiança do binário que você instalou. As checagens bloqueantes, inclusive o smoke, continuam valendo.

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
          "packages": [ { "ecosystem": "npm", "name": "zod", "version": "4.1.12" } ],
          "audit": null
        }
      }
    }
  },
  "runtimes": {
    "node": {
      "active": "24.11.0",
      "versions": {
        "24.11.0": {
          "path": "runtime/node-24.11.0",
          "archive_sha256": "sha256:…",
          "bin": "bin/node",
          "bin_sha256": "sha256:…",
          "tree_hash": "sha256:…",
          "source": { "kind": "nodejs", "channel": "lts", "url": "https://nodejs.org/dist/v24.11.0/node-v24.11.0-linux-x64.tar.xz" },
          "approved": { "by": "user", "at": "2026-10-18T12:00:00Z" }
        }
      }
    }
  }
}
```

- `runtimes` segue o mesmo modelo: `active` aponta a versão em uso, e as 3 últimas ficam em `versions`. `tree_hash` usa o algoritmo do hash de bundle aplicado ao diretório extraído. As versões do exemplo são ilustrativas.
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
