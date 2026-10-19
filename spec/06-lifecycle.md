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
    │             │            │
    ▼             ▼            ▼
  failed        failed      rejected
```

- `received`: tentativa admitida e registrada; o recebimento ou a validação do manifest ainda pode estar incompleto.
- `failed`: erro objetivo no recebimento ou nas checagens, ou interrupção recuperada no boot. É terminal; reenviar cria uma proposta nova.
- `rejected`: decisão humana.
- `approved` por `user` ou `auto:dev-profile`.

Criação e toda transição gravam a proposta e o evento `ext.*` na sessão `sys` na mesma transação da task única de escrita. O shell é notificado (`proposal.updated`) somente depois do commit. Os payloads estão em [03-kernel-protocol.md](03-kernel-protocol.md#gravados-pelo-core).

### Identidade e persistência

[ADR-035](11-decisions.md#adr-035--propostas-duráveis-antes-da-identidade-resolve-arq-019). A tentativa é identificada pelo `proposal_id`, independentemente da identidade da extensão:

- `proposals.ext_id` e `proposals.version` são ambos `NULL` ou ambos preenchidos. Identidade ausente só é permitida em `received` e `failed`; strings vazias, nomes inventados e versões sentinela são proibidos. Nas representações JSON da proposta, ambos os campos são `null` quando ausentes.
- Ao admitir a tentativa, gerar o ULID e o nonce e persistir `source`, `tainted`, estado `received` e timestamps, junto com `ext.proposed`, **antes de abrir, percorrer ou copiar a origem**. `source.kind` vem do canal de entrada; `tainted` vem das flags da sessão, nunca do bundle. Antes da identidade, `manifest`, `hash`, `update_of`, `packages` e `audit_blob` ficam nulos.
- Ler e validar o manifest da cópia recebida. Somente depois da validação completa da etapa 2, vincular `ext_id`, `version`, `manifest` normalizado e `update_of` ao passar de `received` para `checking`, numa única transação. A identidade não pode ser substituída depois; alteração exige proposta nova. Registros legados já identificados em `received` mantêm a identidade.
- Sem identidade validada, não resolver dependências, executar código, pedir aprovação nem promover. Identificar a extensão não concede permissões nem dispensa as demais checagens.
- A migração [0003_proposal_receipts.sql](schemas/0003_proposal_receipts.sql) preserva todas as propostas existentes e o índice `proposals_state`. As migrações 0001/0002 e os eventos antigos não mudam. Backup e recusa de downgrade seguem [02-core.md](02-core.md#sqlite).

## Etapas

### 1. Recebimento

- Depois do registro durável, percorrer a origem de forma iterativa e copiar para um diretório novo e privado `quarantine/.receipt-<proposal_id>/`. Nunca reutilizar nem sobrescrever um destino existente.
- **Ignorados**: não são percorridos, não contam nos limites e aparecem na lista de ignorados da proposta. São eles `.git/` em qualquer nível, `__pycache__/` em qualquer nível e, na raiz do bundle, `node_modules/`, `vendor/`, `.pydeps/` e `.venv/`. Dependências sempre vêm da etapa 3.
- **Recusados** (proposta `failed`): symlinks; arquivos especiais; caminhos absolutos ou com `..`; nomes que não sejam UTF-8 válido ou que contenham caracteres de controle ou `\`.
- Diretórios vazios não entram no bundle.
- O percurso conta entradas e bytes enquanto avança e para no primeiro limite excedido ([Limites](#limites)). A ordenação para o hash só acontece depois, com o percurso já dentro dos limites; assim, memória e tempo ficam limitados pelos tetos.
- Origens remotas (Fase 3): o core resolve a referência para um SHA de commit (`git ls-remote`) ou versão exata de pacote e baixa nessa versão. O download roda num sandbox com rede só para o host de origem.
- Depois da cópia e da validação do manifest, renomear o temporário para `quarantine/<proposal_id>/`, sem sobrescrever outro destino, e sincronizar o diretório pai antes de gravar a transição para `checking`. A recuperação abaixo cobre a janela entre filesystem e banco.

#### Falhas antes da identidade

Persistir `failed` e `ext.failed` na mesma transação, mantendo os metadados da tentativa e os checks já obtidos. Acrescentar um check `{name, passed: false, blocking: true, detail: reason}`, com os códigos abaixo; `reason` também vai no evento. Parar no primeiro erro, sem continuar a leitura para tentar descobrir a identidade.

| Situação | `name` | `reason` |
|---|---|---|
| Teto excedido | `receipt` | Os códigos `limit:*` definidos em [Limites](#limites) |
| Symlink, arquivo especial ou caminho/nome proibido, inclusive colisão de nomes | `receipt` | `receipt:symlink`, `receipt:special_file` ou `receipt:invalid_path` |
| Origem mudou durante a cópia | `receipt` | `receipt:source_changed` |
| Origem inacessível, erro de leitura, cópia, rename ou sincronização | `receipt` | `receipt:io` |
| Manifest ausente | `manifest` | `manifest:missing` |
| Manifest não é UTF-8/YAML válido, tem duplicatas ou construção YAML proibida | `manifest` | `manifest:invalid_yaml` |
| Manifest viola schema ou regras semânticas | `manifest` | `manifest:invalid` (preservar `phase:global` no caso do ADR-025) |
| Tentativa interrompida, recuperada no boot | `recovery` | `recovery:interrupted` |

Os motivos são códigos do core. Não incluir caminhos absolutos, nomes inválidos, conteúdo de arquivos, YAML bruto, segredos nem mensagens arbitrárias de bibliotecas no check de falha ou no evento. A revisão mostra uma explicação produzida pelo core a partir do código. A CLI devolve o `proposal_id` junto do motivo depois do commit, inclusive quando não há identidade.

Depois do commit de `failed`, remover a cópia temporária e, se ainda não houver identidade, o destino `quarantine/<proposal_id>/` eventualmente criado pelo rename, seguindo as regras de limpeza abaixo. A limpeza dos bytes não apaga a proposta nem seus eventos.

Se a persistência inicial falhar, não iniciar o recebimento. Se a persistência de `failed` falhar, interromper o pipeline e reportar erro de persistência com o ID já alocado, sem afirmar que a falha foi auditada. O estado durável anterior será reconciliado no boot.

#### Recuperação de recebimentos

No boot, antes de admitir operações do instalador e sem outro worker ativo no mesmo `FICTOR_HOME`:

1. Propostas `received` ou `checking` deixadas pela execução anterior passam a `failed`, com o check e evento `recovery:interrupted`, mesmo se não houver diretório. Preservar identidade e checks existentes. Não retomar a leitura da origem nem executar novamente dependências ou smoke. Reenvio é uma tentativa nova.
2. Limpar `.receipt-<ULID>` após reconciliar a proposta correspondente. Limpar também `quarantine/<proposal_id>/` de propostas `failed` sem identidade, cobrindo a interrupção após o rename. Bundles de propostas identificadas que falharam ficam para revisão; `checked`, `approved`, `rejected` e `promoted` não são alteradas por esta recuperação.
3. Um `.receipt-<ULID>` sem proposta correspondente, inclusive de versão anterior a este ADR, é temporário órfão: limpar e emitir diagnóstico, sem inventar proposta, origem ou identidade a partir de seus bytes. Outros diretórios desconhecidos não são apagados por esta regra.

A limpeza atua somente nas entradas internas reconhecidas da quarentena, ancorada no diretório aberto pelo core, sem seguir symlinks nem atravessar pontos de montagem. Um symlink é removido como link, sem tocar o destino. Nunca remover a origem ou conteúdo do store. Falha de limpeza mantém o diagnóstico e permite nova tentativa no boot seguinte; não desfaz `failed`. Se a reconciliação no banco falhar, não admitir operações do instalador. Repetir a recuperação não duplica eventos de falha nem muda estados terminais. Nenhum processo sobrevivente pode usar os diretórios durante a limpeza; vale o encerramento confirmado do ADR-029.

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

#### Registros de dependências

`[installer].registries` define todos os destinos de rede permitidos ao processo
que resolve dependências. Os defaults continuam:
`["registry.npmjs.org", "pypi.org", "files.pythonhosted.org"]`.
A lista é configuração confiável do humano. Ela autoriza destinos; não escolhe
automaticamente o index/registry usado pelo gerenciador de pacotes.

| Forma | Exemplo | Autorização |
|---|---|---|
| Nome DNS público sem porta | registry.npmjs.org | somente CONNECT para esse nome na porta 443, com todos os IPs resolvidos públicos |
| Nome DNS e porta | registry.example:8443 | esse nome nessa porta, sujeito às regras normais de IPs do proxy |
| IPv4 e porta | 127.0.0.1:18080 | somente esse literal nessa porta |
| IPv6 entre colchetes e porta | [::1]:18080 | somente esse literal nessa porta |
| localhost e porta | localhost:18080 | somente esse nome nessa porta; não autoriza automaticamente os literais nem seus subdomínios |

- Nome DNS usa a gramática de domínio exato de net.allow; não há wildcard.
  Normalizar ASCII para minúsculas e retirar o ponto final antes de validar e
  comparar. Não inferir sufixos de domínio, apelidos ou equivalência com IP.
- Porta decimal entre 1 e 65535, normalizada sem zeros à esquerda; ausência de
  porta **permanece ausência**. Não converter `host` em `host:443`, pois isso
  ampliaria a permissão para HTTP simples e endereços não públicos.
- IPv6 segue a normalização e proibições de net.allow: colchetes e porta
  obrigatórios; negar zona de interface, IPv4 mapeado e representação NAT64
  proibida. Usar o IPv4 embutido quando a regra de net.allow assim exigir.
- `localhost` e nomes em `.localhost`, assim como literais IP, exigem porta
  explícita. Nome que só na resolução se revele não público continua negado sem
  porta explícita; a resolução pertence ao proxy.
- Rejeitar `*`, `*.example`, curingas parciais, CIDR, URLs com esquema, caminhos,
  credenciais, query, fragmento, whitespace e forma ambígua. Rejeitar
  `models.fictor.internal`: é uma rota interna reservada, não um registro.
- Duplicatas após normalização não ampliam a lista e podem ser eliminadas. Lista
  vazia é válida e não concede rede. Entrada inválida invalida a lista inteira;
  não descartá-la silenciosamente nem herdar os defaults.
- Validar a configuração ao carregá-la e conferir a lista efetiva antes de
  iniciar o processo de dependências. Nunca produzir uma allowlist parcial.

Valem integralmente a autenticação por instância, a resolução pelo core, a
validação dos IPs resolvidos e NAT64 e as regras de CONNECT/HTTP simples do
egress proxy. HTTP simples só é possível com host e porta explícitos; nenhuma
exceção de DNS ou loopback é implícita. Isso admite registros falsos HTTP locais
para testes, por exemplo `127.0.0.1:18080` com URL
`http://127.0.0.1:18080/`. A forma `localhost:18080` também é permitida
explicitamente; a restrição mais estreita de `providers.base_url` (ADR-022)
não é transplantada para esta allowlist.

Metadados de índices, tarballs/wheels, URLs no lockfile e redirecionamentos usam
a mesma fronteira. Cada nova conexão, inclusive a provocada por redirect, precisa
de autorização do proxy para seu destino exato. Host permitido não autoriza outro
host CDN; porta permitida não autoriza outra porta. Um redirect relativo ou para
destino já autorizado não exige ampliação. Um destino fora da lista é negado e
a tentativa de instalação falha quando depende dele; o core não segue fora do
proxy, tenta espelhos adicionais liberados automaticamente nem amplia regras
para tornar a instalação bem-sucedida.

A validação prévia de URLs conhecidas no lockfile pode antecipar o erro, mas não
substitui o proxy: metadados e redirects podem revelar outros destinos depois.
O proxy da Fase 0 continua sem MITM e não precisa interpretar Location dentro
do túnel TLS; a autorização é aplicada às conexões geradas pelo cliente.

O processo de dependências tem política própria derivada somente desta lista,
sem união com `permissions.net.allow` da candidata, providers ou proxies do
ambiente do host. Não recebe chaves de providers, credenciais do usuário ou
configuração global de npm/uv; `NO_PROXY` permanece vazio. Configuração do pacote
não pode remover o proxy, liberar rede direta ou ampliar a lista. Nenhum erro
autoriza desligar TLS, sandbox ou verificação de hash do lockfile.

O diagnóstico identifica o host/porta negados sem incluir URL completa,
userinfo, query, tokens ou headers. Uma sugestão de configuração é apenas texto:
o humano altera a lista e reenvia a instalação como tentativa nova. Não há retry com
permissões ampliadas dentro da mesma proposta. Os checks/eventos existentes
registram falha da etapa e `net.denied` conforme o proxy; este ADR não cria uma
nova tabela ou um novo tipo de evento.


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

Qualquer outro caso exige aprovação humana na tela de revisão ([08-shell.md](08-shell.md#gerenciador-de-extensões)) ou `fictor proposal approve`. Na revisão o humano PODE restringir permissões e ajustar a classificação de tools; os ajustes são validados e persistidos com a decisão, depois copiados para `overrides` no lock; o bundle não muda. O contrato completo está em [Overrides humanos](#overrides-humanos).

Origens `git`, `mcp`, `skill` e `claude-plugin` nunca são promovidas automaticamente.

Origem `builtin`: promovida automaticamente quando o hash do bundle confere com o registrado no próprio binário, porque tem a mesma confiança do binário que você instalou. As checagens bloqueantes, inclusive o smoke, continuam valendo.

### 9. Promoção

A promoção segue o [ADR-036](11-decisions.md#adr-036--promoção-recuperável-resolve-arq-020). Publicar bytes no store não ativa uma extensão. O compromisso lógico é a transação que grava `promoted`, `ext.promoted` e o journal `committed`, depois de tornar o lock durável; nenhum processo novo ou chamada nova usa a candidata antes desse compromisso.

#### Revisão e comparação da base

Ao passar a `checked`, o core fixa `review_base_hash = sha256(JCS(base))`, usando a serialização canônica já usada em `tools_hash`. `base` é `null` quando a extensão não existe no lock, ou `{active, enabled, version}`: `version` contém o registro completo da versão ativa no lock, inclusive overrides, tools e privilégios. Fixar `update_of` na mesma leitura: chave ativa ou `null` para instalação nova. Revalidar ambos na aprovação e antes de promover, sob a exclusão do instalador.

Base diferente, ou `review_base_hash` ausente em proposta legada `checked`/`approved`: recusar com `promotion:stale_base`, preservar estado e exigir proposta/revisão nova. Não substituir `update_of`, renovar aprovação, copiar overrides da versão ativa nem habilitar uma extensão desativada silenciosamente. A promoção preserva `enabled` numa atualização; a primeira instalação aprovada usa `enabled: true`.

Overrides humanos são persistidos na proposta junto da aprovação e depois ficam imutáveis ([Overrides humanos](#overrides-humanos)). Aprovação automática usa overrides vazios. A publicação usa o hash, manifest, catálogo, overrides e decisão fixados na proposta; nunca o conteúdo da origem original nem novos parâmetros de uma tentativa repetida.

Na Fase 0, uma promoção não substitui o registro de uma chave já aprovada em `versions`. Se a chave candidata já é ativa, recusar com `promotion:already_active`; isso não afeta a resposta idempotente de uma operação já `committed`. Para reativar uma chave inativa existente, hash integral, manifest, catálogo, overrides, privilégios e demais metadados executáveis devem coincidir com o registro anterior: conservam-se `source` e `approved` desse registro e a nova decisão fica na proposta/evento. Divergência é `promotion:key_conflict`, sem alterar o lock. Alterar overrides de uma chave já registrada exige incrementar a versão do manifest e submeter nova proposta; rollback nunca reinterpreta uma chave antiga. Os snapshots anterior/próximo de uma intenção válida são sempre distintos.

#### Journal e sequência

A migração [0004_promotion_journal.sql](schemas/0004_promotion_journal.sql) acrescenta `review_base_hash`, `overrides` e `promotion_intents`. Cada tentativa de promoção tem `operation_id` próprio. O writer usa `synchronous=FULL`, confirmado antes de abrir transações, conforme [02-core.md](02-core.md#sqlite): `NORMAL` não garante o journal depois de perda de energia. O journal guarda o texto UTF-8 exato do lock anterior (`null` se ausente), do próximo lock, seus hashes SHA-256 dos bytes e a proposta. Os snapshots são dados privados do core; não vão para eventos públicos. Não apagar nem reescrever o histórico de eventos ao reconciliar.

Todas as alterações de lock (incluindo runtime, rollback, enable/disable e comandos offline) usam a mesma seção crítica do instalador. Antes de alterar o lock, reconciliar qualquer intenção `prepared`; não admitir outra enquanto ela existir. A posse de `FICTOR_HOME` segue o ADR-038. A seção crítica cobre a leitura da base até o compromisso ou a interrupção segura.

1. Revalidar proposta `approved`, identidade, decisão e base. Montar o próximo lock preservando as demais entradas. Gravar journal `prepared` e `ext.promotion_prepared` na mesma transação do writer, antes da materialização desta tentativa. Estado da proposta continua `approved`.
2. Copiar da quarentena para staging privado, conferir hash integral, manifest e checagens aprovadas. Só bytes já verificados podem entrar no store. Publicar por rename sem sobrescrita em `store/<id>/<chave>/`, com arquivos 0444/0555, diretórios 0555 e fsync dos arquivos/diretórios e pais afetados. Destino existente só pode ser reutilizado se hash integral, manifest e imutabilidade forem idênticos; colisão do prefixo de 12 hex não autoriza reutilização.
3. Suspender novas admissões/spawns da extensão. Gravar os bytes exatos de `after_lock` em arquivo novo privado, fsync, rename para `lock.json` e fsync do pai. O temporário é `lock.json.tmp`; só o dono da seção crítica o manipula. Chamadas já admitidas na versão antiga podem terminar; o novo lock não autoriza despacho enquanto o journal estiver `prepared`.
4. Numa única transação, exigir journal `prepared` e proposta `approved`, mudar a proposta para `promoted`, gravar um único `ext.promoted` com `operation_id` e marcar o journal `committed`. Falha do commit mantém a extensão sem novas admissões e o journal recuperável; não alegar sucesso nem compensar o lock automaticamente.
5. Atualizar o registro em memória, executar hot swap e notificações, e só então liberar as admissões. Limpar a quarentena e os temporários conhecidos depois do compromisso. Falha de limpeza não desfaz promoção. Reinício restaura o catálogo pelo lock reconciliado; notificações são invalidadores e podem se repetir, mas o evento durável não.

#### Ordem durável das tentativas

O ADR-047 define a ordem de criação pelo `id` do evento `ext.promotion_prepared`
associado à intenção, nunca por `created_at`, `updated_at` ou relógio civil.
`operation_id` identifica a tentativa, mas seu formato/ordem não substitui a ordem
do evento, inclusive em dados legados. O evento de preparação e a intenção são
persistidos na mesma transação, conforme o passo 1; não há tentativa admitida sem
essa evidência. Os IDs de evento são ULIDs canônicos monotônicos do writer;
compará-los em ordem binária crescente, independentemente de locale.

Para consultar a última tentativa de uma proposta, ler proposta, intenções e seus
eventos num único snapshot SQLite. Para cada intenção deve existir exatamente um
evento `ext.promotion_prepared`, de actor `core` na sessão `sys`, cujo payload
identifica os mesmos `operation_id`, `proposal_id`, `ext_id`, `key`, `before_hash`
e `after_hash`. Validar o evento e os hashes/snapshots pelo contrato existente;
resolver payload em blob quando aplicável. A última é aquela com maior ID do
**evento de preparação**, não do evento de conclusão. Sem intenções nem eventos
de preparação associados, devolver `promotion: null`, inclusive para proposta
legada `promoted` anterior ao journal. Isso não inventa `operation_id` nem autoriza
repromovê-la: a CLI pode informar a promoção legada já concluída, e uma nova chamada
`promote` sem intenção confirmada retorna `invalid_state`. Eventos legados
`ext.promoted` sem `operation_id` não são eventos órfãos de uma tentativa journalada.

A mesma seleção validada serve a `ext.install.status` e à deduplicação/admissão de
`ext.install.promote`; não manter duas regras de ordenação. Todas as tentativas
anteriores da proposta devem estar `aborted`; somente a última pode estar
`prepared` ou `committed`. `prepared` exige proposta `approved`; `committed` exige
`promoted`; se todas estão `aborted`, a proposta permanece `approved`. Cada estado
terminal deve ter a evidência de conclusão do ADR-036, posterior à sua preparação;
a conclusão de uma tentativa anterior deve preceder a preparação da seguinte.
Continuam valendo a unicidade global de `prepared` e a proibição de reabrir tentativa
abortada ou criar nova tentativa depois do commit da mesma proposta.

Evento ausente, duplicado, órfão, divergente ou sequência incompatível é corrupção,
não critério para escolher uma tentativa alternativa. Não ocultar `prepared` ou
`committed` por um `aborted` selecionado incorretamente. No admin, retornar
`invalid_snapshot` sem nova mutação (`effect: none`); no caminho de recuperação,
reter recursos e recusar admissões com `promotion:recovery_conflict`. Não corrigir
por prioridade de estado, timestamps, ordem física/rowid ou heurística de ULID da
operação. Reconciliação de intenções continua obrigatória antes de outra mutação,
sem depender de qual proposta está sendo consultada.

O writer conserva a monotonicidade dos IDs de evento inclusive após regressão do
relógio e reinício: inicializar seu piso pelo maior ID de evento persistido, nunca
pelo evento de maior timestamp. Novo ID deve ser estritamente maior que esse piso
e que os IDs já emitidos nesta execução; overflow falha antes do commit. Lacunas
por transação abortada são permitidas. `created_at`/`updated_at` e timestamps dos
eventos continuam horários civis Unix ms observados; podem recuar e não são
ajustados para ordenar o histórico. Esta regra não altera os relógios de backoff
ou os contratos de crash recovery.

Aplicar a mesma leitura aos journals legados do ADR-036: eles já exigiam o evento
atômico de preparação. Não renumerar IDs, fazer UPDATE/DELETE em eventos, criar
preparação retroativa ou migrar timestamps. Legado sem evidência íntegra falha
explicitamente para intervenção humana. Não há novo campo de protocolo, tabela
ou migração; índices auxiliares são detalhe interno se preservarem esta semântica.

#### Reconciliação da promoção

No boot, antes de despachar extensões ou admitir mutações do lock, e depois de recuperar os registros de instância conforme ADR-038, preservando recursos cuja limpeza não foi autorizada, ler cada intenção `prepared`:

| Lock encontrado | Ação |
|---|---|
| Bytes exatamente iguais a `before_lock` (inclusive ausência) | Não houve compromisso. Marcar intenção `aborted` e gravar `ext.promotion_aborted` atomicamente, com `promotion:interrupted`; manter a proposta `approved`. Uma repetição explícita cria outra intenção e revalida a base. |
| Bytes exatamente iguais a `after_lock`, com bundle/catálogo/overrides íntegros | Sincronizar lock/pai e concluir a transação do passo 4 uma única vez. Não reexecutar smoke, dependências ou chamadas da extensão para recuperar. |
| Diferente de ambos, snapshots inválidos ou integridade não comprovada | Reter journal e recursos, recusar despachos/mutações com `promotion:recovery_conflict` e diagnosticar para intervenção humana. Nunca sobrescrever um lock desconhecido nem escolher uma versão por data. |

Repetir uma operação `committed` devolve o resultado já registrado, sem outra transição/evento; repetir uma `aborted` não a reabre. Uma tentativa com lock ainda anterior pode abortar por erro objetivo antes da publicação do lock, com `promotion:integrity` ou `promotion:io`. Se o resultado de rename/fsync for incerto, reler e aplicar a mesma tabela; não assumir que o rename falhou.

Staging novo usa nomes derivados da intenção: `quarantine/.promotion-<operation_id>/` e, se necessário para publicação no mesmo pai, `store/<id>/.promotion-<operation_id>/`. Limpar apenas temporários atribuídos à tentativa, sem seguir links ou atravessar mounts. Temporário de quarentena órfão reconhecido pode ser removido sob exclusão; entradas de staging no store e cópias finais sem referência ficam inativas, retidas e diagnosticadas até coleta/revisão, sem inventar aprovação, alterar modos ou apagar uma versão publicada. Isso também cobre materializações legadas sem journal. `lock.json.tmp` nunca é fonte de verdade: reconciliar pelo lock final e pelo journal antes de descartá-lo.

## Lock

`extensions/lock.json` é a fonte de verdade das extensões ativas depois de reconciliar o journal de promoção. Enquanto houver intenção `prepared`, o lock sozinho não autoriza ativação. Só o instalador escreve nele. A [listagem de configuração](02-core.md#listagem-de-extensões) coordena a leitura com o journal, recusa promoção pendente e não a reconcilia como efeito de uma consulta.

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

- `runtimes` segue o mesmo modelo: `active` aponta a chave em uso, e no mínimo as 3 últimas ficam em `versions`, além dos pins do ADR-048. Python usa chave com versão e build, conforme [contrato do M0.9](12-maintenance.md#runtimes-python-e-bootstrap). Novos registros incluem `tree_hash_kind: "runtime-v1"`; `tree_hash` segue a árvore tipada do [ADR-048](12-maintenance.md#runtimes-python-e-bootstrap), incluindo symlinks internos validados. Legado conserva o algoritmo anterior somente em árvores regulares. As versões do exemplo são ilustrativas.
- `source` para origens remotas inclui `url`, `ref` pedido e `sha` resolvido (ou `package` e `version`).
- `privileges` só é editável por humano. Valor conhecido: `structured_output_trust` ([05-security.md](05-security.md#leitor-em-quarentena-fase-3)).

`enabled` controla a habilitação administrativa da extensão inteira. O bloqueio de crash loop é separado, persiste no SQLite por extensão/chave/sessão e não é apagado por promoção, rollback ou enable/disable. Uma chave diferente tem contador próprio; reativar uma chave antiga conserva seu estado. `ext reset-crashes` limpa somente o estado selecionado, conforme [02-core.md](02-core.md#reabilitação-humana). Bloqueios por integridade ou mudança de tools conservam a exigência de nova proposta aprovada; reset de crashes não os remove.

## Overrides humanos

Schema: [overrides.schema.json](schemas/overrides.schema.json). O objeto pertence à versão aprovada e não
altera bytes/hash do bundle, lista MCP fixada ou tools_hash. Somente o humano pela
CLI/UI confiável pode fornecê-lo. Qualquer folha explícita de ajuste exige `approved.by = user`; objetos apenas estruturais vazios são no-op. Mesmo patch nominal vazio exige nome válido no catálogo fixado.
Promoção automática usa objeto vazio e avalia elegibilidade pelo manifest original.
Overrides da candidata, manifest ou MCP não têm autoridade. Não vazio significa ao menos uma folha explícita de ajuste; objetos estruturais vazios são no-op. Toda promoção automática grava a forma canônica vazia.

Escrita canônica sem ajustes: {"permissions": {}, "tools": {}}. Ausência de
overrides ou de uma das seções ao ler equivale ao objeto vazio, para compatibilidade
com locks existentes. Null em qualquer nível, duplicatas, campos desconhecidos,
tipos inválidos e coerção são proibidos. O schema de overrides não traz defaults;
nenhum leitor preenche um patch parcial com defaults.

| Campo | Ausente | Presente |
|---|---|---|
| permissions, fs, net | preservar folhas | processar somente folhas presentes |
| fs.read, fs.write, net.allow, models, secrets | preservar lista original | substituir lista inteira; [] remove entradas |
| spawn | preservar original (default false) | substituir booleano |
| env | preservar mapa original | substituir mapa inteiro; {} remove variáveis declaradas |
| tools | nenhum ajuste | aplicar patches abaixo |
| tools.default, tools.<nome> | nenhum patch nesse nível | aplicar somente campos presentes; {} é no-op |
| folha da classificação | preservar valor anterior | substituir, inclusive false |

Remover uma chave do patch restaura herança numa nova decisão humana; não é
tombstone. Não há deleção por null. Registro aprovado não se edita em lugar:
ajuste posterior exige nova versão do manifest e nova revisão vinculada aos bytes e ao catálogo, conforme a regra de chaves da promoção.

### Prova de restrição de permissões

Resolver defaults do manifest: listas/env ausentes vazios; spawn false. Aplicar
patch. O resultado DEVE validar todas as regras semânticas do manifest, incluindo
I11, env reservado, colisões env/segredos, escopo/templates e exigência de rede
não vazia e sem "*" quando houver segredo. Remover rede mantendo segredo é erro,
não remoção implícita de segredo.

Comparar com o manifest original, nunca com outra versão. A prova conservadora
compara regras normalizadas, sem inferir inclusão textual de árvores ou curingas:

| Folha efetiva | Condição |
|---|---|
| fs.write | subconjunto exato de fs.write original |
| fs.read | subconjunto exato de fs.read ∪ fs.write originais |
| net.allow | subconjunto exato das regras originais normalizadas |
| models | subconjunto exato das entradas originais |
| secrets | subconjunto exato de pares (name, env); sem repetição/remapeamento |
| env | cada par (nome, valor) deve existir idêntico no mapa original |
| spawn | true só se original true |

Write implica read, permitindo downgrade de uma entrada write para read. Listas
nunca se concatenam; ordem não tem efeito. Normalização é a mesma do manifest
(incluindo IPv6). Não aceitar caminho novo só porque parece descendente de outro,
troca por alias, domínio em lugar de wildcard ou provider em lugar de "*": todos
falham nessa prova de igualdade. Para esses grants diferentes, uma nova proposta
pode declarar o manifest correspondente. É limite deliberado da Fase 0: remoção
e downgrade dispensam álgebra nova de paths/curingas. Ampliar a prova exige ADR.

Bases implícitas do sandbox (bundle/runtime legíveis, ext_data/tmp da instância,
sockets mediados, regras fixas) permanecem. Retirar entrada redundante não revoga
essas bases; UI não deve afirmar que revoga. Overrides não mudam kernel, role,
scope, runtime, isolation, hooks, surfaces, privileges ou configuração global.
Canonicalização e bloqueios de caminhos sensíveis continuam obrigatórios no spawn.

### Classificação nominal e default

Para cada nome local t da lista MCP fixada:

1. Escolher objeto inteiro manifest.tools[t] se t não é "default" e ele existe;
   senão manifest.tools.default; senão {}. Objeto nominal não herda campos do
   default do manifest.
2. Completar ausentes: effect external, sensitivity private, output_trust
   untrusted, model_visible true, ui_callable false, timeout_ms 120000.
3. Aplicar campos presentes de overrides.tools.default a todas as tools,
   inclusive as nominalmente classificadas.
4. Aplicar campos presentes de overrides.tools[t] quando t != "default".
   Nominal vence o patch comum só nos campos que explicita.
5. Aplicar imposições normativas de 04/05: hooks sempre invisíveis; tool com rede
   não vira read por override; rede fora de trusted_domains, flag de workspace
   e marca d'água preservam sua proveniência. Flags existentes nunca apagam.

A classificação humana pode corrigir o default conservador, inclusive numa
direção menos conservadora, porque é a revisão já prevista pelo spec. Isso não
concede capacidade de SO nem substitui nenhum piso estrutural. Mudança precisa
constar da mesma aprovação dos bytes e catálogo revisados.

Chaves são nomes locais exatos, sem prefixo de extensão nem glob. Chave nominal
ausente na lista fixada é erro, inclusive typo ou patch nominal vazio {}. "default" é reservado ao patch
comum: uma tool MCP literalmente chamada "default" pode existir, mas recebe só
a classificação default e o patch comum. Não há patch nominal distinto para ela.
Nenhum patch cria/remove tool ou altera descrição, schema e annotations MCP.

Model_visible false retira de tools.list sem spawn; ui_callable false impede
chamada de surfaces. Ocultação do catálogo não é ACL de todas as chamadas por
nome: conserva o significado existente. Para negar a todas as origens, regra
policy deny ou desativação da extensão. Hooks seguem invisíveis por imposição.

Exemplo de precedência:
manifest.tools.default = {effect:"write_local", model_visible:false}
manifest.tools.read = {effect:"read"}
overrides.tools = {default:{model_visible:false}, read:{sensitivity:"public"}}
read termina read/public/untrusted/invisível/ui_callable false/120000.
other termina write_local/private/untrusted/invisível/ui_callable false/120000.
Sem override default, read seria visível, porque nominal não herda manifest.default.

### Persistência, validação e consumo

Gravar proposals.overrides na mesma transação da decisão, depois de validar schema,
subconjunto, nome e semântica. Após approved é imutável; somente nova versão e proposta/revisão
permitem outro objeto. A migração pode usar TEXT NOT NULL DEFAULT
'{"permissions":{},"tools":{}}'. O journal de promoção fixa em `after_lock` o objeto
aprovado. `review_base_hash` cobre registro ativo inclusive overrides, conforme
ADR-036; registros legados checked/approved sem base vinculada não promovem.

No boot e em toda ativação, resolver manifest verificado + catálogo fixado +
overrides aprovados como unidade. Supervisor/permissões de runtime, egress/model
proxy, registro/tools.list, tools.call, hooks e proveniência recebem o mesmo
resultado. Consumidores não refazem merge/default por conta própria. Modificadores
de sessão (trust de workspace, flags e marca d'água) agem sobre a mesma base.

Erro impede operação inteira antes de spawn/chamada; não se retorna catálogo
parcial nem classificação original como fallback. Diagnóstico não inclui valores
de env/segredos. Rollback obedece à mesma regra; ext_overrides de eval também quando
a Fase 2 chegar. Não há metade de snapshot velho com metade de novo.

Tools_hash compara as definições MCP originais, mesmo itens ocultos. Não incorpora
classificação ou filtragem do catálogo de modelo.


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
| `fictor ext enable <id>` | `enabled: true`; preserva bloqueios por crash/integridade. Não inicia processo por si só. |
| `fictor ext reset-crashes <id> [--key <chave>] [--session <session_id>]` | Limpa somente recuperação selecionada, com `ext.crash_reset`; preserva `enabled` e estado da extensão. |
| `fictor ext disable <id>` | `enabled: false`. Instâncias encerradas, tools somem, timers param. |
| `fictor ext remove <id>` | Sai do lock. Store e `data/<id>` ficam até `fictor gc` / `--purge-data`. |

As versões antigas ficam no store; `fictor gc` mantém as 5 mais recentes por extensão.


### CLI local online da Fase 0

O fluxo `ext install` usa [o contrato administrativo do ADR-045](02-core.md#mutações-administrativas-do-m05): receipt/checks, revisão completa com nonce/hash, decisão humana e pedido de promoção separados. A confirmação ocorre na CLI confiável, com retomada explícita por ID; não autoriza a CLI geral de propostas da Fase 1. Os estados, overrides, comparação de base e journal definidos acima continuam obrigatórios.


### Manutenção conjunta no M0.9

O [ADR-048](12-maintenance.md) acrescenta planos/journal de manutenção separados
de promotion_intents, sem propostas artificiais para runtimes/rollback. A exclusão
é conjunta; boot, listagens e mutações verificam ambos. O contrato de ordem durável
do ADR-047 usa a associação explícita do plano e seu prepared_event_id para
propostas de lote, sem exigir ext.promotion_prepared individual. Propostas ligadas
a plano não alternam entre os dois caminhos de publicação. Rollback passa pela
revisão e protocolo recuperável daquele documento, preservando enabled/dados/flags;
anterior tem origem no último snapshot confirmado, nunca na ordenação de versões.
