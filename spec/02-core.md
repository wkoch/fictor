# 02 — Core

O core tem os componentes abaixo. Política e aprovações estão em [05-security.md](05-security.md), o instalador em [06-lifecycle.md](06-lifecycle.md) e o servidor web em [08-shell.md](08-shell.md).

Meta de tamanho: 5–8 mil linhas de Rust, sem contar testes. Se passar disso, revisar o que deveria ser extensão.

## Supervisor

Responsável por subir, monitorar e encerrar processos de extensão.

### Identidade de instância

- `instance_id`: ULID gerado a cada spawn.
- Chave lógica: `(ext_id)` para `scope: global`; `(ext_id, session_id)` para `scope: session` e para o harness.

### Spawn

1. Resolver o bundle ativo no lock (`store/<id>/<key>/`).
2. Resolver as permissões do manifest em um `SandboxProfile` ([05-security.md](05-security.md#perfil-de-sandbox)), expandindo templates de caminho.
3. Gerar o token do proxy da instância e, se o manifest pedir escopos de kernel, criar `run/k/<instance_id>.sock` (0600) e um token de kernel. `__sandbox-init` expõe esse socket dentro do sandbox como TCP em `127.0.0.1:3129` ([05-security.md](05-security.md#linux-bubblewrap)).
4. Montar o ambiente do zero (nada herdado do usuário). Recusar o spawn se `permissions.env` ou `permissions.secrets[].env` usar nome reservado ([04-extensions.md](04-extensions.md#variáveis-de-ambiente-reservadas)); a validação principal ocorre no pipeline, esta é a segunda barreira.

| Variável | Valor |
|---|---|
| `PATH` | diretório do runtime ativo + `/usr/bin:/bin` |
| `HOME` | diretório temporário da instância (`${tmp}/home`) |
| `TMPDIR` | `${tmp}` |
| `LANG` | `C.UTF-8` |
| `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` e minúsculas | `http://fx:<proxy_token>@127.0.0.1:<porta>` |
| `NO_PROXY`, `no_proxy` | vazio |
| `NODE_USE_ENV_PROXY` | `1` |
| `FICTOR_EXT_ID`, `FICTOR_INSTANCE_ID` | identidade |
| `FICTOR_SESSION_ID`, `FICTOR_WORKSPACE` | só para instâncias de sessão |
| `FICTOR_KERNEL_URL`, `FICTOR_KERNEL_TOKEN` | só se houver escopos de kernel; URL `tcp://127.0.0.1:3129` |
| `FICTOR_MODELS_URL` | `http://models.fictor.internal/p` se `permissions.models` não for vazio |
| variáveis de `permissions.env` | valores estáticos do manifest |
| variáveis de `permissions.secrets` | ver [05-security.md](05-security.md#segredos) |

5. Montar a linha de comando do runtime ([04-extensions.md](04-extensions.md#runtimes)) e envolvê-la no bubblewrap.
6. Conectar stdin/stdout ao cliente MCP (se `mcp: true`). Stderr vai para `logs/ext/<ext_id>.log`, com rotação a 10 MiB.
7. Gravar o evento `ext.started` na sessão `sys`.

### Encerramento

1. Enviar a notificação `shutdown` pelo Kernel Protocol (se houver canal) e fechar o stdin.
2. Aguardar 3 s, revogar os tokens de proxy e de kernel e enviar SIGTERM à árvore da instância.
3. Aguardar 2 s e enviar SIGKILL à árvore.
4. Confirmar que a árvore está vazia. Só então liberar `${tmp}`, os sockets e o slot da instância.

A árvore da instância é o namespace de PID. Quando `__sandbox-init` (PID 1) morre, o kernel mata todos os processos do namespace, inclusive os que chamaram `setsid()`. A confirmação é a saída do `bwrap`.

Sem confirmação em 10 s: a instância fica `cleanup_failed`, o core grava `ext.cleanup_failed` na sessão `sys`, retém os recursos, mantém os tokens revogados e alerta no shell. Uma nova instância da mesma extensão pode subir, com identidade nova.

O mesmo procedimento roda quando o processo raiz sai sozinho (crash). Se o core morrer, `--die-with-parent` encerra os sandboxes; no boot seguinte, o core remove sockets e diretórios de instância que sobraram.

### Falhas

- Saída inesperada: grava `ext.crashed` (com as últimas 50 linhas de stderr em blob). Reinício com backoff de 1 s, 2 s, 4 s, 8 s, 16 s.
- Mais de 5 crashes em 60 s: a instância fica `disabled` até ação do usuário. Chamadas pendentes falham com `EXT_UNAVAILABLE`.
- Chamadas em andamento quando o processo morre falham com `EXT_UNAVAILABLE`. O core não repete chamadas automaticamente.

### Troca de versão (hot swap)

Ao promover uma versão nova:

1. As instâncias da versão antiga entram em `draining`: não recebem chamadas novas.
2. Chamadas novas vão para instâncias da versão nova, criadas sob demanda.
3. Instâncias em `draining` encerram quando não houver chamada em andamento, ou após 30 s.
4. O core envia `tools.changed` a todos os harnesses e `catalog.changed` ao shell.

## Runtimes

Os runtimes das extensões (Node LTS; uv e o Python que ele instala) são gerenciados pelo core e ficam em `$FICTOR_HOME/runtime/`. As versões são dados no lock; nenhuma versão é fixada no código do core ([ADR-032](11-decisions.md#adr-032--gerenciador-de-runtimes-e-fictor-update)).

### Fontes

Declaradas em `[runtimes.<nome>]` no config ([Configuração](#configuração)). Há dois tipos:

| `source` | Como acha a versão | Verificação |
|---|---|---|
| `nodejs` | Lê `https://nodejs.org/dist/index.json` e escolhe a maior versão do canal (`channel = "lts"`). Baixa `node-v<versão>-linux-x64.tar.xz`. | sha256 do arquivo contra o `SHASUMS256.txt` da mesma versão. (Fase 3) Também a assinatura do `SHASUMS256.txt` com as chaves de release do Node. |
| `github-release` | Última release que não é pré-release de `repo`. Baixa `asset`. | sha256 contra o arquivo `checksum` da mesma release. (Fase 3) Também a atestação Sigstore do GitHub, quando o projeto publicar. |

O core baixa só dos hosts da fonte: `nodejs.org`; ou `api.github.com`, `github.com` e o host de download indicado no redirect, desde que termine em `.githubusercontent.com`. Esse download é feito pelo próprio core, fora de sandbox.

### Instalação e ativação

1. Baixar para `runtime/.staging/<nome>-<versão>/` e conferir o checksum. Se falhar, descartar.
2. Extrair num sandbox sem rede com `fictor __extract`, gravando só em `runtime/.staging/`. São recusados symlinks que apontem para fora, caminhos absolutos e `..`. Formatos: `.tar.xz`, `.tar.gz` e `.zip`.
3. Rodar `<bin> --version` no ambiente de verificação e o smoke de cada extensão ativa que usa o runtime, já com a versão candidata ([06-lifecycle.md](06-lifecycle.md#ambiente-de-verificação)).
4. Aprovação humana, pela CLI ou pela UI confiável. A confirmação do `fictor init` vale para a primeira instalação.
5. Mover para `runtime/<nome>-<versão>/` (somente leitura), gravar no lock (seção `runtimes`, [06-lifecycle.md](06-lifecycle.md#lock)) e trocar como no hot swap: instâncias novas usam a versão nova, e as antigas terminam o que estão fazendo.
6. Manter as 3 últimas versões. `fictor runtime rollback <nome>` volta para a anterior.

Quando instalar:

- `node`: no `fictor init`, porque as extensões padrão precisam dele.
- `uv`: quando chega a primeira proposta com `runtime.kind: python`. O uv instala o Python na etapa de dependências, em `runtime/python/`, com rede só para os hosts de download do próprio uv.

Integridade: no boot, o core confere o sha256 do executável principal de cada runtime ativo contra o lock; `fictor doctor` confere a árvore inteira. Divergência desativa o runtime e gera alerta no shell.

### `fictor update`

1. Verificar:
   - cada runtime de `[runtimes.<nome>]`;
   - as extensões com origem atualizável: `builtin` cuja versão no binário mudou, `local` cujo caminho tem conteúdo novo, e `git`/`mcp` a partir da Fase 3;
   - a release mais nova do core em `[update] core_source`, só como aviso.
2. Preparar os candidatos: runtimes primeiro, depois extensões. As checagens das extensões rodam com os runtimes candidatos.
3. Mostrar uma revisão única, na CLI ou na página "Atualizações" do shell, com versão atual e nova, checagens e diffs de permissão.
4. "Aprovar tudo" (`--yes` na CLI) aplica só os itens que passaram em todas as checagens e não ampliam permissões. Os demais ficam para revisão individual.
5. Cada aplicação vira um lote, registrado no evento `update.batch` da sessão `sys`. `fictor update rollback <batch_id>` reverte todos os itens do lote.
6. Checagem automática conforme `[update] check`. Ela só avisa; nunca aplica.

`fictor update --core` existe só na CLI:

1. Baixa a release do core de `core_source` e confere o `SHA256SUMS` da release.
2. Grava o binário novo ao lado do executável atual, renomeia o atual para `fictor.prev` e põe o novo no lugar.
3. Você reinicia o serviço.

Nenhum caminho da UI web ou de um sandbox chega a esse comando.

## Store

### SQLite

- Arquivo `fictor.db`, `journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=5000`, `synchronous=NORMAL`.
- Migrações em `core/migrations/NNNN_nome.sql`, aplicadas no boot dentro de uma transação, controladas por `PRAGMA user_version`. A migração inicial é [schemas/0001_init.sql](schemas/0001_init.sql).
- Antes de aplicar qualquer migração, o core copia o banco para `fictor.db.bak-<user_version atual>` (API de backup do SQLite, 0600) e mantém as 3 cópias mais recentes. Migrações só avançam; não existe migração reversa.
- Se `user_version` for maior que a última migração que o binário conhece, o core não sobe e explica: um binário antigo nunca abre um banco de versão mais nova. Para voltar um binário, restaure também o backup correspondente.
- Escritas serializadas por uma única task (fila tokio). Leituras usam um pequeno pool de conexões somente leitura.

### Eventos

Campos e tipos estão na migração. Regras:

- `id` é ULID monotônico.
- `payload` é JSON inline até 64 KiB. Acima disso, o conteúdo vai para blob e `payload` guarda `{"$blob": "sha256:..."}`, com o hash também listado em `blob_refs`.
- `trust`, `sensitivity`, `source` e `flags` são calculados pelo core. Extensões não definem esses campos.
- `flags` é cumulativo: `flags = parent.flags | flags_do_evento`. Bit 0 = U (conteúdo não confiável), bit 1 = P (dado privado). Um evento acende U se `trust = untrusted` e P se `sensitivity = private`.
- `text` guarda o texto pesquisável de eventos com texto humano (`user.message`, `assistant.message`, `tool.result` textual até 32 KiB). Alimenta o FTS5.
- `UPDATE` e `DELETE` em `events` abortam (triggers na migração).

### Sessões

- Uma sessão é uma cadeia linear. `head_id` aponta para o último evento.
- `events.append` sem `parent_id` usa o `head_id` atual. Com `parent_id` diferente do head, falha com `HEAD_MOVED`. Ramificar exige fork.
- Fork em um evento E da sessão S cria a sessão S' com `parent_session_id = S` e `fork_event_id = E`. O primeiro evento de S' é `session.forked`, com `parent_id = E`. As flags de S' começam com `E.flags`.
- O caminho de uma sessão (raiz → head) atravessa as sessões ancestrais seguindo `parent_id`.
- A sessão reservada `sys` (`kind = system`) guarda eventos globais (ciclo de vida de extensões, rede, timers). É criada por `fictor init`.
- `kind` distingue sessões normais, delegadas (subagentes, Fase 2) e de eval (Fase 2). `ext_overrides` (JSON `{ext_id: chave do lock}`) faz o supervisor e o gateway usarem outra versão de uma extensão só naquela sessão; é usado apenas por evals.
- Ao criar sessão, o core valida `workspace`: diretório existente, caminho absoluto canônico, diferente de `/`, fora de `FICTOR_HOME` e sem conter `FICTOR_HOME`. Usar o `$HOME` inteiro exige confirmação explícita no shell.

### Blobs

- Endereço: `sha256:<hex>`. Arquivo em `blobs/<hex[0..2]>/<hex[2..]>`.
- Escrita: arquivo temporário no mesmo diretório, fsync, rename. Se já existir, não reescreve.
- Limite por blob: 256 MiB.
- Blobs guardam só bytes. MIME não é propriedade do blob: vem da referência (`Part.mime` nos eventos) ou, na entrega HTTP, da detecção por assinatura ([08-shell.md](08-shell.md#endpoints-http-do-shell)). O mesmo conteúdo enviado com MIMEs diferentes é um único blob, sem conflito.
- Coleta de lixo: `fictor gc` (Fase 2) remove blobs não referenciados por eventos, kv, propostas ou lock.

### KV

- Namespace: `ext_id` para instâncias globais; `ext_id@session_id` para instâncias de sessão, inclusive o harness. O core usa o namespace `core`. Estado compartilhado entre sessões só existe em extensões globais ([05-security.md](05-security.md#fluxo-entre-sessões)).
- Valor JSON até 1 MiB.

## Gateway MCP

O core é cliente MCP de cada extensão com `mcp: true`.

### Conexão

- Transporte stdio do MCP via `rmcp`.
- No `initialize`, o core anuncia a capability `roots` para instâncias de sessão (com o workspace como único root). Sampling e elicitation não são anunciados na Fase 0 (elicitation na Fase 2).
- Após `initialize`, o core chama `tools/list` e calcula o hash canônico das definições ([06-lifecycle.md](06-lifecycle.md#fixação-das-tools)). Se o hash diferir de `tools_hash` no lock, a extensão é desativada, o evento `ext.tools_changed` é gravado e o shell mostra o alerta. A extensão só volta após nova proposta aprovada.
- `notifications/tools/list_changed` em runtime dispara a mesma verificação.

### Registro de tools

- Nome exposto: `<ext_id>__<tool_name>` (dois underscores). IDs de extensão não contêm `_`, então a separação é inequívoca.
- Definições vêm do lock, não do processo vivo.
- Classificação de cada tool: `tools.<nome>` do manifest; senão `tools.default`; senão o default restritivo (`effect: external`, `sensitivity: private`, `output_trust: untrusted`, `model_visible: true`, `ui_callable: false`).
- Annotations MCP de terceiros (`readOnlyHint`, `openWorldHint` etc.) são só dicas para o revisor no pipeline. Não afetam a classificação em runtime.
- Tools com nome iniciado por `hook_` são hooks. Nunca aparecem em `tools.list` nem podem ser chamadas por `tools.call`.
- Tools com `model_visible: false` não aparecem em `tools.list`. Podem ser chamadas pelo shell (MCP Apps) se `ui_callable: true`.

### Execução de `tools.call`

1. Resolver a tool. Se inexistente ou a extensão estiver desativada: `NOT_FOUND` / `EXT_UNAVAILABLE`.
2. Validar `arguments` contra o `inputSchema` fixado. Falha: `INVALID_PARAMS`.
3. Decidir pela política ([05-security.md](05-security.md#decisão)). Se `ask`, criar a aprovação e aguardar. Se negar, gravar `tool.denied` e retornar `POLICY_DENIED` ou `APPROVAL_REJECTED`.
4. Gravar `tool.call`.
5. Garantir a instância e chamar `tools/call`. Timeout: `timeout_ms` da tool (default 120 s, máximo 600 s). Ao estourar, enviar `notifications/cancelled` e retornar `TIMEOUT`.
6. Gravar `tool.result` com `trust` e `sensitivity` derivados da classificação e das flags de rede da instância ([05-security.md](05-security.md#proveniência)).
7. Retornar ao chamador.

Cancelamento: `session.cancel` cancela as chamadas pendentes da sessão (MCP `notifications/cancelled`) e as aprovações pendentes.

### Fan-out de hooks

`hooks.invoke` ([03-kernel-protocol.md](03-kernel-protocol.md#hooks)) é executado aqui. O core não interpreta o significado dos hook points.

1. Selecionar as extensões ativas cujo manifest declara `hooks[].point == point`, ordenadas por `priority` (menor primeiro) e depois por `ext_id`.
2. Para cada uma, chamar a tool `hook_<point com "." trocado por "_">` com `{session_id, point, payload}`.
3. Modo `pipeline`: cada hook recebe o `payload` devolvido pelo anterior (se devolvido). Modo `collect`: todos recebem o payload original.
4. A resposta do hook é o `structuredContent` da tool: `{payload?: any, ...sinais}`. O core acumula `{ext_id, signals}` para cada hook.
5. Timeout por hook: `hooks[].timeout_ms` (default 2000 ms). Erro ou timeout: o hook é pulado, grava `hook.failed`. Três falhas seguidas na mesma sessão desativam aquele hook na sessão.
6. Hooks de extensões `scope: session` só rodam para a própria sessão.

## Egress proxy

Um único proxy HTTP no core.

### Escuta

- Unix socket `run/proxy.sock`. Dentro do sandbox, `__sandbox-init` escuta em `127.0.0.1:3128` e repassa para o socket montado em `/fx/proxy.sock`.

### Autenticação

- Toda requisição exige `Proxy-Authorization: Basic` com usuário `fx` e o token da instância. Token desconhecido: 407.
- O token identifica a instância (extensão, sessão).

### CONNECT (HTTPS)

- O destino `host:porta` é comparado com `permissions.net.allow` da extensão, na sintaxe de [04-extensions.md](04-extensions.md#sintaxe-de-netallow). Sem porta no padrão, só 443.
- Normalização antes da comparação: host em minúsculas e sem ponto final; IPv6 na forma canônica da RFC 5952; IPv4 mapeado (`::ffff:a.b.c.d`) avaliado como o IPv4 embutido; endereços NAT64 tratados conforme [NAT64](#nat64); destino com zona (`%iface`) é negado.
- `*` casa qualquer nome DNS na porta 443 cujos endereços resolvidos sejam todos públicos. Nunca casa IP literal, `localhost` nem destino não público.
- Destinos não públicos (loopback, não especificado, RFC 1918, CGNAT `100.64.0.0/10`, link-local, ULA `fc00::/7`, multicast, faixas de documentação), IP literais e `localhost` só são aceitos por regra com host exato e porta explícita. Vale também para um nome DNS que resolva para endereço não público.
- Negado: 403 e evento `net.denied` (agregado: um evento por par instância+domínio por minuto).
- Permitido: túnel TCP. O proxy não faz MITM na Fase 0.
- A resolução DNS é feita pelo core. No Linux o sandbox não tem DNS.

### NAT64

Um endereço NAT64 carrega um IPv4 que o gateway da rede vai acessar. Sempre que dá para identificar esse IPv4, o proxy avalia o IPv4, não o IPv6.

| Prefixo | Tratamento |
|---|---|
| `64:ff9b::/96` (bem conhecido, RFC 6052) | IPv4 extraído dos últimos 32 bits e avaliado como destino. |
| `64:ff9b:1::/48` (uso local, RFC 8215) | Destino não público como um todo: só por regra exata com porta. O IPv4 não é extraído, porque sua posição depende do prefixo que a rede escolheu. |
| Prefixos específicos da rede em `[egress] nat64_prefixes` | IPv4 extraído conforme a RFC 6052, seção 2.2, para o comprimento declarado (32, 40, 48, 56, 64 ou 96; o octeto `u`, bits 64–71, é ignorado) e avaliado como destino. Com prefixos sobrepostos, vale o mais longo. |
| Qualquer outro IPv6 | Classificado como IPv6. |

- `nat64_prefixes` só vem do config. O core não descobre prefixos sozinho: a descoberta (RFC 7050 via DNS, RFC 8781 via router advertisement) usa dados da rede que um atacante local pode forjar.
- Validação ao carregar o config: prefixo malformado, com bits de host diferentes de zero ou com comprimento fora da lista impede o core de subir.
- `fictor doctor` consulta o AAAA de `ipv4only.arpa` (RFC 7050, timeout de 2 s). Se a resposta embutir `192.0.0.170` ou `192.0.0.171` num prefixo que não é o bem conhecido nem está configurado, mostra o prefixo e a linha de config sugerida. Nunca aplica sozinho.
- Numa rede com prefixo específico não configurado, o IPv4 embutido não é avaliado. Risco residual em [05-security.md](05-security.md#riscos-residuais).

### HTTP simples

- `http://models.fictor.internal/...` vai para o model proxy.
- Outros destinos `http://` só se o padrão da allowlist incluir a porta (ex.: `127.0.0.1:11434` para Ollama).

### Proveniência de rede

- Instâncias de sessão (harness e `scope: session`) que conectam a um domínio fora de `policy.trusted_domains` acendem U na sessão: o core grava `session.tainted {flag: "U", reason: "net:<domínio>"}`.
- Hosts de providers de modelo configurados não contaminam.

## Model proxy

Rota: `http://models.fictor.internal/p/<provider_id>/<resto>` → `<base_url>/<resto>`.

O core não interpreta o corpo. Uso de tokens e custo são reportados pelo harness em `assistant.message`.

### Validação dos providers

Feita ao carregar a configuração. Erro impede o core de subir.

- `base_url` DEVE usar `https://`. Única exceção: `http://` com host IP de loopback literal (`127.0.0.1` ou `[::1]`), para Ollama, LiteLLM local e o provider falso dos testes.
- `http://` com `localhost`, IP de rede privada ou qualquer outro host é erro. Para um provider na rede local, usar HTTPS ou um túnel local.
- Nunca há downgrade de `https` para `http`. Certificado inválido falha; não existe opção para ignorá-lo.

### Admissão

Em ordem; a primeira falha encerra a requisição:

1. `provider_id` em `permissions.models` da extensão (ou `*`). Senão: 403 `{"error": "fictor_provider_not_allowed"}`.
2. Segredo do provider disponível (se houver `secret`). Senão: 503 `{"error": "fictor_secret_unavailable"}`.
3. Corpo da requisição lido até 64 MiB. Acima: 413 `{"error": "fictor_request_too_large"}`.
4. Reserva de orçamento ([Orçamento](#orçamento)). Excedido: 429.
5. Corpo da requisição gravado em blob. Falha: 503 `{"error": "fictor_capture_failed"}`. Nenhuma chamada sai para o provider sem a requisição gravada.
6. Remover cabeçalhos hop-by-hop e qualquer cabeçalho de credencial (`authorization`, `x-api-key`, `api-key`, `proxy-authorization` e o `auth_header` do provider); adicionar `<auth_header>: <auth_prefix><segredo>` e os `extra_headers`; repassar (rustls, raízes do sistema). Timeout de conexão: 30 s.

### Streaming e captura

- A resposta passa ao cliente em streaming, sem esperar o fim. Cada pedaço é escrito na captura **antes** de ser enviado ao cliente. Invariante: todo byte entregue à extensão está na captura.
- Limite de captura: 256 MiB. Ao atingir, o core encerra o stream do cliente e a conexão com o provider (`capture_limit`).
- Falha de escrita na captura: encerra os dois lados (`capture_failed`).
- Cliente desconecta: encerra a conexão com o provider (`client_cancelled`).
- Falha do provider (conexão, reset, 600 s sem bytes): encerra o stream do cliente (`upstream_error`).
- O provider termina a resposta normalmente, com qualquer status HTTP: `complete`.
- A captura vira blob com o hash do que foi capturado, inclusive quando parcial.

### Evento `model.call`

Gravado uma única vez, ao final, para toda requisição autenticada que chegou ao model proxy. Campos em [03-kernel-protocol.md](03-kernel-protocol.md#gravados-pelo-core). Vai para a sessão da instância, ou para `sys` em extensões globais.

- `resp_complete = true` só com `outcome = complete`.
- Requisições recusadas antes do passo 5 têm `req_blob = null`.
- Falha ao gravar o evento fecha o model proxy até o reinício do core, como no egress.
- Se o core cair no meio de um stream, não há evento. As extensões morrem junto (`--die-with-parent`), então nenhum conteúdo não registrado é usado. Capturas temporárias órfãs são apagadas no boot.

### Orçamento

- **Unidade:** requisição admitida, isto é, que passou pela reserva do passo 4. Contam todas, inclusive as que depois falham, são canceladas ou são retries. Recusas nos passos 1–3 não contam.
- **Escopos:** dia (global, todas as extensões) e sessão (vida inteira da sessão). Instâncias globais só consomem o limite do dia.
- **Dia:** data civil local, no fuso do sistema no momento da admissão (`YYYY-MM-DD`). Zera à meia-noite local.
- **Fonte de verdade:** tabela `budget_usage` ([schemas/0002_flow_budget.sql](schemas/0002_flow_budget.sql)). A reserva é um incremento condicional na task única de escrita: se o dia e a sessão estão abaixo dos limites, incrementa os dois na mesma transação e admite. Sobrevive a reinício. Não há devolução.
- **Excedido:** 429 com `{"error": "fictor_budget_exceeded", "scope": "day" | "session", "limit": <n>}`.

## Segredos

- **Backend explícito:** `[secrets] backend = "keyring"` (default) ou `"file"`. Nunca há fallback automático entre backends nem cópia de segredos do keyring para disco.
- **`keyring`:** crate `keyring` via Secret Service (D-Bus), serviço `fictor`, conta = nome do segredo. Se a sessão COSMIC não tiver um provedor de Secret Service ativo, usar `backend = "file"` ou instalar um provedor (ex.: `gnome-keyring`).
  - Backend ausente (por exemplo, sem Secret Service): `fictor doctor` e `fictor secrets` falham com mensagem que sugere `backend = "file"`.
  - Backend presente mas bloqueado, ou com erro transitório: a operação falha e pode ser repetida depois. O model proxy responde 503 `fictor_secret_unavailable`. O arquivo nunca é usado como alternativa.
- **`file`:** `$FICTOR_HOME/secrets.toml`, do próprio usuário, modo 0600. O core recusa ler se o dono for outro ou o modo for mais aberto. Formato:

  ```toml
  schema = 1

  [secrets]
  anthropic_api_key = "..."
  ```

  Nomes seguem `^[a-z0-9_]+$`; valores são strings não vazias. Escrita atômica: temporário 0600 no mesmo diretório, fsync, rename. Lido na inicialização e após `fictor secrets set|rm`. O conteúdo fica em texto puro (risco equivalente ao de `~/.aws/credentials`); `fictor doctor` avisa.
- **Troca de backend:** o usuário roda `fictor secrets set` no backend novo e `rm` no antigo. Sem migração automática.
- Entrada só pela CLI: `fictor secrets set <nome>` lê do TTY sem eco. Nunca pelo chat.
- Leitores: model proxy e supervisor (para segredos declarados em `permissions.secrets`).
- Logs: o layer de tracing DEVE substituir valores de segredos carregados por `***`.

## Timers

- `timers.set` grava em `timers` (migração). Uma task do core verifica a cada 15 s os timers vencidos.
- Ao vencer: sobe a extensão se necessário e envia `timer.fired`. Recalcula `next_at` para cron; remove se for `at_ms`.
- Cron: 5 campos, fuso local. Intervalo mínimo de 1 minuto.
- Timers de extensão desativada não disparam.

## Configuração

Arquivo `$FICTOR_HOME/config.toml`. `fictor init` grava exatamente o conteúdo abaixo; linhas comentadas ficam comentadas.

- O core lê o arquivo na inicialização. Mudanças nas seções do core exigem reinício.
- Seções `[ext.<id>]` são relidas do arquivo a cada `config.get`, para que extensões vejam mudanças sem reiniciar o core.

```toml
[server]
listen = "127.0.0.1:7350"        # shell (UI confiável)
surface_port = 7351              # surfaces servidas em http://localhost:7351

[paths]
default_workspace = "~/Projetos"

[runtimes.node]                  # ver #runtimes; a versão instalada fica no lock
source = "nodejs"
channel = "lts"

[runtimes.uv]
source = "github-release"
repo = "astral-sh/uv"
asset = "uv-x86_64-unknown-linux-gnu.tar.gz"
checksum = "uv-x86_64-unknown-linux-gnu.tar.gz.sha256"
bin = "uv-x86_64-unknown-linux-gnu/uv"

[update]
check = "weekly"                 # weekly | off; só avisa
core_source = "github:wkoch/fictor"

[providers.anthropic]
base_url = "https://api.anthropic.com"
auth_header = "x-api-key"
auth_prefix = ""
secret = "anthropic_api_key"

[providers.openai]
base_url = "https://api.openai.com"
auth_header = "authorization"
auth_prefix = "Bearer "
secret = "openai_api_key"

[providers.deepseek]
base_url = "https://api.deepseek.com"
auth_header = "authorization"
auth_prefix = "Bearer "
secret = "deepseek_api_key"

[providers.ollama]
base_url = "http://127.0.0.1:11434"   # sem secret

[policy]
default_mode = "default"         # plan | default | auto
trusted_domains = []             # domínios cujo conteúdo não acende U

# [[policy.rules]]               # opcional; ver 05-security.md#decisão
# tool = "fs-tools__*"
# decision = "allow"

[secrets]
backend = "keyring"              # keyring | file

[egress]
nat64_prefixes = []              # prefixos NAT64 específicos da rede, ex.: "2001:db8:64::/96"

[budget]
max_model_requests_per_day = 2000
max_model_requests_per_session = 300

[harness]
default = "harness"              # ext_id com role=harness
idle_timeout_min = 30

[sandbox]
home_ro_files = ["~/.gitconfig"] # arquivos do HOME real montados só leitura em instâncias de sessão

[installer]
registries = ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org"]
trusted_packages = ["npm:@modelcontextprotocol/sdk", "npm:zod"]   # não contam como dependência nova

[evals]                          # Fase 2
judge_model = "main"             # chave de [ext.harness.models]
max_call_ratio = 1.25

[ext.harness]                    # seção opaca: só a extensão "harness" lê via config.get
default_model = "main"           # chave de [ext.harness.models]

# Preencha antes da primeira conversa. Ver 07-harness.md#configuração.
# [ext.harness.models.main]
# provider = "anthropic"         # id em [providers]
# api = "anthropic"              # anthropic | openai-chat
# model = "<nome exato do modelo no provider>"
# context_window = 200000
# max_output_tokens = 16000
```

Seções `[ext.<id>]` são opacas para o core e só legíveis pela extensão `<id>`.

## CLI

Binário único `fictor`. Comandos que alteram estado com o servidor rodando falam com ele via `run/admin.sock`. Sem servidor, só funcionam `init`, `doctor`, `secrets`, `serve` e `ext rollback|enable|disable`; estes três editam o lock diretamente, para recuperar o sistema mesmo com o core parado.

| Comando | Fase | Função |
|---|---|---|
| `fictor init` | 0 | Cria `FICTOR_HOME`, config, banco e sessão `sys`. Instala o Node LTS e as extensões padrão embutidas (origem `builtin`), com uma confirmação. |
| `fictor doctor` | 0 | Verifica bubblewrap (versão mínima) e user namespaces, SELinux, integridade dos runtimes, keyring e portas. |
| `fictor serve [--open] [--shell-dir <dir>]` | 0 | Sobe o core e imprime a URL de login com token único. `--shell-dir` serve assets do disco (desenvolvimento). |
| `fictor secrets set\|list\|rm <nome>` | 0 | Gerencia segredos. `list` mostra só nomes. |
| `fictor login` | 0 | Pede ao core em execução uma URL de login nova, com token de uso único. Útil quando o core roda como serviço systemd de usuário. |
| `fictor ext list` | 0 | Extensões, versões ativas, estado. |
| `fictor ext install <caminho> [--yes]` | 0 | Proposta de origem `local`; mostra permissões e pede confirmação no TTY. |
| `fictor ext enable\|disable <id>` | 0 | Liga ou desliga no lock. |
| `fictor ext rollback <id> [--to <key>]` | 0 | Volta para a versão anterior (ou a indicada). |
| `fictor runtime list\|check\|update\|rollback [<nome>]` | 0 | Gerencia runtimes ([Runtimes](#runtimes)). |
| `fictor update [--yes] [--core]` | 0 | Verifica e aplica atualizações de runtimes e extensões; `--core` troca o binário do core. |
| `fictor update rollback <batch_id>` | 0 | Reverte um lote de atualizações. |
| `fictor ext remove <id> [--purge-data]` | 1 | Remove do lock; store e dados ficam até `gc`/`--purge-data`. |
| `fictor proposal list\|show\|approve\|reject <id>` | 1 | Revisão de propostas pela CLI. |
| `fictor ext add git\|mcp\|skill\|claude-plugin <ref>` | 3 | Importação de terceiros. |
| `fictor eval run <ext>[@<key>] [--baseline <key>]` | 2 | Roda evals. |
| `fictor gc` | 2 | Coleta blobs e versões antigas do store (mantém as 5 últimas por extensão). |
| `fictor __sandbox-init` | 0 | Interno: init do sandbox Linux. |
| `fictor __extract` | 0 | Interno: extração de arquivos de runtime dentro de sandbox. |
