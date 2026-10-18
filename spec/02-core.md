# 02 — Core

O core tem os componentes abaixo. Política e aprovações estão em [05-security.md](05-security.md), o instalador em [06-lifecycle.md](06-lifecycle.md) e o servidor web em [08-shell.md](08-shell.md).

Meta de tamanho: 5–8 mil linhas de Rust, sem contar testes. Se passar disso, revisar o que deveria ser extensão.

## Posse do diretório de dados

- Depois de criar o próprio diretório, se necessário, e antes de abrir o writer, migrar, recuperar, criar sockets ou iniciar processos, todo core/CLI que muta um home DEVE abrir o diretório canônico `FICTOR_HOME`, conferir que é diretório privado do usuário e adquirir flock exclusivo não bloqueante no seu inode. O descritor permanece aberto até o fim de todas as mutações e supervisão; é CLOEXEC, não é herdado pelos filhos e nunca é destravado antecipadamente.
- O diretório não é removido nem substituído enquanto existir um dono. Caminhos alternativos para o mesmo inode concorrem pelo mesmo lock. Não adquirir o lock impede mutações; uma CLI com core ativo encaminha a operação pelo socket admin. Não há fallback offline quando o core está ocupado ou inacessível.
- O core serializa suas próprias operações conflitantes de promoção/rollback/ativação e recupera journals antes de atender operações novas. O lock é posse, não evidência de que sandboxes do dono anterior terminaram. PID, idade de arquivo e existência/ausência de socket não substituem o lock.

A posse segue o [ADR-038](11-decisions.md#adr-038--posse-do-home-e-recuperação-de-instâncias-resolve-arq-022) e a semântica de descritores de [flock(2)](https://man7.org/linux/man-pages/man2/flock.2.html). Uma versão anterior que não implementa a posse global deve ser encerrada antes de usar a nova versão no mesmo home; PID files antigos não autorizam takeover.

## Supervisor

Responsável por subir, monitorar e encerrar processos de extensão.

### Identidade de instância

- `instance_id`: ULID gerado a cada spawn.
- Chave lógica: `(ext_id)` para `scope: global`; `(ext_id, session_id)` para `scope: session` e para o harness.

### Spawn

1. Resolver o bundle ativo no lock (`store/<id>/<key>/`), após reconciliar promoções pendentes, conferir integridade e consultar a recuperação de crashes. Nenhuma candidata é usada antes do compromisso do [ADR-036](06-lifecycle.md#9-promoção).
2. Derivar as permissões e a classificação efetivas aprovadas do manifest verificado, catálogo fixado e overrides aprovados ([ADR-037](06-lifecycle.md#overrides-humanos)). Supervisor, runtime, proxies, catálogo e política usam esse único resultado, sem outro merge ou default. Resolver seus caminhos em um `SandboxProfile` ([05-security.md](05-security.md#perfil-de-sandbox)). Escopos `kernel` permanecem os originais validados, pois overrides não os alteram.
3. Persistir `prepared` conforme [Registro e barreira de spawn](#registro-e-barreira-de-spawn). Gerar o token do proxy da instância e, se o manifest pedir escopos de kernel, criar `run/k/<instance_id>.sock` (0600) e um token de kernel. `__sandbox-init` expõe esse socket dentro do sandbox como TCP em `127.0.0.1:3129` ([05-security.md](05-security.md#linux-bubblewrap)).
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
| variáveis de `permissions.env` | valores estáticos do resultado efetivo aprovado |
| variáveis de `permissions.secrets` | ver [05-security.md](05-security.md#segredos) |

5. Montar a linha de comando do runtime ([04-extensions.md](04-extensions.md#runtimes)) e envolvê-la no bubblewrap, cumprindo a sequência `spawning` → `armed` e a barreira durável antes de liberar a extensão.
6. Conectar stdin/stdout ao cliente MCP (se `mcp: true`). Stderr vai para `logs/ext/<ext_id>.log`, com rotação a 10 MiB.
7. Gravar o evento `ext.started` na sessão `sys`.

### Registro e barreira de spawn

O namespace de PID permanece a unidade de contenção. O launcher DEVE usar `--as-pid-1` para que `__sandbox-init` seja efetivamente PID 1, além de `--die-with-parent` e `--unshare-all`. O init não executa a extensão antes da barreira abaixo.

Cada instância possui `run/instances/<instance_id>/`, 0700, criado exclusivamente pelo dono. O arquivo `state.json`, regular 0600, usa schema 1 ([ADR-038](11-decisions.md#adr-038--posse-do-home-e-recuperação-de-instâncias-resolve-arq-022)); o objeto e seus subobjetos têm exatamente os campos mostrados, todos obrigatórios. No exemplo, valores entre `<...>` representam tipos, não texto literal:

```json
{
  "schema": 1,
  "instance_id": "<ULID>",
  "ext_id": "<manifest.id>",
  "key": "<version-hash do bundle>",
  "session_id": null,
  "owner_id": "<ULID gerado por aquisição da posse>",
  "boot_id": "<UUID /proc/sys/kernel/random/boot_id>",
  "observer_pidns": { "dev": "<decimal u64>", "ino": "<decimal u64>" },
  "owner": { "pid": 123, "start_ticks": "<decimal u64>" },
  "state": "armed",
  "launcher": { "pid": 124, "start_ticks": "<decimal u64>" },
  "init": { "pid": 125, "start_ticks": "<decimal u64>" },
  "sandbox_pidns": { "dev": "<decimal u64>", "ino": "<decimal u64>" }
}
```

- ULIDs são válidos e `instance_id` coincide com o diretório; `ext_id` é um identificador válido de manifest; `key` é a chave válida `version-hash` do bundle, fixada desde `prepared`, inclusive no smoke. Não recuperá-la do lock atual: ele pode ter mudado ou a versão ainda não ter sido ativada. `session_id` é `null` para processo global e ID válido de sessão para harness e processo de sessão. PIDs são inteiros positivos no namespace observador; start_ticks é o campo 22 de /proc/<pid>/stat, sem conversão para relógio civil. dev/ino vêm de fstat dos descritores de namespace PID. Strings u64 são decimais canônicas sem sinal, zeros à esquerda ou overflow. observer_pidns identifica /proc/self/ns/pid.
- state admite apenas prepared, spawning e armed. prepared exige launcher/init/sandbox_pidns nulos. spawning admite launcher nulo ou completo, exige init/sandbox_pidns nulos. armed exige os três completos. Campos desconhecidos, schema desconhecido, forma inválida ou duplicação de chaves não são aceitos para recuperação automática.
- Caminhos descartáveis são derivados, não aceitos como caminhos livres do JSON: run/instances/<id>/tmp/ e run/k/<id>.sock. O tmp host é só a árvore auxiliar de preparação; o /tmp da carga continua privado no namespace. Estado, diretório pai, journal e lock não são montados na extensão. ext_data, workspace, bundles, logs, proxy.sock global e dados de outras instâncias nunca fazem parte desta limpeza.
- Atualizar state.json exige arquivo temporário 0600 no mesmo diretório, escrita completa, fsync do arquivo, rename e fsync do diretório. Criação do diretório e remoções também são sincronizadas nos pais. O arquivo anterior válido continua sendo a autoridade até a substituição durável; um temporário de atualização não é promovido implicitamente no boot.
- Ordem: (1) persistir prepared; (2) criar recursos derivados; (3) persistir spawning antes de criar qualquer filho; (4) iniciar bwrap e manter __sandbox-init bloqueado por canal privado do launcher; (5) obter identidades do launcher e do init no namespace observador, confirmar que init é PID 1 do namespace filho e abrir pidfds para ambos; (6) persistir armed com as identidades; (7) só então liberar a barreira para executar a extensão.
- O canal da barreira não é Kernel Protocol nem é herdado pelo workload. EOF, ausência de autorização, falha de persistência ou morte do dono fazem init abortar sem executar a extensão; a proteção --die-with-parent continua obrigatória. Mecanismo interno do canal fica a cargo da implementação.
- Nenhuma falha de spawn autoriza o destrutor de um temporário a apagar recursos antes da confirmação abaixo. Se prepared ainda é o último registro válido, a ordenação garante que nenhum filho chegou a ser criado; spawning cobre inclusive a janela entre fork e registro da identidade.
- O supervisor conserva pidfds do launcher e do init até confirmar término. O registro não guarda tokens, segredos nem o ambiente. Este journal não altera a migração SQLite.

### Encerramento

1. Enviar a notificação `shutdown` pelo Kernel Protocol (se houver canal) e fechar o stdin.
2. Aguardar 3 s, revogar os tokens de proxy e de kernel e enviar SIGTERM à árvore da instância.
3. Aguardar 2 s e enviar SIGKILL à árvore.
4. Confirmar que a árvore está vazia. Só então liberar `${tmp}`, os sockets e o slot da instância.

A árvore da instância é o namespace de PID. Quando `__sandbox-init` (PID 1) morre, o kernel mata todos os processos do namespace, inclusive os que chamaram `setsid()`. A confirmação exige a saída completa do PID 1 e do launcher, conforme [Confirmação e recuperação no boot](#confirmação-e-recuperação-no-boot).

Sem confirmação em 10 s: a instância fica `cleanup_failed`, o core grava `ext.cleanup_failed` na sessão `sys`, retém os recursos, mantém os tokens revogados e alerta no shell. Uma nova instância da mesma extensão pode subir, com identidade nova.

O mesmo procedimento roda quando o processo raiz sai sozinho (crash). Se o core morrer, `--die-with-parent` encerra os sandboxes. No boot seguinte, o core recupera os registros e só remove recursos cuja posse e término foram confirmados; desconhecidos e registros parciais seguem as regras de retenção abaixo.

### Confirmação e recuperação no boot

Em execução normal, sinais vão a processos presos por pidfd; o grupo POSIX é auxiliar, nunca a prova de ausência. São exigidos término do launcher **e** saída completa do PID 1, confirmados pelo pidfd de cada processo. A confirmação de saída do PID 1 ocorre após a eliminação dos demais processos do namespace; --die-with-parent, EOF, lock liberado ou launcher morto isoladamente não bastam.

1. Com a posse global adquirida, ler cada state.json por descritores ancorados em run/instances/, sem seguir links. Não reabrir nem retomar workloads do dono anterior. Um owner anterior com o mesmo boot, namespace observador e identidade PID/start_ticks comprovadamente vivo indica inconsistência de posse: recusar a recuperação mutante, conservar recursos e diagnosticar.
2. Registro prepared válido pode ter seus recursos derivados removidos: nenhum filho foi iniciado. Para outro estado, boot_id diferente do boot atual prova que nenhum processo daquela execução sobreviveu; a limpeza ainda exige registro válido e caminhos confinados.
3. No mesmo boot, observer_pidns DEVE coincidir com o atual. Mudança de namespace observador, /proc indisponível, permissão negada ou identidade ilegível são incerteza, nunca ausência.
4. Para armed, confirmar separadamente as identidades originais de launcher e init. Abrir /proc/<pid> uma vez e ler stat relativamente a esse descritor; para init, conferir também namespace e PID 1. Abrir pidfd, reler a identidade pelo mesmo descritor de /proc e só associar o pidfd ao registro se a revalidação for coerente. Mudança durante a aquisição descarta o pidfd e repete a observação, sem sinal.
5. Ausência comprovada daquele PID em /proc no namespace observador, ou presença de outro start_ticks, prova que o processo original terminou. PID reutilizado não recebe sinal e não passa a pertencer à instância. Ausência de um subarquivo, erro de leitura ou falha ao ler o namespace não equivalem à ausência do processo.
6. Se a identidade coincide e está viva, aguardar sua saída por pidfd por até 10 s no total. Na recuperação automática não são enviados sinais a processos redescobertos. Se init coincide mas seu namespace diverge, tratar como registro inconsistente e reter, sem inferir término.
7. spawning sem identidade completa não é limpo automaticamente no mesmo boot, mesmo quando o launcher não existe: um init ainda poderia estar finalizando. Conservar até um boot_id diferente; não procurar processos por nome, cmdline, grupos ou varredura heurística.
8. Só após ambas as identidades de armed estarem terminadas (ou regras 2/7 após reboot) remover o socket exato e a árvore descartável. Operar por descritores relativos, sem seguir symlinks nem atravessar pontos de montagem; validar tipo/posse de cada raiz. Apagar state.json e seu diretório por último. Ausência já produzida por tentativa anterior é sucesso idempotente.
9. Falha de confirmação ou de limpeza retém o registro e os recursos restantes, revoga/não recria tokens, para registro válido gera `ext.cleanup_failed` em `sys` com a identidade e chave persistidas, além de diagnóstico; nunca reporta limpeza concluída. O próximo boot tenta novamente. Outra instância usa outro ULID e recursos novos.
10. PID files legados, temporários antigos em /tmp/fictor, diretórios sem registro, registros malformados e schemas desconhecidos são preservados e reportados para inspeção. Não são sinalizados nem apagados automaticamente, mesmo após reboot, pois sua posse não está demonstrada. Não inventar registros a partir deles. Sem identidade válida, emitir diagnóstico confiável sem evento que invente extensão, chave ou instância.

O [pidfd permite acompanhar a saída](https://man7.org/linux/man-pages/man2/pidfd_open.2.html); um [descritor aberto de /proc não passa a representar outro processo](https://www.kernel.org/doc/html/latest/filesystems/proc.html) quando o PID é reutilizado. O [kernel encerra os processos do namespace antes de notificar a saída de seu init](https://github.com/torvalds/linux/blob/master/kernel/exit.c); o fechamento de arquivos ocorre antes dessa etapa. Por isso, nenhum lock ou pipe fechado substitui a confirmação do PID 1.

### Falhas

A recuperação pertence a `(ext_id, key, session_id)`: `key` é a chave completa
`version-hash` do lock; `session_id` é nulo para `scope: global` e obrigatório
para `scope: session` e harness. Ela independe de `instance_id`, que muda a cada
spawn. Uma sessão, versão ou extensão não compartilha contador com outra. O
contrato não habilita processos globais na Fase 0 (ADR-025).

- Conta como crash uma saída inesperada de processo de extensão ativo, inclusive
  exit code 0, observada pelo supervisor. Paradas solicitadas pelo core por idle,
  arquivamento, disable, hot swap ou encerramento do serviço não contam. Falhas
  antes de criar processo e processos de smoke não contam. A morte do core não
  autoriza inferir que os processos interrompidos tenham causado crash; a
  recuperação de recursos segue o ADR-038.
- Para um crash observado em `t`, remover amostras com `at_ms <= t - 60000` e
  adicionar a amostra corrente. As primeiras cinco amostras na janela
  `(t - 60000, t]` impõem, respectivamente, esperas de 1, 2, 4, 8 e 16 s a partir
  de `t`. Um processo saudável não zera o contador: as amostras expiram pela janela.
- A sexta amostra coloca a combinação em `crash_blocked`. Esse bloqueio não
  expira. Não muda `enabled` no lock nem impede instâncias de outras sessões ou
  chaves. A chave antiga conserva o bloqueio depois de atualização/rollback,
  disable/enable, remoção/reinstalação da mesma identidade e reinício do core.
- Reinício é lazy: expirar a espera não cria processo. Somente uma nova entrada
  para o harness ou uma nova chamada permitida dispara a avaliação normal de
  spawn. Chamadas recebidas durante espera/bloqueio falham imediatamente com
  `EXT_UNAVAILABLE`; não são enfileiradas para reexecução.
- Chamadas em andamento quando o processo morre falham uma única vez com
  `EXT_UNAVAILABLE`. O core nunca as repete, inclusive após reset humano. Uma
  mensagem de entrada já gravada fica no histórico; reiniciar o harness não
  reenvia automaticamente a notificação antiga nem reexecuta tools anteriores.
- Nova instância ainda exige `enabled`, integridade, permissões, política,
  recursos e condições de contenção normais. `cleanup_failed` não vira crash
  adicional; recursos retidos e revogação seguem o contrato de encerramento.

#### Persistência e relógio

A migração [0005](schemas/0005_crash_recovery.sql) acrescenta
`extension_crash_recovery`. `session_id = null` identifica global; não se usa uma
sessão sentinela. Ausência de linha significa nenhuma falha registrada. `crashes`
é JSON array ordenado por `at_ms`, de até seis objetos exatos
`{"instance_id": "<ULID>", "at_ms": <inteiro não negativo>}`. IDs não se repetem;
os tempos pertencem ao `boot_id` da linha. O writer valida esses detalhes além
dos CHECKs do SQL. `retry_at_ms` é o prazo monotônico da espera; é zero sem espera
ou enquanto bloqueado. `updated_at` usa Unix ms somente para diagnóstico.

A janela e os prazos usam `CLOCK_BOOTTIME` em ms, que inclui suspensão, e o
identificador de `/proc/sys/kernel/random/boot_id`, lidos pelo core. Não usam
UTC, fuso horário nem o relógio civil. No mesmo boot, reiniciar o core preserva
amostras e prazo. Em boot diferente, antes de admitir spawn, o writer conserva
os `instance_id` de uma linha não bloqueada, rebaseia todos os `at_ms` para o
instante atual, atualiza `boot_id` e aplica novamente a espera correspondente ao
número de amostras. Bloqueios permanecem bloqueados, sem prazo. Assim não é
necessário adivinhar a duração de uma parada ou interpretar um salto no relógio
civil. Rebasear e podar a janela não alteram eventos históricos. Leitura inválida
de identidade de boot, relógio ou registro impede o spawn; não equivale a reset.

O writer único, com `synchronous=FULL` confirmado conforme [SQLite](#sqlite),
grava na mesma transação a amostra, o novo prazo/bloqueio,
`ext.crashed` e, no sexto crash, `ext.crash_blocked`, ambos em `sys`. A cauda de
stderr continua em blob (últimas 50 linhas, filtrada como os logs); seu hash vai
em `blob_refs`. Falta de blob é indicada por `stderr_unavailable`; não elimina a
amostra nem autoriza omitir o crash. Falha na transação impede respawn e é
reportada; não se alega auditoria concluída. Repetir o processamento de uma
observação não pode somar duas vezes: `instance_id` identifica a observação, e o
writer consulta também os eventos duráveis quando a amostra já saiu da janela.
Uma transação interrompida não deixa evento sem contador nem contador sem evento.
Após perda do core sem observação durável, aplica-se recuperação de recursos,
sem inventar crash. Todos os leitores de disponibilidade consultam o estado
confirmado antes de admitir spawn. Limpar a janela expirada ou alterar o lock
não apaga uma linha bloqueada.

#### Reabilitação humana

`fictor ext reset-crashes <id> [--key <chave>] [--session <session_id>]` é uma ação
humana explícita, disponível na CLI e na UI confiável. Não existe método de
Kernel Protocol nem tool que a execute. A chave default é a ativa; `--key`
seleciona outra chave ainda presente em `versions`. Sem `--session`, a seleção
inclui todas as combinações dessa extensão/chave; com a opção, inclui somente
aquela sessão, que deve existir. `--session` é inválido para bundle global.

O writer apaga as linhas selecionadas e acrescenta um `ext.crash_reset` por linha
na mesma transação durável, actor `user`, sessão `sys`. Se não houver linha, responde
"nenhuma recuperação a limpar" sem evento fictício. Reset não inicia processos,
não repete mensagens/chamadas, não altera `enabled`, o bundle, kv, `${ext_data}`,
flags U/P, grants, recursos retidos ou bloqueios de integridade. `ext enable`
só habilita no lock; uma extensão desabilitada e bloqueada exige as duas ações
humanas. O reset também pode limpar uma espera/contagem que ainda não bloqueou.

Com o serviço ativo, usa `admin.sock`. Offline, exige a mesma posse exclusiva de
`FICTOR_HOME` do core e os mesmos guardas de versão/migração e writer único; a
resolução de chave ocorre sob a exclusão do instalador, depois de reconciliar
promoções pendentes. Não escreve `lock.json`. Um core ativo ou um journal que
não possa ser reconciliado faz o comando falhar sem mudança parcial.

### Troca de versão (hot swap)

Somente depois do compromisso lógico da promoção (`promoted` + `ext.promoted` + journal `committed`), conforme [ADR-036](06-lifecycle.md#9-promoção):

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

- Arquivo `fictor.db`, `journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=5000`. Toda conexão que escreve usa `synchronous=FULL` desde antes da primeira transação; o core consulta o PRAGMA e recusa a escrita se não confirmar o valor `FULL` (2). Isso vale para inicialização, migrações, writer normal e operações offline; conexões de leitura continuam somente leitura. Journals, autorizações e auditoria precisam sobreviver a perda de energia: no WAL, [FULL sincroniza cada commit, enquanto NORMAL pode perder commits recentes](https://www.sqlite.org/pragma.html#pragma_synchronous). Um checkpoint posterior não substitui essa exigência ([ADR-036](11-decisions.md#adr-036--promoção-recuperável-resolve-arq-020)).
- O comentário de `synchronous=NORMAL` na migração histórica 0001 fica preservado; o contrato vigente de conexão é `FULL`, acima. Não reescrever migrações antigas para alterar PRAGMA de conexão.
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

`installer.registries` aceita somente destinos exatos conforme [Registros de dependências](06-lifecycle.md#registros-de-dependências). Preservar a presença explícita de porta; curingas e descoberta automática de hosts não são admitidos (ADR-040).

## CLI

Binário único `fictor`. Comandos que alteram estado com o servidor rodando falam com ele via `run/admin.sock`. Sem servidor, só funcionam `init`, `doctor`, `secrets`, `serve` e `ext rollback|enable|disable|reset-crashes`. Toda mutação offline exige a [posse exclusiva do home](#posse-do-diretório-de-dados) e os mesmos guardas de migração. Rollback/enable/disable alteram o lock sob a seção crítica do instalador, após reconciliar promoções pendentes. `reset-crashes` escreve somente o SQLite pelo writer único, conforme [Reabilitação humana](#reabilitação-humana); não altera o lock. Core ativo ou reconciliação inconclusiva impede fallback offline.

| Comando | Fase | Função |
|---|---|---|
| `fictor init` | 0 | Cria `FICTOR_HOME`, config, banco e sessão `sys`. Instala o Node LTS e as extensões padrão embutidas (origem `builtin`), com uma confirmação. |
| `fictor doctor` | 0 | Verifica bubblewrap (versão mínima) e user namespaces, SELinux, integridade dos runtimes, keyring e portas. |
| `fictor serve [--open] [--shell-dir <dir>]` | 0 | Sobe o core e imprime a URL de login com token único. `--shell-dir` serve assets do disco (desenvolvimento). |
| `fictor secrets set\|list\|rm <nome>` | 0 | Gerencia segredos. `list` mostra só nomes. |
| `fictor login` | 0 | Pede ao core em execução uma URL de login nova, com token de uso único. Útil quando o core roda como serviço systemd de usuário. |
| `fictor ext list` | 0 | Extensões, versões ativas, estado. |
| `fictor ext install <caminho> [--yes]` | 0 | Proposta de origem `local`; mostra permissões e pede confirmação no TTY. |
| `fictor ext enable\|disable <id>` | 0 | Liga ou desliga no lock; preserva bloqueios de crashes e integridade. |
| `fictor ext rollback <id> [--to <key>]` | 0 | Volta para a versão anterior (ou a indicada). |
| `fictor ext reset-crashes <id> [--key <chave>] [--session <session_id>]` | 0 | Limpa a recuperação selecionada com auditoria; não altera `enabled` nem executa processos. |
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
