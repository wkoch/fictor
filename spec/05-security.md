# 05 — Segurança

## Modelo de ameaças

### Ativos

- Chaves de API e outros segredos.
- Dados privados: arquivos do usuário, emails, documentos, histórico de sessões.
- Integridade do core, da configuração, do lock e do store.
- Atenção do usuário (aprovações demais viram cliques automáticos).

### Adversários

| ID | Adversário | Exemplo |
|---|---|---|
| A1 | Conteúdo externo com prompt injection | Página web, email, issue do GitHub, README de repositório clonado. |
| A2 | Extensão de terceiros maliciosa ou comprometida | Pacote com postinstall malicioso; servidor MCP que muda a descrição das tools depois de aprovado (rug pull). |
| A3 | Código gerado pela IA defeituoso ou influenciado por A1 | Extensão proposta que exfiltra dados. |
| A4 | Sites abertos no navegador atacando o localhost | DNS rebinding, CSRF contra o shell. |
| A5 | Erro do modelo | Comando destrutivo, edição errada. |

### Fora de escopo

Atacante com acesso à conta local do usuário ou root; exploits de kernel do SO e de escape de sandbox; canais laterais; provider de modelo malicioso.

## Camadas de defesa

1. Sandbox do SO por processo de extensão (fronteira principal).
2. Permissões do runtime (modelo de permissões do Node) derivadas das permissões efetivas aprovadas, com os overrides humanos validados (defesa em profundidade).
3. Egress proxy: toda rede passa pelo core, com allowlist e registro.
4. Política no core: classificação de tools, flags U/P, Rule of Two, modos, aprovações.
5. Pipeline de extensões: nada roda sem checagens, aprovação e hash fixado.
6. Endurecimento do shell web e isolamento das surfaces.

## Perfil de sandbox

O supervisor converte as [permissões efetivas aprovadas](06-lifecycle.md#overrides-humanos) em um `SandboxProfile`. Manifest verificado e overrides validados produzem um único resultado para supervisor, runtime, proxies, catálogo e política; nenhum consumidor ignora um override ou refaz o merge. As bases implícitas e os bloqueios abaixo continuam obrigatórios:

```rust
struct SandboxProfile {
    read_paths: Vec<PathBuf>,     // bundle, runtime, fs.read, home_ro_files
    write_paths: Vec<PathBuf>,    // ext_data, tmp, fs.write
    spawn: bool,
    kernel_socket: Option<PathBuf>,
    proxy: ProxyEndpoint,         // sempre presente; não existe rede direta
    env: BTreeMap<String, String>,
    cwd: PathBuf,
    tier: Tier,                   // Os | Container (Fase 3) | Vm (Fase 4)
}
```

Regras comuns:

- Caminhos são canonicalizados antes de montar. Symlinks que apontem para fora dos caminhos permitidos são recusados.
- `FICTOR_HOME` nunca é montado, exceto o bundle, o `${ext_data}` da instância e os sockets da instância. O HOME real nunca é montado inteiro (só `sandbox.home_ro_files`, em instâncias de sessão).
- Arquivos montados um a um (`fs.read` apontando para arquivo, `home_ro_files`) que sejam sockets são recusados.
- Caminhos sensíveis: o supervisor recusa o spawn se um caminho do perfil for igual a um caminho sensível, o contiver ou estiver contido nele. Lista:
  - credenciais: `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`, `~/.docker`, `~/.config/gcloud`, `~/.config/gh`, `~/.netrc`, `~/.git-credentials`, `~/.local/share/keyrings`, `~/.npmrc`, `~/.pypirc`, `~/.cargo/credentials`, `~/.cargo/credentials.toml`, `~/.config/containers/auth.json`;
  - diretórios de runtime com sockets: `$XDG_RUNTIME_DIR` (ou `/run/user/<uid>`), `/run`, `/var/run`, `/tmp/.X11-unix`;
  - endpoints descobertos na inicialização do core (e de novo em `fictor doctor`):
    - `SSH_AUTH_SOCK` do ambiente do core;
    - saída de `gpgconf --list-dirs` (`homedir`, `socketdir`, `agent-socket`, `agent-ssh-socket`, `agent-extra-socket`, `agent-browser-socket`, `dirmngr-socket`, `keyboxd-socket`), com timeout de 2 s. Esse comando não inicia o agente. Se `gpgconf` não existir ou falhar, usar `~/.gnupg` e `$XDG_RUNTIME_DIR/gnupg`, seguir e avisar no `doctor`;
    - `DOCKER_HOST` e `DBUS_SESSION_BUS_ADDRESS` quando apontam para Unix socket; `/run/docker.sock`, `$XDG_RUNTIME_DIR/docker.sock`, `$XDG_RUNTIME_DIR/podman/podman.sock`, `/run/podman/podman.sock`, `/run/dbus/system_bus_socket`.
- Sockets Unix que não estão na lista, criados dentro de um diretório montado (por exemplo, no workspace): montagem somente leitura não impede `connect()` em socket. Ficam alcançáveis até a Fase 3, quando o seccomp nega `socket(AF_UNIX, …)` à carga de trabalho. Risco residual documentado no fim deste arquivo.
- Destinos proibidos para escrita (persistência fora do sandbox): o diretório do executável do core (por padrão `~/.local/bin`), `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc`, `~/.config/autostart`, `~/.config/systemd/user`, `~/.config/environment.d`, `~/.local/share/applications`. Montar qualquer um deles, ou um diretório que os contenha, com escrita é recusado.
- Não existe rede direta. Só o proxy.
- O ambiente é construído do zero ([02-core.md](02-core.md#spawn)).

### Origem protegida dos arquivos de controle

A proibição de expor a árvore privada de `FICTOR_HOME` vale também para aliases por bind mount e sobreposições de montagem, não só para prefixos textuais ou symlinks canonicalizados. A validação de cada perfil deve considerar identidade e ancestralidade de suas fontes/montagens, incluindo submounts que seriam incorporados por um grant de diretório. Se o grant expuser por alias a raiz privada ou um arquivo de controle, recusar o grant inteiro e o spawn; não reescrever o grant, ocultar um submount silenciosamente nem conceder outro caminho. Quando não for possível estabelecer essa separação, recusar o perfil. Isso conserva as exceções já explícitas de bundle, ext_data e sockets próprios; elas não abrangem os arquivos de controle nem permitem expor sua raiz privada. A identidade da raiz protege também `config.toml`/`AGENTS.md` ainda ausentes: a criação futura não pode tornar acessível um novo controle a um sandbox existente.

Nenhuma nova lista de destinos de symlinks é criada. A política recusa os links dos arquivos de controle conforme [02-core.md](02-core.md#arquivos-de-controle-do-core); não adiciona seus alvos ao perfil. `FICTOR_HOME` e workspaces continuam sujeitos às restrições de sobreposição existentes, considerando a identidade fixada do home, não apenas a grafia do caminho. A topologia de [mountinfo](https://man7.org/linux/man-pages/man5/proc_pid_mountinfo.5.html) permite distinguir raízes e ancestrais de bind mounts; a estratégia interna permanece responsabilidade do implementador.

### Linux (bubblewrap)

O supervisor executa `bwrap` com ambiente vazio. Estrutura dos argumentos (ajustar por teste no Fedora COSMIC Atomic):

```text
bwrap
  --die-with-parent --new-session --unshare-all --as-pid-1
  --ro-bind /usr /usr
  --symlink usr/bin /bin --symlink usr/sbin /sbin --symlink usr/lib /lib --symlink usr/lib64 /lib64
  --ro-bind-try /etc/ssl /etc/ssl --ro-bind-try /etc/pki /etc/pki
  --ro-bind-try /etc/ca-certificates /etc/ca-certificates
  --ro-bind-try /etc/alternatives /etc/alternatives --ro-bind-try /etc/localtime /etc/localtime
  --ro-bind-try /etc/passwd /etc/passwd --ro-bind-try /etc/group /etc/group
  --ro-bind-try /etc/crypto-policies /etc/crypto-policies --ro-bind-try /etc/nsswitch.conf /etc/nsswitch.conf
  --symlink var/home /home ...                               (Fedora Atomic; ver abaixo)
  --proc /proc --dev /dev --tmpfs /tmp
  --ro-bind <dir do runtime> <mesmo caminho>
  --ro-bind <bundle> <mesmo caminho>
  --bind <ext_data> <mesmo caminho>
  --ro-bind | --bind <cada caminho de fs.read | fs.write>
  --ro-bind <executável fictor> /fx/fictor
  --bind <run/proxy.sock> /fx/proxy.sock
  --bind <run/k/<instance_id>.sock> /fx/kernel.sock          (se houver kernel)
  --setenv <K> <V> ...
  --chdir <cwd>
  /fx/fictor __sandbox-init -- <comando do runtime>
```

Caminhos do host são montados no mesmo caminho canônico dentro do sandbox, exceto `${tmp}`, que é o `/tmp` interno. `--unshare-all` cria namespaces de rede, PID, IPC, UTS, cgroup e usuário; o bubblewrap ativa o loopback.

No Fedora Atomic:

- Montagens usam sempre o caminho canônico (`/var/home/<usuário>/...`). Para cada um de `/home`, `/opt`, `/srv`, `/mnt` e `/root` que no host seja symlink para `var/...`, o sandbox recebe o mesmo symlink (`--symlink var/home /home` etc.). Assim, `/home/<usuário>/Projetos/x` funciona dentro do sandbox quando o caminho canônico está montado; o resto de `/var` continua invisível.
- `/etc/crypto-policies` e `/etc/nsswitch.conf` são necessários para o OpenSSL do Fedora (git, curl).
- Nada é sobreposto em `/usr` (R8). Runtimes vêm de `$FICTOR_HOME/runtime/`. Na instância de desenvolvimento, que roda dentro do toolbx, o `/usr` montado é o do container, com as ferramentas de desenvolvimento.
- SELinux: processos do usuário rodam como `unconfined_t`, e o bubblewrap funciona sem política extra. O `doctor` reporta negações que afetem o sandbox quando conseguir detectá-las.

Sandbox aninhado: os testes do próprio core que criam sandboxes reais, rodados dentro de uma sessão Fictor, dependem de user namespaces aninhados. Até a Fase 3 isso DEVERIA funcionar; o seccomp da Fase 3 nega `unshare`. Esses testes DEVEM continuar executáveis fora do Fictor (terminal e CI). A Fase 3 decide, por ADR, se haverá permissão para sandbox aninhado.

`fictor __sandbox-init` roda como PID 1 dentro do sandbox, garantido por `--as-pid-1`. O supervisor persiste o journal e mantém a carga bloqueada até registrar duravelmente as identidades do launcher e do init, conforme [Registro e barreira de spawn](02-core.md#registro-e-barreira-de-spawn) ([ADR-038](11-decisions.md#adr-038--posse-do-home-e-recuperação-de-instâncias-resolve-arq-022)):

1. Escuta em `127.0.0.1:3128` e repassa cada conexão para `/fx/proxy.sock`.
2. Se houver kernel, escuta em `127.0.0.1:3129` e repassa cada conexão para `/fx/kernel.sock`. Os dois listeners sobem antes do comando, então a carga de trabalho não consegue ocupar essas portas.
3. Aguarda a liberação pelo supervisor em canal privado, não herdado pela carga. EOF, ausência de autorização, falha de persistência ou morte do dono abortam sem executar a extensão. `--die-with-parent` continua obrigatório.
4. (Fase 3) No processo filho, antes do `execve`, aplica Landlock (somente os caminhos do perfil) e um filtro seccomp que nega: `ptrace`, `mount`, `umount2`, `pivot_root`, `bpf`, `keyctl`, `add_key`, `request_key`, `unshare`, `setns`, `perf_event_open`; `socket()` com domínio diferente de `AF_INET`/`AF_INET6` (inclui `AF_UNIX`, `AF_NETLINK`, `AF_PACKET`), mantendo `socketpair(AF_UNIX)`; e `execve`/`execveat` depois do primeiro, se `spawn: false`. O próprio init não recebe o filtro. Validar com Node e Python; ajustes exigem ADR.
5. Após a barreira, inicia o comando, repassa sinais, recolhe zumbis e sai com o código do filho.

A liberação dos recursos exige confirmação do término do launcher **e** do PID 1. Saída do launcher, fechamento do canal ou liberação da posse do home isoladamente não provam a ausência de descendentes. Recuperação e retenção de recursos ambíguos seguem [Confirmação e recuperação no boot](02-core.md#confirmação-e-recuperação-no-boot); journals e temporários sem posse comprovada não autorizam limpeza.

Até a Fase 3, `spawn: false` é aplicado pelo modelo de permissões do Node (sem `--allow-child-process`). Para `python` é apenas declarativo. Isso DEVE aparecer na UI de aprovação.

### Tiers de isolamento

| Tier | Mecanismo | Fase | Uso |
|---|---|---|---|
| `os` | bubblewrap | 0 | default |
| `container` | podman rootless, com o mesmo proxy e init | 3 | dependências de sistema pesadas, imagens OCI de MCP |
| `vm` | podman com runtime krun | 4 | computer use, tarefas estilo Cowork, código de alto risco |

## Proveniência

O core calcula `trust` e `sensitivity` de cada `tool.result` a partir da classificação efetiva aprovada, resolvida com os [overrides humanos](06-lifecycle.md#overrides-humanos). As imposições abaixo prevalecem sobre ajustes humanos; nenhuma classificação apaga flags já adquiridas.

`trust = untrusted` se qualquer condição valer:

1. `output_trust` efetivo da tool é `untrusted`;
2. `output_trust` é `workspace` e a sessão tem `workspace_trust = untrusted`;
3. `output_trust` é `workspace` e o workspace da sessão está com a flag U ([Flag de workspace](#flag-de-workspace));
4. a extensão tem `net.allow` efetivo com algum padrão fora de `policy.trusted_domains`. Nesse caso o `output_trust` efetivo de todas as suas tools é `untrusted`, independentemente do manifest ou do override de classificação;
5. a extensão é global e sua marca d'água tem U ([Marca d'água](#marca-dágua-de-extensões-globais-fase-1)).

Caso contrário, `trust = trusted`. `sensitivity` vem da classificação da tool; vira `private` se a marca d'água da extensão tiver P.

Além disso, instâncias de sessão que conectam via proxy a domínio fora de `policy.trusted_domains` acendem U diretamente ([02-core.md](02-core.md#proveniência-de-rede)).

### Flags da sessão

- **U**: a sessão já recebeu conteúdo `untrusted`.
- **P**: a sessão já recebeu conteúdo `private`.

As flags só acendem e nunca apagam dentro de uma sessão. Para "limpar", o usuário faz fork de um evento anterior à contaminação. Cada vez que uma flag acende, o core grava `session.tainted` com o motivo e o evento de origem.

## Fluxo entre sessões

Invariante I11. O harness, e portanto o modelo, só recebe dados por canais mediados pelo core, e os canais que atravessam sessões também propagam flags. Nada aqui depende de algo que a extensão informe em runtime; a classificação efetiva vem do manifest revisado e dos overrides humanos fixados no lock.

### Canais de entrada do harness

| Canal | Regra |
|---|---|
| `tools.call` | `tool.result` com [proveniência](#proveniência). É o único caminho do workspace, da web e de serviços externos até o harness. |
| `hooks.invoke` | Cada hook que responde acende na sessão as flags da sua classificação efetiva: base nominal/default/restritiva com os overrides humanos validados ([06-lifecycle.md](06-lifecycle.md#overrides-humanos)), combinada com a marca d'água se a extensão for global. |
| Rede via proxy | Domínio fora de `trusted_domains` acende U ([02-core.md](02-core.md#proveniência-de-rede)). |
| Model proxy | Respostas de providers configurados não contaminam. |
| `events.*` | Só a linhagem da própria sessão, cujas flags já estão no head. |
| `kv`, `${ext_data}` | Por sessão (`ext_id@session_id`, `data/<id>/sessions/<session_id>`). Não formam canal entre sessões. |
| `blobs.get` | Ler exige conhecer o hash, que só chega por um dos canais acima. |
| `config.get` | Somente dados de arquivos de controle aprovados pelas verificações de [origem protegida](02-core.md#arquivos-de-controle-do-core), ou snapshots já validados na inicialização: trusted, public. Fonte insegura falha; não se reclassifica nem é seguida para fora do home. |
| Arquivos | Só `${store}`, `${ext_root}`, `${ext_data}` e `${tmp}` ([04-extensions.md](04-extensions.md#escopo-e-templates-de-caminho)). Bundles no store foram aprovados: trusted, public. |

Extensões de sessão com `${workspace}` (como `fs-tools`) leem o workspace diretamente, mas só entregam dados ao harness como `tool.result`, com a classificação efetiva aprovada e as regras de proveniência do core.

### Flag de workspace

Fecha o caminho "sessão contaminada escreve no workspace, outra sessão lê".

- Tabela `workspace_flags` ([schemas/0002_flow_budget.sql](schemas/0002_flow_budget.sql)), chave = caminho canônico.
- Quando uma sessão com U tem admitida uma chamada com `effect` diferente de `read` a uma tool de extensão que tem `${workspace}` em `fs.write`, o core acende U no workspace antes de executar e grava `workspace.flagged`.
- Enquanto a flag estiver acesa, tools com `output_trust: workspace` devolvem `untrusted` em qualquer sessão desse workspace. Workspaces sobrepostos (um contém o outro) compartilham a flag.
- Só o usuário apaga a flag: na UI confiável, depois de revisar as mudanças, ou com `fictor workspace clear <caminho>`. Grava `workspace.cleared`.
- P não é propagado ao workspace: tools que leem o workspace já são `sensitivity: private`.

### Marca d'água de extensões globais (Fase 1)

Fecha o caminho "sessão contaminada envia dados a uma extensão global com estado, outra sessão lê".

- Tabela `ext_flags` ([schemas/0002_flow_budget.sql](schemas/0002_flow_budget.sql)).
- O core acende na marca d'água as flags da sessão que chama uma tool da extensão, invoca um hook dela ou tem eventos lidos por ela via `events.*`. Grava `ext.flags_changed` quando a marca muda.
- Resultados de tools, respostas de hooks, `ui.event` e `ext.input` da extensão saem combinados com a marca: U → `untrusted`, P → `private`.
- A marca só apaga com "limpar estado" (UI confiável ou `fictor ext reset <id>`). Isso apaga o kv da extensão, o `${ext_data}` global e a marca, reinicia as instâncias e grava `ext.state_reset`.
- Consequência intencional: uma extensão global de memória chamada por sessão contaminada passa a contaminar quem a lê.

## Decisão

Toda chamada a `tools.call`, vinda do harness ou de uma surface, passa por esta função usando a classificação efetiva aprovada. Chamadas de surfaces exigem também `ui_callable: true` efetivo e tool da própria extensão. A ordem é normativa:

```text
decide(tool T, sessão S, origem O):
  1. T inexistente ou extensão desativada                         → deny
  2. regra de config com decision=deny casa T.name                → deny
  3. S.mode == plan e T.effect != read                            → deny  ("modo plan")
  4. T.effect == external e S.U e (S.P ou sensitivity efetiva de T == private)
                                                                  → ask   (Rule of Two; escopo só "once")
  5. existe grant (sessão S ou permanente) para T.name            → allow
  6. regra de config com decision=ask casa T.name                 → ask
  7. regra de config com decision=allow casa T.name               → allow
  8. default do modo:
       default: read → allow; write_local → allow; external → ask
       auto:    allow
```

Pós-regra: em sessões `kind = eval`, qualquer resultado `ask` vira `deny` com motivo "eval sem humano".

Regras de config (`[[policy.rules]]`) usam glob sobre o nome exposto (`fs-tools__*`, `web__web_fetch`).

### Rule of Two adaptada

A regra original da Meta proíbe combinar, sem humano: [A] entrada não confiável, [B] acesso a dados sensíveis, [C] mudar estado ou comunicar para fora. Aqui A = U, B = P (ou tool privada) e C = `effect: external`.

Adaptação consciente: escrita local (`write_local`) não conta como C. Ela é confinada ao workspace pelo sandbox e é reversível por git e checkpoints (Fase 2). O risco residual está na tabela do fim deste arquivo.

## Aprovações

- Criadas pelo core (`approvals` no banco) com um `nonce` aleatório de 128 bits.
- Exibidas só pela UI confiável do shell ([08-shell.md](08-shell.md#aprovações)). Decididas só por mensagem WebSocket autenticada do shell com o `nonce` correto, ou pela CLI.
- Conteúdo exibido: extensão e tool, origem (harness ou surface), classificação, argumentos completos, flags da sessão com os motivos (links para os eventos `session.tainted`) e, no caso da Rule of Two, um aviso explicando a combinação.
- Escopos: `once`, `session` (grava grant da sessão), `always` (grava grant permanente). No caso da Rule of Two só existe `once`.
- Negar aceita uma mensagem opcional, devolvida ao modelo em `APPROVAL_REJECTED.data.message`.
- Sem timeout. `session.cancel`, arquivamento da sessão ou morte do harness marcam as pendentes como `cancelled`.
- Aprovação customizada (`approval.request`) é exibida com o rótulo "pedido da extensão <id>" e não gera grant.

## Segredos

- Chaves de provider ficam só no model proxy (invariante I4). Armazenamento e backends em [02-core.md](02-core.md#segredos).
- **Exceção:** `permissions.secrets` injeta um segredo como variável de ambiente, para servidores MCP de terceiros que só aceitam token assim. Condições:
  - nunca é promovido automaticamente;
  - `net.allow` efetivo DEVE ser não vazio e sem `*`; um override que remova a rede e preserve algum segredo é inválido;
  - a UI marca a extensão como "segredo exposto ao processo";
  - os valores são mascarados nos logs.
- (Fase 3) O proxy termina TLS só para hosts com regra de injeção, usando uma CA local confiada apenas dentro do sandbox (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`), e injeta o cabeçalho. Com isso a exceção deixa de ser necessária.
- Servidores MCP remotos (`runtime.kind: remote`) não precisam da exceção: o core é o cliente HTTP e injeta o cabeçalho.

## Endurecimento web

Uma UI web em localhost é alvo de qualquer site aberto no navegador. As regras abaixo são obrigatórias desde a Fase 0.

| Regra | Detalhe |
|---|---|
| Host do shell | Só aceitar `Host: 127.0.0.1:<porta>`. Requisições com `Host: localhost:<porta>` recebem redirect para `127.0.0.1`. Outros hosts: 403 (defesa contra DNS rebinding). |
| Login | `fictor serve` imprime `http://127.0.0.1:<porta>/login?t=<token>`. Token de uso único, 256 bits, válido por 10 minutos. |
| Cookie | `fictor_session`, aleatório, `HttpOnly`, `SameSite=Strict`, `Path=/`. Expira em 30 dias. |
| WebSocket | Exige cookie válido e `Origin: http://127.0.0.1:<porta>`. Sem isso, 403. |
| Mutações HTTP | `POST`/`PUT`/`DELETE` exigem cookie, `Origin` igual ao shell e cabeçalho `X-Fictor-CSRF` com o token CSRF da sessão. |
| CORS | Nenhum cabeçalho CORS é emitido. |
| CSP do shell | `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' ws://127.0.0.1:<porta>; frame-src http://localhost:<surface_port>; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` |
| Host de surfaces | Listener separado em `http://localhost:<surface_port>`, aceita só `Host: localhost:<surface_port>`, nunca recebe cookies do shell (host diferente) e não expõe nenhuma API. |
| CSP das surfaces | Cabeçalho HTTP: `default-src 'none'; script-src http://localhost:<surface_port> 'unsafe-inline'; style-src http://localhost:<surface_port> 'unsafe-inline'; img-src http://localhost:<surface_port> data: blob:; font-src http://localhost:<surface_port>; connect-src 'none'; form-action 'none'; frame-ancestors http://127.0.0.1:<porta>` |
| iframe | `sandbox="allow-scripts allow-forms"`. Sem `allow-same-origin`, `allow-popups`, `allow-top-navigation`. |
| Imagens no chat | Imagens remotas não são carregadas (CSP e sanitização). Links mostram a URL completa. |

## Medidas contra prompt injection

Nenhum filtro remove prompt injection de forma confiável. A defesa é estrutural; detecção é só sinal.

| Medida | Fase |
|---|---|
| Flags U/P e Rule of Two aplicadas pelo core | 0 |
| Spotlighting: o harness delimita conteúdo `untrusted` no contexto e instrui o modelo a não seguir instruções dele | 0 |
| Chat sem imagens remotas; links com URL completa visível | 0 |
| `workspace_trust` por sessão para repositórios de terceiros | 0 |
| Hash das definições de tools fixado; mudança desativa a extensão | 0 |
| Propostas vindas de sessão com U nunca são promovidas automaticamente | 1 |
| Surfaces sem rede (`connect-src 'none'`) | 1 |
| Leitor em quarentena (ver abaixo) | 3 |
| Classificador de injection como sinal na tela de aprovação | 4 (opcional) |
| Aprovação com notificação no celular (ntfy) para sessões longas | 4 |

### Leitor em quarentena (Fase 3)

Extensão first-party `qreader` com a tool `extract({source, schema})`. Ela faz uma chamada de modelo sem tools, pedindo que o conteúdo externo seja extraído para o schema dado. O core considera o resultado `trusted` somente se todas as condições valerem:

1. o lock marca a extensão com o privilégio `structured_output_trust` (concedido só por humano);
2. o schema contém apenas `boolean`, `number`, `integer`, `string` com `enum` ou `string` com `format: date`/`date-time`, com no máximo 100 campos;
3. o resultado valida contra o schema.

Senão, o resultado é `untrusted`. Valores fechados não carregam instruções; textos livres carregam.

## Riscos residuais

| Risco | Mitigação | Fase |
|---|---|---|
| Escrita local sob injection planta código que o usuário executa depois fora do sandbox | Flag de workspace; checkpoints e diff; aviso quando sessão com U edita scripts, hooks de git ou CI | 0 / 2 |
| Programas fora do Fictor (ex.: `git pull`) trazem conteúdo de terceiros para um workspace `trusted` sem acender flag | `workspace_trust` é escolha do usuário por sessão; o shell mostra o valor ao criar a sessão | — |
| Marca d'água superestima a contaminação de extensões globais | "Limpar estado"; preferir `scope: session` para extensões com estado | 1 |
| Linux: sockets Unix fora da lista de caminhos sensíveis, dentro de diretórios montados, ficam alcançáveis | Lista de caminhos sensíveis e descoberta; seccomp nega `socket(AF_UNIX)` | 3 |
| Rede com prefixo NAT64 específico não configurado: o IPv4 embutido não é avaliado e pode alcançar um destino privado via gateway | `fictor doctor` detecta e sugere `[egress] nat64_prefixes`; o prefixo bem conhecido e o de uso local já são cobertos | — |
| Segredo via env visível para a extensão | Allowlist de rede obrigatória; injeção no proxy | 3 |
| `spawn: false` não aplicado para python | Documentado na aprovação; seccomp | 3 |
| Atualização de runtime confia no que o upstream publica no momento | Checksum da mesma origem; (Fase 3) assinatura ou atestação; smoke com as extensões ativas; aprovação humana; rollback | 0 / 3 |
| Instruções maliciosas dentro de skills | Revisão no pipeline; skills só de bundles promovidos | 3 |
| Fadiga de aprovação | Grants por sessão; motivo explícito; modo `auto` com Rule of Two | — |
