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
2. Permissões do runtime (Deno) derivadas do manifest (defesa em profundidade).
3. Egress proxy: toda rede passa pelo core, com allowlist e registro.
4. Política no core: classificação de tools, flags U/P, Rule of Two, modos, aprovações.
5. Pipeline de extensões: nada roda sem checagens, aprovação e hash fixado.
6. Endurecimento do shell web e isolamento das surfaces.

## Perfil de sandbox

O supervisor converte o manifest em um `SandboxProfile`:

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
- Nunca montados: `FICTOR_HOME` (exceto o bundle, `data/<id>` e os sockets da instância), o HOME real (exceto `sandbox.home_ro_files` em instâncias de sessão), `/var/run/docker.sock`, sockets de agente SSH e GPG.
- Não existe rede direta. Só o proxy.
- O ambiente é construído do zero ([02-core.md](02-core.md#spawn)).

### Linux (bubblewrap)

O supervisor executa `bwrap` com ambiente vazio. Estrutura dos argumentos (ajustar por teste em Fedora Atomic e em uma distro tradicional):

```text
bwrap
  --die-with-parent --new-session --unshare-all
  --ro-bind /usr /usr
  --symlink usr/bin /bin --symlink usr/sbin /sbin --symlink usr/lib /lib --symlink usr/lib64 /lib64
  --ro-bind-try /etc/ssl /etc/ssl --ro-bind-try /etc/pki /etc/pki
  --ro-bind-try /etc/ca-certificates /etc/ca-certificates
  --ro-bind-try /etc/alternatives /etc/alternatives --ro-bind-try /etc/localtime /etc/localtime
  --ro-bind-try /etc/passwd /etc/passwd --ro-bind-try /etc/group /etc/group
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

Caminhos do host são montados no mesmo caminho dentro do sandbox, exceto `${tmp}`, que é o `/tmp` interno. `--unshare-all` cria namespaces de rede, PID, IPC, UTS, cgroup e usuário; o bubblewrap ativa o loopback.

`fictor __sandbox-init` roda como PID 1 dentro do sandbox:

1. Escuta em `127.0.0.1:3128` e repassa cada conexão para `/fx/proxy.sock`.
2. (Fase 3) Aplica Landlock (somente os caminhos do perfil) e um filtro seccomp (bloqueia `ptrace`, `mount`, `bpf`, `keyctl`, `unshare`, criação de sockets fora de AF_UNIX/AF_INET para loopback; bloqueia `execve` se `spawn: false` após o primeiro exec).
3. Inicia o comando, repassa sinais, recolhe zumbis e sai com o código do filho.

Até a Fase 3, `spawn: false` só é aplicado pelo Deno (`--allow-run` ausente). Para `node` e `python` é apenas declarativo. Isso DEVE aparecer na UI de aprovação.

### macOS (Seatbelt)

O supervisor gera um perfil SBPL por instância e executa `/usr/bin/sandbox-exec -p <perfil> -- <comando>`. Estrutura (ilustrativa; partir da política base auditada do Codex ou do sandbox-runtime e validar):

```scheme
(version 1)
(deny default)
; base: sysctl-read, mach-lookup necessários, leitura de /usr, /System, /Library, /private/etc, dyld
(allow process-exec (literal "<binário do runtime>"))
(allow process-fork)                                   ; só se spawn
(allow process-exec)                                   ; só se spawn
(allow file-read* (subpath "<dir do runtime>") (subpath "<bundle>"))
(allow file-read* (subpath "<cada fs.read>"))
(allow file-read* file-write* (subpath "<ext_data>") (subpath "<tmp>") (subpath "<cada fs.write>"))
(allow network-outbound (remote tcp "localhost:<porta do proxy>"))
(allow network-outbound (remote unix-socket (path-literal "<socket do kernel>")))
```

`${tmp}` no macOS é `$TMPDIR/fictor/<instance_id>`, removido ao encerrar a instância.

`sandbox-exec` é uma API depreciada pela Apple, mas é usada por Codex e Claude Code. Monitorar e manter o tier `vm` como alternativa.

### Tiers de isolamento

| Tier | Mecanismo | Fase | Uso |
|---|---|---|---|
| `os` | bubblewrap / Seatbelt | 0 | default |
| `container` | podman rootless, com o mesmo proxy e init | 3 | dependências de sistema pesadas, imagens OCI de MCP |
| `vm` | podman com runtime krun (Linux), Apple `container` (macOS) | 4 | computer use, tarefas estilo Cowork, código de alto risco |

## Proveniência

O core calcula `trust` e `sensitivity` de cada `tool.result`.

`trust = untrusted` se qualquer condição valer:

1. `output_trust` efetivo da tool é `untrusted`;
2. `output_trust` é `workspace` e a sessão tem `workspace_trust = untrusted`;
3. a extensão tem `net.allow` com algum padrão fora de `policy.trusted_domains`. Nesse caso o `output_trust` efetivo de todas as suas tools é `untrusted`, independentemente do manifest.

Caso contrário, `trust = trusted`. `sensitivity` vem da classificação da tool.

Além disso, instâncias de sessão que conectam via proxy a domínio fora de `policy.trusted_domains` acendem U diretamente ([02-core.md](02-core.md#proveniência-de-rede)).

### Flags da sessão

- **U**: a sessão já recebeu conteúdo `untrusted`.
- **P**: a sessão já recebeu conteúdo `private`.

As flags só acendem e nunca apagam dentro de uma sessão. Para "limpar", o usuário faz fork de um evento anterior à contaminação. Cada vez que uma flag acende, o core grava `session.tainted` com o motivo e o evento de origem.

## Decisão

Toda chamada a `tools.call`, vinda do harness ou de uma surface, passa por esta função. A ordem é normativa:

```text
decide(tool T, sessão S, origem O):
  1. T inexistente ou extensão desativada                         → deny
  2. regra de config com decision=deny casa T.name                → deny
  3. S.mode == plan e T.effect != read                            → deny  ("modo plan")
  4. T.effect == external e S.U e (S.P ou T.sensitivity == private)
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

- Chaves de provider ficam só no model proxy (invariante I4).
- **Exceção:** `permissions.secrets` injeta um segredo como variável de ambiente, para servidores MCP de terceiros que só aceitam token assim. Condições:
  - nunca é promovido automaticamente;
  - `net.allow` DEVE ser não vazio e sem `*`;
  - a UI marca a extensão como "segredo exposto ao processo";
  - os valores são mascarados nos logs.
- (Fase 3) O proxy termina TLS só para hosts com regra de injeção, usando uma CA local confiada apenas dentro do sandbox (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `DENO_CERT`), e injeta o cabeçalho. Com isso a exceção deixa de ser necessária.
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
| Escrita local sob injection planta código que o usuário executa depois fora do sandbox | Checkpoints e diff; aviso quando sessão com U edita scripts, hooks de git ou CI | 2 |
| Extensão global mistura dados de sessões diferentes | Extensões que tocam dados privados DEVERIAM ser `scope: session`; revisão no pipeline | — |
| Segredo via env visível para a extensão | Allowlist de rede obrigatória; injeção no proxy | 3 |
| `spawn: false` não aplicado para node/python no Linux | Documentado na aprovação; seccomp | 3 |
| Seatbelt depreciado | Tier `vm` | 4 |
| Instruções maliciosas dentro de skills | Revisão no pipeline; skills só de bundles promovidos | 3 |
| Fadiga de aprovação | Grants por sessão; motivo explícito; modo `auto` com Rule of Two | — |
