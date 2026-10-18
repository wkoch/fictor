# Fictor

Runtime pessoal de agentes de IA: core Rust mínimo e extensões em processos isolados.
Plataforma única: **Linux x86-64**, com validação no **Fedora COSMIC Atomic**.
A arquitetura e o contrato estão em [spec/README.md](spec/README.md).

Implementação em andamento na **Fase 0**. Há bootstrap, store, sandbox, egress,
model proxy e segredos, além da base de supervisor/MCP/Kernel Protocol e
verificação local de bundles; o app ainda não executa conversas nem tem interface web.
A prioridade é a **v0.1 autossuficiente**, conforme o [roadmap](spec/10-roadmap.md):
Fase 0 completa e desenvolvimento dentro do próprio Fictor. O pacote `0.1.0`
identifica o esqueleto atual; o gate de release ainda não foi cumprido.

## Executar a base atual

O desenvolvimento usa o Toolbx Fedora 44 definido em `dev/Containerfile`, com
Rust, Cargo, Clippy, rustfmt, GCC, Git, Node 24 LTS, npm, uv, bubblewrap e
`unshare` (util-linux). Nada é
instalado na base imutável ou como ferramenta global no `$HOME`. As dependências
Rust são fixadas em `core/Cargo.lock`. A compilação exige Linux x86-64.

No terminal do host, na raiz do clone:

```sh
podman build --tag localhost/fictor-dev:44 --file dev/Containerfile dev
toolbox create --image localhost/fictor-dev:44 fictor-dev
toolbox enter fictor-dev
```

Dentro do Toolbx, na raiz do mesmo clone, mantenha os caches no workspace:

```sh
export CARGO_HOME="$PWD/.fictor/cargo"
export npm_config_cache="$PWD/.fictor/npm"
export FICTOR_HOME="$HOME/.local/share/fictor-dev"
cargo fetch --manifest-path core/Cargo.toml --locked
```

O Vite+ será dependência npm local do workspace TypeScript; não use `vp env`
nem uma instalação global. Shell, SDK e extensões padrão ainda não existem nesta
base. A instância de desenvolvimento usará as portas 7360/7361 quando `serve`
estiver implementado.

```sh
cd core
cargo build --locked --offline
./target/debug/fictor init
./target/debug/fictor doctor
```

Sem `FICTOR_HOME`, os dados ficam em `$XDG_DATA_HOME/fictor` ou
`~/.local/share/fictor`. Builds de desenvolvimento devem usar um `FICTOR_HOME`
temporário, separado da instância de uso.

`init` preserva a configuração existente, cria a sessão `sys` e aplica a migração
SQLite. `doctor` retorna erro quando falta Node, sandbox operacional ou porta
livre. uv e Python são opcionais. Node vem de `/usr/bin/node` do Toolbx durante o
desenvolvimento; o gerenciador de runtimes para a instalação de uso permanece
pendente em M0.9. Deno não é mais um runtime aceito.
O diagnóstico de keyring testa apenas a inicialização do backend, sem ler
credenciais. O backend `file` é uma escolha explícita em `[secrets] backend = "file"`;
nesse modo, `secrets.toml` guarda texto puro com dono e modo 0600 verificados.
Não existe fallback automático.

Para gerenciar credenciais no backend configurado:

```sh
./target/debug/fictor secrets set anthropic_api_key
./target/debug/fictor secrets list
./target/debug/fictor secrets rm anthropic_api_key
```

`set` lê exclusivamente do TTY, sem eco; não passe o valor em argumentos nem pelo
chat. `list` mostra somente nomes. Não existe comando que imprima o valor salvo.

Para verificar um bundle local sem ativá-lo:

```sh
./target/debug/fictor ext check /caminho/do/bundle
```

O comando recebe uma cópia em quarentena, valida o manifest e grava a proposta e
as checagens em SQLite. No Toolbx, dependências Node usam `npm ci --ignore-scripts`
com `package-lock.json`; Python usa uv com `requirements.lock`, hashes obrigatórios
e builds desativados. A resolução roda em sandbox com estado descartável e rede
limitada aos registros exatos de `[installer] registries`. Nenhum host é acrescentado
a partir de lockfiles ou redirecionamentos; wildcards são recusados. Porta omitida
permite somente CONNECT público na 443; IP/localhost exige porta explícita.
O smoke de processos usa sandbox, estado descartável, nenhuma rede/modelo e
honeytokens. Grants absolutos/`~/` não são concedidos ao código em verificação.
O resultado imprime hashes, diretórios ignorados e checagens, incluindo as permissões
pedidas e os caminhos omitidos no smoke. Cancelar o chamador não interrompe o worker
de verificação do core; isso não cobre morte ou reinício do processo.
Não há promoção ou ativação por esse comando.

Com o core parado, os controles offline editam somente `enabled` no lock:

```sh
./target/debug/fictor ext disable <id>
./target/debug/fictor ext enable <id>
```

Eles preservam versões e dados, exigem exclusividade do instalador e recusam
qualquer endpoint administrativo existente. O caminho administrativo com servidor
ativo aguarda M0.7.

Toda tentativa recebe um ID durável antes de abrir a origem. Recusas anteriores
ao manifest válido ficam como `failed`, com identidade nula e motivo estável;
a CLI informa o ID sem copiar conteúdo inválido ou caminhos privados no erro.
Falha de persistência terminal é informada como transição não confirmada e
conserva a cópia para recuperação.

No `init` e antes de admitir o primeiro recebimento, tentativas interrompidas
passam a `failed` com `recovery:interrupted`. A limpeza se limita à quarentena,
sem seguir symlinks ou atravessar montagens. Candidatas identificadas que
falharam permanecem disponíveis para revisão; estados terminais são preservados.

Migrações fazem backup privado pela API SQLite e mantêm três cópias. O core
recusa schema mais novo antes de abrir uma conexão SQLite gravável, preservando
inclusive um WAL deixado por um core mais novo após crash.

`init --first-party` será integrado ao pipeline de instalação em M0.5. Atualmente
ele retorna um erro antes de alterar arquivos. `serve` ainda não está implementado.

## Verificar

```sh
cd core
cargo fmt --all -- --check
cargo clippy --locked --offline --all-targets -- -D warnings
cargo test --locked --offline
```

Os testes usam diretórios temporários, chaves falsas e endpoints locais; não
precisam de chaves de modelo nem de rede externa. O Toolbx de desenvolvimento
precisa permitir os namespaces do bubblewrap. Aninhamento pode impedir a execução
dentro de outra sandbox; nenhuma proteção é desativada para fazer testes passar.

A CI também inclui um container Fedora 44 para build e testes que não criam
sandboxes reais. A versão corresponde à [release estável do COSMIC Atomic](https://fedoraproject.org/atomic-desktops/cosmic/download/)
consultada em 2026-10-17. O gate de release exige todos os critérios de aceitação
na máquina Fedora COSMIC Atomic do usuário, com data, versão do SO e commit
registrados. Build, Clippy e 408 testes passaram no Toolbx Fedora 44 sobre Bazzite;
esse diagnóstico não substitui o gate no COSMIC Atomic nem a execução da CI.

Veja o [andamento](docs/implementation.md), a [verificação](docs/verification.md),
a [cobertura das invariantes](docs/invariants.md) e as
[pendências do arquiteto](docs/architect-pending.md).
O [caminho até a v1.0](docs/release-path.md) distingue o escopo restante e os gates.
As entregas seguem diretamente na `main`, conforme o
[fluxo de Git](docs/implementation.md#fluxo-de-git).
