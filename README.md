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

Requer Linux x86-64, Rust stable, Cargo e bubblewrap. Deno 2 será necessário
para o app completo. As dependências são fixadas em `core/Cargo.lock`.
A compilação recusa qualquer outro sistema ou arquitetura.

```sh
cd core
cargo build --locked
FICTOR_HOME=/tmp/fictor-dev ./target/debug/fictor init
FICTOR_HOME=/tmp/fictor-dev ./target/debug/fictor doctor
```

Sem `FICTOR_HOME`, os dados ficam em `$XDG_DATA_HOME/fictor` ou
`~/.local/share/fictor`. Builds de desenvolvimento devem usar um `FICTOR_HOME`
temporário, separado da instância de uso.

`init` preserva a configuração existente, cria a sessão `sys` e aplica a migração
SQLite. `doctor` retorna erro quando falta um requisito obrigatório, como Deno,
sandbox operacional ou porta livre. Node, uv e Python são opcionais neste estágio.
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
FICTOR_HOME=/tmp/fictor-dev ./target/debug/fictor ext check /caminho/do/bundle
```

O comando recebe uma cópia em quarentena, valida o manifest e grava a proposta e
as checagens em SQLite. Bundles `binary` e `none` podem chegar a `checked`; os
resolvers de dependências Deno/npm/uv ainda estão pendentes e falham explicitamente.
O smoke de processos usa sandbox, estado descartável, nenhuma rede/modelo e
honeytokens. Grants absolutos/`~/` não são concedidos ao código em verificação.
O resultado imprime hashes e diretórios ignorados. Não há promoção ou ativação por esse comando.

`init --first-party` será integrado ao pipeline de instalação em M0.5. Atualmente
ele retorna um erro antes de alterar arquivos. `serve` ainda não está implementado.

## Verificar

```sh
cd core
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Os testes usam diretórios temporários, chaves falsas e endpoints locais; não
precisam de chaves de modelo nem de rede externa. Testes reais de sandbox devem
rodar no terminal do host ou na CI Ubuntu 22.04 x86-64. Aninhamento de namespaces
pode impedir sua execução dentro de outra sandbox; nenhuma proteção é desativada.

A CI também inclui um container Fedora 44 para build e testes que não criam
sandboxes reais. A versão corresponde à [release estável do COSMIC Atomic](https://fedoraproject.org/atomic-desktops/cosmic/download/)
consultada em 2026-10-17. O gate de release exige todos os critérios de aceitação
na máquina Fedora COSMIC Atomic do usuário, com data, versão do SO e commit
registrados. Nenhuma validação Linux foi concluída nesta entrega de migração.

Veja o [andamento](docs/implementation.md), a [verificação](docs/verification.md) e
as [pendências do arquiteto](docs/architect-pending.md).
