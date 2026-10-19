# 12 — Administração de runtimes, atualização e rollback

Contrato do **M0.9**, aprovado no ADR-048 (ARQ-030). Não autoriza implementação
antecipada, novas origens de extensão, atualização do core por UI, nem métodos de
manutenção no Kernel Protocol/MCP/surfaces. Reutiliza posse do home, sandbox,
propostas, revisão de permissões e journal recuperável; não inventa propostas para
rollback ou runtime. A numeração da futura migração será a próxima disponível no
M0.9; este documento define seu conteúdo, sem fornecer implementação SQL.

## Transporte e autoridade

Herdar do [admin](02-core.md#canal-administrativo-mínimo) identidade por UID, socket
privado, JSON-RPC estrito, frame de 16 MiB, IDs e exclusão de logs brutos. Herdar os
erros/effect e deadlines do [ADR-045](02-core.md#mutações-administrativas-do-m05).
Todos os campos indicados são exatos, incluindo objetos aninhados; `?` significa
omissão, não null, salvo null explícito. ULIDs são canônicos, hashes são
`sha256:<64 hex minúsculos>`. Não aceitar paths de download, actor, callbacks,
comandos, fontes, URLs ou credenciais escolhidos pelo cliente.

| Método | Params | Result |
|---|---|---|
| `runtime.list` | `{}` | `{schema:1, runtimes:RuntimeSummary[]}` |
| `update.prepare` | `{request:Request}` | `{schema:1, plan_id:string}` |
| `update.list` | `{before?:string, limit?:integer}` | `{schema:1, plans:PlanSummary[], next_before:string ou null}` |
| `update.status` | `{plan_id:string}` | `PlanStatus` |
| `update.decision` | `{plan_id:string, nonce:string, review_hash:string, decision:"approve" ou "reject", items:"all_passing" ou string[]}` | `{schema:1, plan_id:string, state:"approved" ou "rejected", selected:string[]}` |
| `update.apply` | `{plan_id:string}` | `{schema:1, plan_id:string, operation_id:string}` |
| `login.issue` | `{}` | `{schema:1, url:string, expires_in_seconds:600}` |

`RuntimeSummary = {name, active, versions:[{key, version}]}`; nomes/chaves/versões
são strings. `active` é chave ou null para runtime configurado ainda não instalado. Em versions, version é a versão humana
do runtime (source.version para Python; chave de versão para Node/uv).
Ordenar nomes e chaves por bytes UTF-8. A consulta não executa downloads, checks,
reconciliação ou migração; sob gate/snapshot validado, qualquer journal prepared
retorna recovery_required. Não confundir presença no lock com saúde do processo.

`PlanSummary = {plan_id, state, request_kind, operation_id}`; último campo é string
ou null. `update.list` ordena pelo ID monotônico do evento de criação, descendente;
`before` é plan_id existente usado como cursor exclusivo, não timestamp. Limit
1–100, default 20; next_before é último plan_id da página quando há mais, ou null.
Somente planos deste home, sem nonce ou revisão nessa listagem.

`Request` é a união fechada:

- `{kind:"ext.rollback", ext_id:string, to?:string}`;
- `{kind:"runtime.rollback", name:string}`;
- `{kind:"runtime.update", name?:string}` (ausente: todos os runtimes configurados);
- `{kind:"runtime.check", name?:string}` (integridade e smoke do estado atual);
- `{kind:"update", targets:"all" ou Target[]}`;
- `{kind:"update.check"}` (descoberta de novidades, sem ativação);
- `{kind:"batch.rollback", batch_id:string}`.

`Target = {kind:"runtime" ou "extension", id:string}`. Arrays não vazios, sem
repetidos, nomes existentes; unknown/ausente é not_found. Update geral só considera
entradas já instaladas: builtin do binário em execução e local com origem privada
registrada, além de runtimes configurados. Sem origem local registrada, reportar
source_unavailable no item, sem inferir path do workspace. Primeira instalação de
extensão continua ext.install/init; primeira instalação de runtime é runtime.update
explícito ou bootstrap do init. Check automático usa update.check e só notifica.

## Planos e revisão

`prepare` cria plano e `update.plan_created` duráveis antes de abrir fontes/fazer
rede; responde após esse commit e continua trabalho longo sem depender do socket.
Estados: preparing → checked/failed; checked → approved/rejected; approved →
applying → applied/aborted. Falha de check de item pode coexistir com plano checked;
failed é falha estrutural que impede revisão completa. Check-only termina checked
ou failed, mas nunca admite decision/apply. Reinício transforma preparing em failed
(reason interrupted), sem retomar downloads/checks. Checked/approved persistem;
applying é recuperado pelo journal. Nenhuma consulta aplica ou confirma algo.

`PlanStatus` contém exatamente:

```
{schema:1, plan_id, request, state, reason:string|null,
 review:Review|null, review_hash:string|null, nonce:string|null,
 selected:string[], operation:{operation_id,state:"prepared"|"committed"|"aborted"}|null}
```

Revisão existe em checked e estados posteriores; em preparing/failed é null.
Nonce aleatório de 128 bits, codificado em 32 hex minúsculos, somente em checked de
plano mutante; só guardar/expor por canal confiável. Review/hash são imutáveis
após checked. `review_hash = sha256(JCS(Review))`. Status devolve revisão histórica,
não a recalcula contra fontes atuais; revalidar base na decisão e aplicação.
Snapshots privados de lock/config não vão para wire nem eventos.

```
Review = {schema:1, base_hash, config_hash, items:Item[], groups:string[][],
          core_notice:{version:string}|null}
Item = {item_id, kind:"runtime"|"extension", id,
        action:"install"|"update"|"rollback"|"check",
        from:string|null, to:string|null,
        before:Record|null, after:Record|null,
        proposal_id:string|null,
        checks:[{name,passed:boolean,blocking:boolean,reason:string|null}],
        eligible:boolean, permission_change:"none"|"reduced"|"expanded"|"unknown",
        omitted_fs:string[]}
```

Strings não anotadas têm tipo string. Record é a projeção de revisão:
`{record:LockVersion, manifest:object|null, tools:object[], packages:Package[],
overrides:object|null}`. LockVersion usa o schema da versão no lock para o kind,
mas projeta source sem caminho local privado: conserva kind e metadados remotos
já previstos, omitindo path de origem local. Path relativo imutável no store/runtime
continua permitido. Para runtime, manifest/overrides são null, tools/packages são [].
Para extensão, manifest normalizado, catálogo tools, packages
`{ecosystem,name,version}` e overrides seguem os contratos ADRs 035/037 e schema
de extensão. Tanto before quanto after carregam esses dados: a revisão deve poder
comparar permissões/classes anteriores e novas, não somente números de versão.
Em candidatos novos install/update, record.approved é null na revisão: aprovação
não é fabricada antes do consentimento. O commit da decisão fixa actor user e
timestamp no evento; ao construir after_lock, usar essa decisão durável para os
registros novos. Rollback e chaves já existentes conservam approved original.
Essas projeções não acrescentam campos ao registro persistido no lock. Não aceitar
campos adicionais nem expor config livre, paths de staging ou valores de segredos.
Review de update.check pode ter itens sem candidato verificado (`after:null`,
`eligible:false`, `permission_change:"unknown"`); core_notice é apenas aviso, nunca
item selecionável nem binário baixado como efeito deste método.

`base_hash` cobre JCS do lock reconciliado completo; conservar também seus bytes
exatos no plano. `config_hash` cobre JCS das tabelas runtimes/update relevantes,
políticas de verificação e raízes usadas no smoke, excluindo valores de segredos.
Conservar snapshot privado dessas entradas. Mudança em qualquer uma dessas bases
até apply retorna stale_base, sem rebase silencioso; criar plano novo. Estado de
crash/flags/kv não faz parte desse hash e nunca é restaurado pelo plano.

Preparar runtimes antes de propostas, com todas as checagens das fases atuais.
Staging é privado e atribuído ao plan_id (`runtime/.staging/<plan_id>/`); cada item
usa subdiretório próprio. Publicação/limpeza só manipulam caminhos desse plano ou
operation_id, por descritores validados, sem seguir links. Preparos concorrentes
nunca compartilham staging só por nome/versão; falha não autoriza limpar outro plano.
Fixar bytes, hashes, catálogo, base, dependências e limitações do smoke. Propostas
criadas pelo plano obedecem ADRs 035/036/037, e permanecem checked até decisão humana.
Permissões efetivas de update preservam overrides anteriores quando válidos; se
não puderem ser preservados sem interpretação nova, item não é eligible. Ajuste
manual de overrides usa nova proposta/revisão, não edição de plano aprovado.
Nenhum check executa fora do sandbox por ser runtime, rollback ou bundle aprovado.

**Combinações.** `groups` particiona todos os item_id em grupos não vazios/disjuntos,
ordenados. Itens que compartilham runtime candidato ou cuja verificação depende
um do outro ficam no mesmo grupo (componentes conexos da dependência). Smoke cobre
todos os consumidores ativos, inclusive disabled, e as versões candidatas do grupo,
contra a combinação exata revisada. Seleção deve incluir grupos inteiros; não
reutilizar resultado de smoke de outra combinação. Para atualizar só parte de um
grupo, preparar outro plano com targets explícitos e verificar contra o restante
atual. Concorrência muda base e exige novo plano. Isso evita publicar extensão
verificada com runtime diferente daquele efetivamente selecionado.

**Decisão.** CLI exibe revisão completa com controles/ANSI escapados e pede
confirmação no TTY; UI usa modal confiável. `--yes` de update seleciona all_passing:
apenas grupos cujos itens são eligible, todos os checks bloqueantes passaram e
permission_change é none/reduced. Unknown/expanded exige seleção explícita humana;
check bloqueante nunca pode ser dispensado. Conjunto vazio dá nothing_to_apply.
Comparar permissões, classes de tools e demais capacidades efetivas dos manifestos,
não somente números de versão; mudança não comprovadamente restritiva é unknown.
Runtime exige verificação/hash e não concede novos acessos às extensões; a revisão
expõe que o código executável muda. Rollbacks de versão antiga com permissões
maiores também exigem confirmação explícita.

Approve exige nonce vigente, hash exato, base atual, seleção válida; fixa selected,
registra user e aprova propostas selecionadas com seus overrides na mesma transação.
Rejeitar usa items:[], consome nonce e registra rejected, sem alterar propostas
alheias. Exige hash/nonce, mas não exige base ainda atual, pois Review está persistido.
Propostas não selecionadas são rejeitadas atomicamente ao decidir, sem permanecerem
como aprovações reaproveitáveis. Replay dá invalid_state, sem outro evento. Propostas
ligadas a plano não podem ser decididas/promovidas via ext.install/proposal geral;
a associação impede contornar seleção/revisão do lote, inclusive depois de abort.

`apply` só aceita approved, confere integridade das árvores fixadas, bases e decisão,
e grava journal prepared antes de responder operation_id. O worker conclui sem
socket. Prepared/committed repetidos devolvem o mesmo ID; não criam worker nem
reativam versões posteriormente substituídas. Aborted é terminal para esse plano:
novo consentimento requer novo plano, sem reabrir proposta antiga. CLI termina com
sucesso só em applied/committed; retomada `fictor update --resume <plan_id>` consulta
e pede confirmação atual para apply de approved. Não aceita --yes/--core/targets
junto com --resume. Lista/status permitem recuperar IDs após resposta perdida.

## Journal e formato persistido

Migração futura aditiva, com backup, FULL e user_version novo antes de handlers.
Não modificar migrações antigas. Binário M0.5 recusa banco mais novo. Tabelas lógicas
(obrigatórias; índices adicionais são internos):

| Tabela | Campos e restrições |
|---|---|
| `maintenance_plans` | plan_id TEXT PK; created_event_id TEXT UNIQUE FK events; request TEXT JSON; state TEXT no enum acima; reason TEXT nullable; base_lock TEXT nullable somente antes de checked; base_hash/config_hash TEXT nullable antes de checked; config_snapshot TEXT nullable; review TEXT nullable; review_hash TEXT nullable; nonce TEXT nullable; selected TEXT JSON array (default []); created_at/updated_at INTEGER Unix ms. Snapshots/review/seleção aprovados imutáveis. |
| `maintenance_plan_proposals` | plan_id FK plans; proposal_id FK proposals UNIQUE; item_id TEXT; PK(plan_id,item_id). Sem associação de rollback/runtime a proposta fictícia. |
| `maintenance_intents` | operation_id TEXT PK; plan_id FK plans UNIQUE; prepared_event_id FK events UNIQUE; before_lock TEXT nullable no bootstrap; after_lock TEXT; ambos snapshots exatos. before_hash TEXT nullable se before_lock null; after_hash TEXT; SHA256 dos bytes; state prepared/committed/aborted; created_at/updated_at INTEGER Unix ms. No máximo uma prepared nesta tabela. |

Dados JSON obedecem os tipos deste documento; rejeitar extras/duplicatas/IDs e
hashes inválidos ao ler. Null lock anterior só no bootstrap de init, não em home
já inicializado; depois de checked base_lock pode ser null apenas nesse bootstrap.
Nonce só em checked de plano mutante; consumi-lo no commit de decisão. Eventos e
linhas nascem juntos na transação, sem FK temporariamente pendente após commit.

Há **uma exclusão global** entre maintenance_intents e promotion_intents: writer
verifica ambas antes de inserir prepared; gate do instalador cobre todo o protocolo.
Constraints por tabela não bastam. Mais de uma pendência entre tabelas é corrupção,
não escolher por data. Reconciliar ambas antes de despacho, listagem confirmada ou
qualquer mutação do lock; consultas read-only devolvem recovery_required, sem
reconciliar por conta própria. Status de plano pode observar intenção em andamento
pelo snapshot privado do journal, sem esperar pelo gate ou ler lock candidato.

1. Sob gate, revalidar e persistir intenção prepared + update.operation_prepared,
   mudar plano approved→applying numa única transação. Snapshots exatos anterior e
   posterior diferem; o posterior conserva tudo que não pertence à seleção.
2. Publicar bytes verificados em diretórios imutáveis com fsync, sem sobrescrever
   chaves existentes. Suspender admissões afetadas, inclusive consumidores dos
   runtimes; escrever lock temporário, fsync, rename e fsync do pai como ADR-036.
3. Em uma transação FULL: intenção committed, plano applied, propostas selecionadas
   approved→promoted, seus ext.promoted, eventos de runtime/rollback e update.batch
   quando aplicável. Nenhuma parte é sucesso isolado. Não criar promotion_intents
   por proposta dentro do lote.
4. Publicar catálogo/runtime em memória e iniciar hot swap; depois liberar admissões.
   Chamadas antigas terminam sob identidades antigas. Falha de limpeza não desfaz
   commit; falha de publicação conserva admissões bloqueadas até recuperação.

No boot, após ADR-038: lock idêntico a before aborta intenção/plano com evento;
lock idêntico a after e árvores/catálogos íntegros conclui passo 3 uma vez; terceiro
estado ou prova incompleta gera recovery_conflict, retém recursos e bloqueia.
Não repetir checks/reabrir origens, compensar parcialmente ou restaurar lock antigo
por adivinhação. Propostas de lote aborted conservam approved histórico, mas ficam
vinculadas ao plano terminal e não podem ser reaproveitadas.

Para status/deduplicação de propostas associadas, projetar a intenção de manutenção
como promotion `{operation_id,state}` no snapshot já existente. Até apply é null.
Sua ordem é prepared_event_id; associação explícita substitui o ext.promotion_prepared
individual. Não exigir evento preparado fictício nem linha em promotion_intents.
Mesma proposta não pode ter caminhos simultâneos nos dois journals. Valer as provas
de estado/evento e o piso monotônico do ADR-047. Propostas normais/legadas mantêm seu
contrato. `ext.install.promote` rejeita proposta associada; consultas podem mostrar
seu estado, sem autorizar outra publicação. As regras antigas que exigem que
todas as propostas promoted apareçam em promotion_intents não se aplicam a essa
associação explícita, mas a ausência dos dois journals continua tratada pelo
contrato de legado do ADR-047.

## Rollback, lotes e retenção

Rollback muda seleção de código, nunca kv, dados, sessões, flags, grants, crash
recovery ou efeitos externos. Preservar enabled e os metadados aprovados imutáveis.
Conferir integridade completa e compatibilidade/smoke com runtimes e consumidores
atuais antes de oferecer a revisão. Falha invalida o grupo/lote inteiro.

**Anterior.** Sem --to, procurar a última transição committed que mudou active da
extensão/runtime, cujo resultado active e metadados executáveis ainda correspondem
ao estado atual; se a última transição divergir, falhar com invalid_snapshot sem
procurar uma transição mais antiga conveniente. Ordenar pelo ID monotônico de seu evento de preparação (journal
normal ou manutenção). Alvo é a chave anterior registrada nessa transição, que
precisa existir e diferir da atual. Rollback também conta como transição: o próximo
rollback pode voltar à seleção que acabou de sair. Não ordenar por SemVer, horário,
inventário ou aprovação. Sem predecessor demonstrável, no_previous_version; para
extensão, --to permite selecionar chave retida explícita. Runtime sem histórico
comprovável não inventa predecessor. Instalação inicial não tem anterior.

**Lote.** batch_id é operation_id de update geral ou runtime.update committed; update.batch
identifica exatamente a seleção dessas operações. Runtime.update avulso permite
reversão explícita quando todos os itens têm predecessor.
Batch.rollback exige lote íntegro, committed e todos os predecessores existentes;
lote que instalou runtime antes ausente retorna no_previous_version (não remove
runtime nem extensão implicitamente). Nunca desfazer lote parcialmente: em batch.rollback, approve exige selected igual
a todos os itens do lote original, independentemente de groups ou all_passing.
Qualquer seleção própria/subconjunto é selection_invalid; rejeição usa [].

Exigir que active e registro executável atual de cada item coincidam com o after do
lote original; se diferirem, stale_base. Preservar enabled e inventário atual; montar
novo lock a partir do atual, trocando somente active dos itens do lote. Não copiar
o snapshot antigo inteiro. Validar também consumidores fora do lote contra os
runtimes resultantes. O novo plano fixa esse conjunto e a base completa, impedindo
corrida após revisão. Rollback confirmado grava update.batch_rolled_back com
original_batch_id e novo operation_id; não reescreve lote original. Nova tentativa
sobre lote já revertido retorna already_rolled_back, não desfaz mudanças posteriores.

**Retenção.** Três versões de runtime é mínimo, não autorização de apagar versão
referenciada. Manter pins para ativa, instâncias/draining/cleanup_failed, planos não
terminais, journals prepared e predecessores de lotes com rollback oferecido. Na
Fase 0 a oferta nasce no commit de todo lote com predecessor para todos os itens,
independentemente de listagem ou exibição na UI; os pins nascem nesse commit.
Não há expiração silenciosa dessa oferta: reter versões adicionais quando
necessário, inclusive as de extensão; coleta avançada pertence à Fase 2. Histórico
terminal sem pin não exige reler todos os bundles antigos em cada consulta: validar
auditoria/snapshots históricos; árvores apenas para ativos, planos/aplicação ou
recovery. Bytes de alvo ausentes/corrompidos recusam rollback, nunca redownload sem
nova revisão. Não limpar por número de entradas enquanto houver referência viva.

## Eventos e compatibilidade

Eventos na sessão sys, transacionados com o estado que descrevem. Campos abaixo
são exatos para as novas operações; strings de erro são códigos, nunca texto bruto.

| Kind | Actor | Payload |
|---|---|---|
| update.plan_created | core | `{plan_id, request_kind}` |
| update.plan_checked | core | `{plan_id, review_hash}` |
| update.plan_failed | core | `{plan_id, reason}` |
| update.plan_decided | user | `{plan_id, decision, review_hash, selected:string[]}` |
| update.operation_prepared | core | `{operation_id, plan_id, before_hash:string ou null, after_hash}` |
| update.operation_aborted | core | `{operation_id, plan_id, reason}` |
| update.operation_committed | core | `{operation_id, plan_id}` |
| update.batch | user | `{batch_id, items:[{kind:"runtime" ou "extension", id, from:string ou null, to:string}]}` |
| update.batch_rolled_back | user | `{operation_id, original_batch_id}` |
| ext.rolled_back | user | `{operation_id, ext_id, from, key}` |
| runtime.installed | user | `{operation_id, name, version}` |
| runtime.activated, runtime.rolled_back | user | `{operation_id, name, version, from:string ou null}` |

Para lote com propostas, ext.promoted conserva o payload existente, com operation_id
da manutenção e proposal_id de cada item. Não emitir ext.promotion_prepared nem
ext.promotion_aborted individuais nesse caminho. runtime.installed só para chave
nova, runtime.activated para install/update; rollback emite runtime.rolled_back.
Version nos eventos runtime é a chave completa do lock (inclui build para Python).
Payloads não contêm nonce, tokens, URLs privadas ou snapshots. Razão de interrupção
antes/depois de prepared é interrupted; erro de integridade é integrity_failed.

Cada intenção tem exatamente um update.operation_prepared; prepared não tem
evento terminal, committed tem exatamente um update.operation_committed, aborted
tem exatamente um update.operation_aborted. Não admitir terminais de ambos os
tipos, terminal anterior à preparação ou evento de operação sem intenção.
Associação por operation_id/plan_id, hashes da preparação e seleção imutável do
plano deve coincidir; cada evento de item/proposta/batch deve corresponder exatamente
a essa seleção, sem extras ou omissões. Planos applying/applied/aborted correspondem
respectivamente a prepared/committed/aborted; demais estados não têm intenção.
Ausência/duplicidade/divergência retorna invalid_snapshot/recovery_conflict sem
reconstruir eventos.

Preparação/conclusão usam IDs monotônicos, como ADR-047; validar evento único e
coerente com plano/journal/seleção, incluindo correspondência das propostas e
sequência de estados. A consulta lê o estado persistido numa transação; não tenta
reconstruir revisão faltante a partir de fontes atuais. Legacy não ganha eventos
retroativos: a migração cria tabelas vazias e conserva todos os journals/eventos
antigos. Promoções ADR-036 íntegras oferecem predecessor; rollback/runtime/update
legados sem snapshots não comprovam anterior. Eventos antigos sem operation_id
permanecem legíveis e não são corrupção por terem schema anterior.

## Runtimes, Python e bootstrap

Node/uv usam fontes e checksum do contrato existente, extração e --version no
sandbox, sem segredos. Runtime declarado aprovado não autoriza ampliar montagens,
rede ou escapes. Chave de versão é imutável: mesmo nome/versão com hash diferente
é integrity_failed, nunca sobrescrita. Conferir identidade e aprovações das entradas preservadas; parâmetros não podem
mudar fonte do runtime. A revisão fixa URL resolvida e hashes no
registro de origem; redirects continuam limitados à allowlist da fonte.

**Árvore de runtime.** Diferente de bundles de extensão, arquivos de runtime podem
ter symlinks internos verificados. Novos registros incluem
`tree_hash_kind:"runtime-v1"`. O hash é `sha256:` seguido do SHA256 de
`JCS({schema:1,entries:[...]})`. Enumerar sem seguir symlinks, sem incluir a raiz,
ordenando pelo path relativo em bytes UTF-8. Cada entrada é exatamente um de:
`{path,type:"file",executable:boolean,sha256:string}`, `{path,type:"dir"}` ou
`{path,type:"symlink",target:string}`. Sha256 de arquivo usa o formato sha256:hex;
executable indica qualquer bit de execução no artefato validado, normalizado na
publicação a 0555 ou 0444; diretórios finais 0555. UID/mtime não entram no hash.
Target é o texto literal UTF-8 do link, não os bytes do destino.

Paths são relativos canônicos, sem NUL/controles/componentes vazios/. ou ..;
links podem conter .. somente quando toda resolução permanece dentro da árvore.
Recusar links absolutos, magic links, ciclos, destinos ausentes, hardlinks, tipos
especiais e qualquer entrada que tente escrever atravessando um symlink. Fixar e
validar árvore e resolução por descritores, incluindo symlinks encadeados; destino
final precisa ser arquivo/diretório da mesma árvore. Extração e validação precedem
qualquer execução. Bin pode ser symlink interno validado; bin_sha256 cobre bytes
do arquivo executável final, e tree_hash protege também nomes/links/modes lógicos.

Legado sem tree_hash_kind mantém algoritmo de bundle apenas se a árvore não tiver
symlinks; nunca reinterpretar hash antigo como runtime-v1 ou atualizar o lock por
leitura. Se não puder provar integridade, falhar e exigir atualização/revisão nova.
Nenhuma dessas permissões de link passa para bundles ou controles privados do core.

Python é entrada explícita `runtimes.python` no lock com active/versions e os mesmos
hashes/bin/path/source/approved dos outros runtimes. Acrescentar à configuração a
fonte `source = "uv-python"`, `version = "stable"` ou seletor major.minor CPython.
O catálogo é o JSON oficial
`https://raw.githubusercontent.com/astral-sh/uv/<tag>/crates/uv-python-managed/download-metadata.json`;
somente se esse path retornar 404, usar o path histórico
`crates/uv-python/download-metadata.json` sob o mesmo host/repo/tag. Outros erros
não provocam descoberta ou fallback. São dois paths fixos, sem busca genérica.
A tag é exatamente igual ao da release uv oficial verificada (`astral-sh/uv`)
selecionada no plano ou já ativa. Essas duas URLs/paths são exceções nominais de download
de metadados, não uma allowlist genérica para raw.githubusercontent.com. Não usar
main/latest, metadata da CLI local, uv do sistema ou catálogo de outra versão como
fallback. Recusa de tag/catalog ausente ou formato desconhecido é source_unavailable.
Fixar bytes e SHA256 do catálogo no plano, sem buscá-lo novamente em apply; guardar
URL/hash e uv_key no source da versão Python. A confiança é a da origem HTTPS
configurada, como checksums de runtime na Fase 0; isso não afirma assinatura.
Limitar catálogo a 16 MiB e aceitar somente JSON sem chaves duplicadas.
Filtrar entradas com name="cpython", os="linux", libc="gnu",
arch={family:"x86_64",variant:null}, variant=null e prerelease=""; major/minor/patch
são inteiros e build é data válida YYYYMMDD. Selecionar maior versão SemVer estável
compatível com o seletor (stable aceita todas as versões estáveis; major.minor
restringe a série), Linux x86-64 glibc, sem builds debug/free-threaded;
empate escolhe maior identificador de build do catálogo. Se catálogo não fornecer
ordem inequívoca ou SHA256 verificável, falhar com source_unavailable. A chave inclui
versão e build, não apenas major.minor. Usar path `runtime/python/<chave>` e
`bin` relativo ao diretório extraído. Source usa exatamente
`{kind:"uv-python", uv_key, catalog_url, catalog_sha256, version, build, url, sha256}`
(strings); version é a
versão completa CPython e build é o identificador do catálogo. Checksum é sha256
no formato deste documento. O init inclui a configuração de python com seletor
stable, sem instalar Python até necessidade/consentimento explícitos. Sem descoberta por PATH, .python-version, ambiente do
usuário, índice arbitrário ou download automático no spawn/dependências.

Downloads do Python usam somente o artefato do catálogo fixado, hosts GitHub já
permitidos para runtime e checksum antes de executar; URL fora deles é recusada.
Extração/hash/bin/smoke/consentimento seguem o mesmo plano. uv no preparo de pacotes
usa esse interpretador explicitamente e downloads de Python desativados. Capturar
config/version/catalog como base da revisão; não deixar o uv escolher nova versão
no momento da instalação. Não instalar executável no PATH ou HOME do host.

Quando uma proposta Python precisar de uv/python ausente, falhar a proposta antes
de dependências com `ext.failed.reason = "check:runtime_required"` e check bloqueante
`{name:"runtime", passed:false, blocking:true, detail:"check:runtime_required"}`.
Não deixar worker aguardando decisão inexistente em ext.install.status. A CLI
informa a necessidade de `fictor runtime update python`; o humano prepara/aprova esse
plano (inclui uv ausente no mesmo grupo) e depois cria nova proposta de extensão,
com nova base. Não retomar a proposta failed nem aplicar runtime automaticamente
ao receber código. Ausência de Node em proposta Node segue a mesma regra, indicando
runtime update node. O init usa o mesmo protocolo interno
sob posse exclusiva: baixar/verificar e mostrar revisão de Node e builtins antes
da confirmação única. Não precisa de socket/servidor temporário; após crash,
reconciliar antes de continuar e nunca repetir consentimento como se ainda valesse
para conteúdo/base novos. Migração/bootstrapping são exclusivos de init/serve;
comandos offline usuais continuam sem migração implícita.

## Login e atualização do executável

`login.issue` só existe no admin local, nunca WS/UI/surface/Kernel. Requer listener
do shell pronto; a URL é construída pelo core para http://127.0.0.1:porta/login,
com token CSPRNG de 256 bits em base64url sem padding (43 caracteres). Token vale
600 s pelo relógio monotônico do processo; é consumido atomicamente na primeira
validação bem-sucedida e trocado pelo cookie conforme spec de segurança. A rota
/login remove o token da URL por redirect para a raiz, aplica Cache-Control:
no-store e Referrer-Policy: no-referrer; logs de acesso não registram query/token. Duas
requisições concorrentes não consomem o mesmo token duas vezes. Host errado não
consome token. Reinício invalida todos os tokens ainda não usados; não persistir
URL/token em eventos, blobs, journal ou logs. Manter somente digest em memória;
o token bruto sai na resposta e a CLI o exibe explicitamente, sem log de diagnóstico.
Vários tokens podem coexistir, sem revogar cookies existentes. EOF não revoga o
token emitido nem gera retry automático; nova invocação humana emite outro.
`serve` usa o mesmo emissor e exibe a URL uma vez somente em execução interativa
com stdout TTY; serviço/headless não emite token no boot nem o envia ao journal.
Nesse caso o usuário executa fictor login explicitamente. --open exige execução
interativa; não criar URL secreta implicitamente no serviço.

`update --core` não entra nos planos, journal de lock ou métodos administrativos.
É rotina exclusiva da CLI, para executável Linux x86-64 no caminho instalado
validado, sem seguir symlink/aceitar path de cliente. Exige diretório/executável do
usuário graváveis; instalação de sistema sem permissão falha, sem sudo/elevação
implícita. Só a fonte configurada e seu checksum são usados; não executar o novo
binário para validar antes de instalá-lo. Sem comando de shell vindo da release.

Para evitar duas renames com janela sem executável: baixar para temporário no mesmo
diretório, validar checksum e formato/alvo; fsync. Copiar o executável atual para
novo temporário, fsync e publicar atomicamente como fictor.prev, fsync do pai;
por último rename atômico do candidato sobre o executável atual e fsync do pai.
Serializar esse procedimento por lock exclusivo dedicado no diretório, possuído
pela CLI; nunca substituir paths fora dele. Revalidar identidade do executável
atual antes da troca. Crash deixa o nome principal antigo ou novo e a cópia anterior
íntegra antes da troca; não retomar download/instalação implicitamente. Execução
anterior permanece até reinício humano. A troca não migra banco; ao reiniciar valem
backup/guarda de versão. Restaurar fictor.prev não autoriza abrir banco mais novo.
`--core` é mutuamente exclusivo com --yes/--resume e não aplica runtimes/extensões.
A CLI apresenta versão/hash e exige confirmação TTY antes da substituição.

## CLI, UI e falhas

Comandos ext rollback/runtime update/runtime rollback/update/update rollback mapeiam
para prepare → status → decision → apply → status; não são RPCs de mutação direta.
Runtime check e update.check param em status. Somente ext rollback mantém caminho
offline (além de init e comandos já existentes): posse exclusiva, schema atual,
reconciliação de ambos journals e mesmo protocolo interno. Outros comandos exigem
core ativo; --core é a exceção local acima. Consultas runtime.list também exigem
core ativo neste marco. Nenhuma falha online permite fallback offline.

A UI confiável usa os mesmos nomes update.prepare/list/status/decision/apply e
runtime.list como `type` WS, com os mesmos campos e resultados no ack do spec08;
sem envelope JSON-RPC dentro do WS. Exige cookie/Origin e nonce de decisão. Botões
rollback apenas iniciam prepare; não há handler antigo que altere active só com
ext_id/name/batch_id. Atualização de core e login não são encaminháveis via WS.

Domínio herda reason/effect do ADR-045 e acrescenta no_previous_version,
already_rolled_back, nothing_to_apply, selection_invalid, runtime_required,
source_unavailable, recovery_conflict, not_ready. Erros de item usam esses códigos
ou check:failed/integrity_failed/interrupted; sem texto de subprocesso/paths privados.
`too_large` impede revisão/decisão, sem truncamento para aprovação. Params inválidos
falham antes do receipt; falha posterior pode ter plano durável. effect:none/busy
nunca deixam job mutante capaz de executar depois. Check-only pode criar receipt,
mas nunca muda seleção de código. Consultas são effect:none. Não repetir efeitos
por EOF/timeout nem inferir atomicidade de filesystem e SQLite sem o journal.


Fontes para a integração uv (consultadas em 2026-10-18):
[catálogo oficial histórico](https://raw.githubusercontent.com/astral-sh/uv/0.12.12/crates/uv-python/download-metadata.json),
[catálogo após reorganização](https://raw.githubusercontent.com/astral-sh/uv/0.13.1/crates/uv-python-managed/download-metadata.json) e [documentação de versões Python do uv](https://docs.astral.sh/uv/concepts/python-versions/).
A versão do exemplo não fixa a versão do runtime no produto; o plano fixa a release
selecionada e seu catálogo antes da decisão humana.
