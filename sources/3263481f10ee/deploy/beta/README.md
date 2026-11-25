# Operação do piloto Vulnetic

O cadastro permanece fechado até o operador preencher a lista de convites. O
limite é cinco contas. A configuração individual do compose geral não substitui
`docker-compose.beta.yml`, que exige SaaS e o pool RLS.

## Preparar o pacote

No checkout Windows, com Git, Go 1.26.3, Node 22 e npm no PATH:

```powershell
./scripts/build-beta.ps1
```

O script exige o código commitado, instala as dependências do lockfile, valida
TypeScript, exporta o frontend e compila a plataforma Windows/Linux amd64, agentes Linux amd64/arm64 e o executor Windows amd64 em terminal. O ZIP sai em
`dist/beta/`, com a revisão e hashes em `release-manifest.json`, além do checksum
do próprio ZIP. Não contém banco, chaves, configurações privadas ou contas de
homologação. Os testes locais obrigatorios devem passar para esta revisao antes da instalacao; esta entrega nao usa CI externa.

Para compilar Linux diretamente do código, use `./build.sh --target linux/amd64`
e copie o executável gerado para `dist/amd64/vulnetic` antes de montar o compose.
Os comandos restantes deste guia partem da raiz do pacote extraído ou checkout.

## Instalar no servidor da plataforma

Use um servidor Linux amd64 separado das VPS dos clientes. Instale Docker com
Compose, Python 3, logrotate e o proxy HTTPS do operador. Nunca cadastre o próprio
servidor da plataforma como executor de cliente.

1. Extraia o pacote em `/opt/vulnetic`. Confira o SHA-256 recebido e o manifesto.
2. Copie `deploy/beta/.env.example` para `.env.beta`. Gere duas senhas hexadecimais
   independentes e defina `VULNETIC_PUBLIC_URL` com a URL HTTPS definitiva e mantenha
   `VULNETIC_SIGNUP_ALLOWLIST` vazio enquanto o cadastro
   estiver fechado. Proteja o arquivo com `chmod 600 .env.beta`.
3. Para homologação local, valide e prepare somente este projeto. A publicação
   usa o gateway e o overlay descritos em **Proteção do servidor** abaixo:

```sh
docker compose --env-file .env.beta -f docker-compose.beta.yml config --quiet
docker compose --env-file .env.beta -f docker-compose.beta.yml build app
docker compose --env-file .env.beta -f docker-compose.beta.yml up -d postgres
docker compose --env-file .env.beta -f docker-compose.beta.yml run --rm prepare
docker compose --env-file .env.beta -f docker-compose.beta.yml up -d app
curl --fail http://127.0.0.1:8795/api/auth/status
```

O banco não publica portas. O aplicativo escuta no loopback e reinicia com o
Docker (`restart: unless-stopped`). A imagem executa sem root, com filesystem
somente para leitura e estado persistente separado do executável.

4. Configure o domínio e certificado do proxy HTTPS para `127.0.0.1:8795`.
   Preserve os streams: desabilite buffering e use timeout de leitura superior
   a cinco minutos. Encaminhe Upgrade/Connection para WebSocket em `/agent/connect`.
   Valide login, streams, WebSocket e downloads pelo domínio.
5. Instale o monitor supervisionado:

```sh
sudo install -m 644 deploy/beta/vulnetic-monitor.service /etc/systemd/system/vulnetic-monitor.service
sudo install -m 644 deploy/beta/vulnetic-monitor.logrotate /etc/logrotate.d/vulnetic-monitor
sudo systemctl daemon-reload
sudo systemctl enable --now vulnetic-monitor
sudo systemctl status vulnetic-monitor
sudo journalctl -u vulnetic-monitor -f
```

A unidade usa `/opt/vulnetic`, `/usr/bin/docker` e `/usr/bin/python3`; ajuste
os caminhos se a instalação diferir. Ela lê os logs do compose pela entrada
padrão, reinicia após queda do coletor ou fechamento do stream e guarda métricas
em `/var/lib/vulnetic-operator/metrics.jsonl`. Logrotate limita os arquivos
retidos; os alertas ficam no journal do operador. Nenhuma mensagem externa é
enviada. Configure o destino externo somente quando for definido pelo operador.

6. Quando os convites forem autorizados, preencha a allowlist com os e-mails e
   recrie somente `app`; confirme o limite de cinco contas. Valide duas contas
   pelo navegador: agente temporário na VPS própria, perfil próprio, tarefa, prova, relatório e
   reteste. Captura de tráfego permanece indisponível neste beta.

## Backup, atualização e incidente

O volume `state` mantém `vault.key` e `jwt.key` fora do subdiretório `data`.
Preserve esse volume com o dump PostgreSQL, confira os hashes e ensaie a
restauração isolada antes da abertura. Não use `down -v` no piloto.

Antes de atualizar, pause as tarefas e faça backup. Instale somente a revisão
validada. Após atualizar, confira login, isolamento, agente, provas e o monitor.
Uma migração exige restaurar banco e estado do mesmo backup para reverter;
trocar apenas a imagem não reverte o banco.

Em incidente, pare somente o serviço `app` deste compose e preserve volumes e
logs. Não altere serviços das VPS dos clientes. A instalação pública só pode
ser liberada depois da validação do domínio, da restauração e dos convites.

## Homologação neste PC

O ambiente privado restaurado usa `vulnetic-newpc-postgres`, PostgreSQL 16 no
loopback `5433`, e as portas `8789` e `8791` para duas homologações. O launcher
local `INICIAR-BETA-NOVO-PC.ps1` inicia os serviços e o coletor, sem duplicá-lo.
Esse launcher depende dos dados privados locais e não acompanha o pacote.
Credenciais e fixtures ficam fora do Git. Não reutilize esses dados no piloto.

## Agentes temporários de execução

### Windows amd64 — terminal temporário

Selecione Windows ao criar o executor. Execute o comando em PowerShell 64 bits,
sem administrador, numa VM/VPS dedicada ou conta previamente restrita. O comando
mostra destino, versão, permissões e prazo; confere HTTPS, SHA-256 e identidade
do produto e informa o editor não verificado se não houver assinatura. Ao executar
o comando, conecta diretamente após essas verificações, sem pedir confirmação
digitada. Assinatura inválida bloqueia a execução. Não desative o antivírus nem
crie exclusões para executar o arquivo.

Não são criados serviço, usuário, tarefa agendada ou inicialização automática.
Mantenha o terminal aberto. Reconexão de rede/plataforma preserva a identidade e
o prazo original enquanto o processo permanecer ativo. Ctrl+C, fechamento,
revogação ou expiração encerram o acesso e os processos dos comandos. Após
fechar o processo ou reiniciar Windows, gere uma nova autorização explicitamente.
Credenciais de execução ficam somente em memória; o arquivo privado de inscrição
é removido antes da conexão. Workspace e provas são preservados. O executor usa
as permissões do usuário atual; o diretório de trabalho não é uma sandbox Windows.
Python 3, ferramentas de teste e PATH precisam ser preparados pelo administrador
da VM. A captura de tráfego permanece indisponível neste beta.

O pacote inclui `dist/agents/windows-amd64.exe`, com metadados e manifesto
`asInvoker`. Teste o binário exato do pacote com o antivírus ativo antes de
publicar; um resultado local não garante aceitação por todos os produtos.

### Linux — serviço sem root

Em VPS executors, escolha um nome e validade de 3 horas, 24 horas, 3 dias ou 7 dias. O comando
usa uma inscrição de uso único, válida por 5 minutos. Ele baixa um binário Go
genérico, confere o checksum e habilita um serviço systemd temporário na VPS, que volta no boot até a expiração.
Não exige senha SSH, porta de entrada ou alteração de authorized_keys. O binário
não contém credenciais de conta ou provedor.

O agente usa HTTPS/WebSocket de saída e uma identidade efêmera por instalação.
A plataforma mantém somente hashes dos tokens, além da chave de autenticação
cifrada no vault. A identidade do agente é fixada na inscrição. Cada sessão de
execução é independente dentro da conexão da conta; não há execução local em
caso de falha. Há limite de três agentes conectados por conta.

Requisitos da VPS: Linux amd64/arm64, bash, Python 3, curl, sha256sum e systemd 250+ com systemd-creds. Execute o instalador como root (por exemplo após sudo -i). Ele cria/reutiliza somente a conta gerenciada `vulnetic-agent`, com senha bloqueada, shell nologin, grupo privado e nenhum grupo suplementar. Não concede sudo.

O serviço e todos os comandos executam como `vulnetic-agent`, sem capabilities e com NoNewPrivileges. O binário recusa UID root e grupos suplementares. Código, unidade e chave cifrada pertencem a root; o serviço pode escrever apenas no workspace `/var/lib/vulnetic-workspace`, no estado privado de sua instalação e em seu tmp privado. ProtectHome bloqueia os diretórios pessoais, incluindo /root. O agente não instala pacotes, não altera configuração do sistema e não ganha permissões extras para ferramentas de rede.

Durante a instalação, systemd-creds cifra uma chave aleatória para aquela instalação. O systemd entrega a chave em uma credencial privada somente leitura ao usuário do serviço por LoadCredentialEncrypted. O agente cifra o próprio estado com AES-256-GCM e não executa helper privilegiado para isso. A inscrição é lida pelo próprio usuário sem root, nunca pelo gerenciador privilegiado através de StandardInput. O token de inscrição é apagado após salvar o estado cifrado.

Rede, plataforma e reboot da VPS mantêm a mesma identidade enquanto o prazo original for válido. Não há renovação automática da validade. O preflight é repetido na reconexão, e as tarefas interrompidas exigem retomada explícita. O serviço é habilitado no boot, mas ConditionPathExists impede reinício após a limpeza da inscrição.

Expiração/revogação encerram o acesso e removem inscrição e estado privado sem sudo. Binário, chave cifrada sem estado e unidade root-owned ficam inativos; para removê-los, execute como administrador o comando cleanup.sh remove exibido pelo instalador. Nenhum cleanup do serviço executa como root. Workspace e histórico são preservados. Um desligamento só permite limpeza ao voltar; não há promessa de apagamento seguro.

**Agentes antigos devem executar o novo comando uma vez**, no mesmo registro do executor. A conta muda de root/usuário instalador para vulnetic-agent e usa um workspace novo. Arquivos antigos em /root não são modificados nem têm permissões relaxadas; use Files para restaurar os uploads/relatórios/provas salvos no Vulnetic e prepare ferramentas adicionais com seu administrador. O usuário dedicado permanece para conservar os arquivos do workspace.

A validação de ferramentas e workspace acontece automaticamente após conectar.
Registros SSH antigos ficam consultáveis e não executam no modo SaaS.

HTTP sem TLS é aceito apenas em localhost/IP literal de loopback nos ensaios
isolados. A instalação pública exige HTTPS confiável e WebSocket no proxy.

## Modelo primeiro, VPS depois

O perfil LLM pode ser salvo e ativado sem cadastrar VPS. A chave permanece no vault da conta; salvar não faz uma chamada ao provedor e não confirma conectividade. Os botões de teste e listagem de modelos exigem uma VPS conectada selecionada.

O seletor na barra superior define um padrão para novas tarefas e testes da sessão do navegador. Cada ação pode escolher outra VPS. Tarefas e conversas existentes mantêm seu vínculo; mudar o padrão não transfere execuções. A seleção não persiste ao recarregar ou sair da sessão.

Os estados incluem aguardando instalação, conectada, próxima de expirar (30 minutos), expirada, desconectada e status indisponível. Uma falha ao atualizar o status não libera execução. Os prazos contam a partir da inscrição do agente, e não da geração do comando. Revogação, desconexão ou reinício da plataforma podem encerrar o acesso antes do prazo máximo. Gerar um comando substituto encerra as sessões atuais; o cliente precisa executá-lo novamente na VPS.

## Trocar a VPS de uma tarefa existente

Pause a tarefa e aguarde as operações e a conversa ativa do agente principal encerrarem. Cadastre/conecte o novo executor e aguarde a validação automática. No detalhe da tarefa, abra o status da VPS no topo, escolha **Change task VPS**, selecione a VPS conectada da mesma conta e use **Save task VPS**. A tarefa mantém seu ID, grafo, findings, histórico e provas já salvas. Retome manualmente quando estiver pronta.

Na aba Files, use Restore task files para copiar uploads e versões de relatório salvos no Vulnetic, além das provas de execução originais, para a VPS atual. A operação roda em segundo plano, pode ser interrompida e verifica hashes sem sobrescrever arquivos diferentes. Arquivos presentes somente numa VPS antiga indisponível não podem ser recuperados; prepare as ferramentas separadamente. As provas originais continuam vinculadas à execução original. A troca não revoga o acesso de outras tarefas à VPS antiga. Se quiser encerrar esse acesso, use Revoke access ou Delete executor separadamente.

## Proteção do servidor — implantação com gateway

Esta revisão exige migração explícita antes de iniciar a aplicação SaaS. A aplicação
normal usa somente `vulnetic_app`; a credencial de proprietário fica no serviço
`prepare`, executado pelo operador e encerrado após preparar banco, vault e catálogos.
O gateway recebe apenas credenciais temporárias dos executores, não banco, JWT,
vault, artefatos ou Docker socket.

A validação de release pode ser executada localmente. CI externa e chamadas pagas
não são necessárias. Os testes obrigatórios de Linux/PostgreSQL precisam passar;
skips não equivalem a aprovação.

### Preparação e segredos

1. Faça backup consistente de PostgreSQL, volume `state`, `.env.beta`, configuração
   do proxy e regras do firewall. Ensaie a restauração em volumes/rede separados.
2. Confirme que `172.30.240.0/29`, `172.30.241.0/29` e `172.30.242.0/29` não se
   sobrepõem às redes do servidor. Não instale o agente executor nesta máquina.
3. Crie um túnel **localmente gerenciado**, exclusivo para Vulnetic, com a API da
   Cloudflare. Salve somente suas credenciais restritas em
   `secrets/tunnel-credentials.json`; o token administrativo da Cloudflare fica fora
   da VPS e dos containers. As regras revisáveis estão em `cloudflared.yml`.
4. Gere `secrets/gateway-token` com 32 bytes aleatórios ou mais. Proteja o diretório
   `secrets` com proprietário root e modo 0700. Os dois arquivos podem ter modo
   0444 dentro desse diretório, para os UIDs dos containers conseguirem ler os binds
   de secrets do Compose; não use diretório de artefatos. Não os versione.
5. Em `.env.beta`, configure `VULNETIC_TUNNEL_ID`, `VULNETIC_CLOUDFLARED_IMAGE`
   com digest fixo verificado, e `VULNETIC_LEGACY_AGENT_UNTIL` com data UTC RFC3339
   fixa, no máximo sete dias após a troca. Não recalcule a data ao reiniciar.
   `VULNETIC_PROTECTED_TARGETS` acrescenta IPs/CIDRs/domínios exclusivos do operador.

### Troca e verificação

Com as tarefas paradas e as imagens construídas, execute primeiro a preparação:

```sh
docker compose --env-file .env.beta -f docker-compose.beta.yml build app
docker compose --env-file .env.beta -f docker-compose.beta.yml up -d postgres
docker compose --env-file .env.beta -f docker-compose.beta.yml run --rm prepare
```

Para a implantação protegida, use **ambos** os arquivos Compose. Instale
`platform-firewall.sh`, a unidade `vulnetic-firewall.service` e o drop-in
`docker-firewall.conf` em `docker.service.d/`. O firewall precisa passar antes
que o Docker inicie automaticamente os containers. As alterações de chains são
atômicas; conexões de resposta continuam permitidas. Atualize as regras após
mudanças nos IPs das integrações internas autorizadas.

```sh
docker compose --env-file .env.beta -f docker-compose.beta.yml -f docker-compose.protected.yml config --quiet
docker compose --env-file .env.beta -f docker-compose.beta.yml -f docker-compose.protected.yml build app gateway
docker compose --env-file .env.beta -f docker-compose.beta.yml -f docker-compose.protected.yml up -d postgres gateway app tunnel
```

O overlay remove a porta local da aplicação. O monitor continua lendo os logs
pelo Docker. Valide o site, SSE, inscrição, reconexão e expiração pelo túnel antes
que os registros DNS sejam trocados e antes de fechar as portas públicas 80/443.
Preserve o SSH administrativo e mantenha acesso ao console da Google durante a troca.
Não reinicie o Docker para instalar a regra enquanto houver tarefas rodando.

O domínio `agent.vulnetic.site` publica apenas os caminhos exatos do agente.
`/v1/control` e `/v1/session` não podem ter rota pública. Os caminhos antigos do
agente em `vulnetic.site` expiram na data fixa configurada. O banco continua sem
porta publicada. Reinícios preservam a autorização original, mas tarefas SaaS
recuperadas ficam pausadas.

### Verificações obrigatórias

- Gateway sem acesso iniciado ao núcleo, PostgreSQL, host, metadados ou Internet.
- Núcleo conecta somente a banco, gateway e integrações internas autorizadas.
- URLs, IPs, CIDRs, aliases e redirecionamentos para infraestrutura protegida
  bloqueados; redes privadas legítimas do cliente continuam disponíveis.
- IP observado de executor bloqueado no site/API por até o vencimento + 24 horas,
  inclusive após apagar/revogar o executor. Cabeçalhos de IP de origem não
  confiável não são aceitos. Navegadores no mesmo NAT também serão bloqueados.
- Perda do controle encerra agentes em até cinco segundos; expiração e revogação
  não se transformam em renovação durante uma reconexão.
- Restore de arquivos continua verificando hashes e rejeitando sobrescrita.

O proxy de ferramentas HTTP gerenciadas fica indisponível nesta revisão: use
endpoint direto, para preservar a validação do destino. Comandos opacos e proxies
externos controlados pelo cliente exigem a próxima etapa de contenção nas VPS.
Containers compartilham o kernel; isso não representa garantia absoluta contra
comprometimento do host.


### Backup completo e restauração isolada

Use `sudo python3 scripts/backup-beta.py --root /opt/vulnetic` com tarefas pausadas.
A rotina interrompe a aplicação durante o snapshot, preserva banco, volume completo
(incluindo JWT/vault), configurações e segredos do túnel/gateway. Cada arquivo tem
hash SHA256; os arquivos do backup têm permissão 0600 e diretórios 0700. O backup
local contém segredos e deve ficar restrito ao operador; cópias externas precisam
de criptografia. Não há rotação nem exclusão automática nesta rotina.

O comando restaura em PostgreSQL e volume descartáveis, sem rede nem portas
publicadas, compara a identidade/expiração dos executores e todos os arquivos do
volume, e só então registra sucesso. A aplicação retorna ao estado anterior de
execução; tarefas não são retomadas. Para repetir a conferência de um backup:
`sudo python3 scripts/backup-beta.py --restore-check /var/backups/vulnetic/beta-...`.
A restauração sobre a instalação real exige procedimento administrativo separado.
Sessões de navegador válidas no mesmo NAT de um executor continuam permitidas;
requisições sem autenticação do IP observado permanecem bloqueadas.


## Cadastro público gratuito

`VULNETIC_PUBLIC_SIGNUP=true` abre cadastro para qualquer e-mail válido e remove o teto de cinco contas do piloto. O valor padrão `false` mantém o cadastro por convite e seu teto. A lista de convites é preservada para um eventual fechamento. A plataforma não cobra neste lançamento; chamadas de LLM e infraestrutura continuam usando as chaves e executores de cada cliente. Limites de execução, autenticação, RLS e proteções permanecem obrigatórios. O endpoint `/api/auth/status` informa `public_signup` para a interface.
