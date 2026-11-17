# Dependências e fronteira desta distribuição

## Go — fontes efetivamente anexadas

Os 52 módulos declarados estão em `dependency-sources/go`. Cada entrada contém o ZIP de fontes original, `go.mod` e metadados públicos da versão. Os arquivos ZIP preservam os avisos e licenças internos, incluindo materiais de terceiros incorporados pelos próprios módulos.

`dependency-source-index.json` identifica nome, versão, hash h1 de conteúdo, hash do go.mod, origem pública quando informada e SHA-256 de cada arquivo anexado. A obtenção foi feita por `go mod download` e os hashes h1 foram comparados com `go.sum`. Os três snapshots usam os mesmos manifests de dependências.

Os arquivos anexados são fontes de upstream: podem conter certificados e chaves de teste públicos do próprio projeto upstream. Isso não é material de clientes ou credencial operacional do Vulnetic. Não execute exemplos, ferramentas ou testes upstream apenas por estarem presentes.

Foram inspecionadas as estruturas dos 52 ZIPs: 12.445 entradas e 74 entradas de avisos/licenças preservadas. Existe um executável de teste upstream dentro de `golang.org/x/sys/windows/testdata/ev-signed-file.exe` (18.152 bytes). Ele pertence ao arquivo-fonte original e foi mantido para não alterar sua integridade; não é um executável do produto, não é instalado e não foi executado. A classificação “fontes” não esconde esse fixture binário.

## npm — dependências externas, não redistribuídas

Os dois lockfiles originais são preservados. O índice relaciona 588 entradas com versão, licença declarada, URL de registro e integridade. Seis entradas são incluídas no tarball de `@tailwindcss/oxide-wasm32-wasi`: para elas, a integridade identifica o tarball contendo a dependência, e o caminho interno é registrado separadamente. Não foi inventado um hash individual inexistente no lockfile.

Não são anexados tarballs npm, `node_modules`, módulos nativos ou bundles gerados. O usuário obtém dependências externas pelos endereços fixados para construir o programa. As 481 cópias disponíveis de avisos/licenças da revisão anterior são mantidas como documentação suplementar, sem alegar que constituem um inventário completo de qualquer imagem/container.

As 85 URLs do lockfile da skill api-recon usavam registry.npmmirror.com. Os arquivos equivalentes no registro oficial npm foram baixados para verificação e comparados com as integridades do lockfile: todos coincidiram. O índice oferece as URLs oficiais verificadas sem reescrever o lockfile histórico. O relatório de hashes dessa comparação está em `provenance/npm-origin-verification.json`.

`sharp`/`libvips` e variantes nativas LGPL e `lightningcss`/variantes MPL são dependências externas de construção neste perfil. Nenhuma biblioteca desses pacotes é distribuída aqui. Não são convertidas para AGPL, e as expressões com `AND` e `OR` continuam preservadas. Caso uma entrega futura as inclua, devem ser tratados os avisos, as fontes correspondentes e, quando aplicável, as condições de substituição/relinkagem da LGPL. A classificação “dev” no lockfile, isoladamente, não comprova ausência de um bundle distribuído.

## Materiais incorporados ao próprio código

- Norma/NOA: fontes e modificações locais incluídas, com Apache e histórico MIT/atribuição preservados.
- php2shell: subconjunto de fontes verificado, licença MIT oficial incluída; nenhuma execução nesta entrega.
- AegisHook: licença MIT e crédito conservador para o material de referência/adaptado.
- Frontend base: licença MIT preservada; isso não relicencia a aplicação inteira como MIT.
- Geist: licença OFL-1.1 e copyright Vercel/basement.studio preservados. Os arquivos de fonte são obtidos da dependência npm externa `geist`; não há uma cópia separada desses arquivos neste pacote de fontes. Bundles futuros que incluam as fontes deverão preservar os avisos OFL.
- Folha de estilos shadcn: atribuição e licença MIT preservadas.
- Metadados de dependências CC-BY-4.0/CC0: origem, licença e avisos disponíveis preservados; seus pacotes e bundles não são distribuídos neste perfil.

## Fora do perfil final

Nenhuma imagem Docker, pacote Debian/Python, Chromium/Playwright, executável de ferramenta externa, biblioteca nativa npm ou imagem de laboratório é anexada. Os Dockerfiles e scripts de referência não são um produto binário auditado. Antes de distribuir uma imagem construída a partir deles, inventarie o conteúdo efetivo e cumpra as licenças correspondentes; este relatório não oferece essa liberação antecipadamente.

Referências oficiais consultadas em 17/11/2026: [AGPL](https://www.gnu.org/licenses/agpl-3.0.html), [FAQ MPL](https://www.mozilla.org/en-US/MPL/2.0/FAQ/), [MPL 2.0](https://www.mozilla.org/en-US/MPL/2.0/) e licenças upstream fixadas no relatório de proveniência.
