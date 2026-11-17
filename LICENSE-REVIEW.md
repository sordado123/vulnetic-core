# Fechamento de preparação das licenças

Status: **pacote de fontes preparado para revisão privada; publicação não autorizada**.

## 1. AGPL, autoria e fontes por versão

A aplicação derivada do ARTEX continua AGPL-3.0. O pacote não tenta manter modificações SaaS integradas como um módulo proprietário. Os três snapshots completos, suas modificações legais e o mapa das versões são preservados. Código de build/instalação, testes, interface, schemas e regras de segurança continuam incluídos. O texto legal do login foi esclarecido nos três snapshots: os termos do serviço não restringem os direitos da AGPL; a obrigação de preservar avisos segue as licenças aplicáveis. Nenhuma regra de autenticação, acesso ou execução foi alterada. A sintaxe TSX foi conferida.

A página `publication/index.html` oferece gratuitamente o arquivo completo de fontes do núcleo e do agente e identifica as versões. `publication/ACTIVATION.md` descreve a integração visível no produto. Hospedar o arquivo e ativar o link são passos posteriores que exigem aprovação: uma página privada preparada não cumpre, por si só, a oferta pela rede aos usuários da instalação existente.

Fonte oficial: [AGPL, definição de fontes correspondentes e seção 13](https://www.gnu.org/licenses/agpl-3.0.html).

## 2. Norma e NOA/acp-kernel

Norma v0.4.4 e os commits do port foram comprovados. Licença Apache, avisos originais e indicação de modificações foram preservados. As quatro regras de compressão coincidem com um baseline acp-kernel verificável após as adaptações documentadas.

A licença MIT histórica e o texto posterior de atribuição adicional são ambos fornecidos. A entrega inclui crédito explícito a acp-kernel e ranxianglei, com link, na página de oferta e na documentação. A preservação do texto posterior e o cumprimento conservador da atribuição evitam depender da suposição de que ele não se aplica. Isso não altera retroativamente a licença histórica nem identifica o checkout original completo que não foi recuperado.

## 3. php2shell

Os seis blobs importados correspondem a dois commits upstream que têm o mesmo subconjunto de conteúdo. A diferença entre eles é material não importado. A ambiguidade foi mantida como fato histórico; ela não muda o conteúdo distribuído. A licença MIT oficial posterior e o copyright Qi Deng substituem o aviso antes reconstruído. O arquivo e sua origem estão no relatório por hash. Não foi necessária reatribuição inventada nem remoção de fontes históricas.

## 4. AegisHook

O crédito de inspiração, o componente de referência e uma licença MIT upstream fixada foram preservados. A atribuição a RuoJi6 e contribuidores é mantida para qualquer material adaptado. Não afirmamos que o componente React seja uma cópia literal nem que foi recuperado um checkout originalmente não registrado.

## 5. Dependências e materiais incorporados

As fontes dos 52 módulos Go, com suas licenças internas, foram anexadas. As 588 dependências npm externas estão identificadas por versão, origem e integridade, incluindo as seis dependências empacotadas dentro de outra. Os 85 arquivos apontados a um espelho foram conferidos no registro npm oficial com as mesmas integridades. Não distribuímos suas bibliotecas nativas, tarballs ou bundles neste perfil. OFL, frontend MIT e shadcn mantêm seus próprios avisos.

O inventário antigo de 481 cópias de licença é documentação suplementar; não é usado como prova de que todas as dependências de qualquer futuro binário foram liberadas. O recorte foi fechado pela presença efetiva no pacote, não por assumir que todo lockfile é runtime ou que todo item dev fica fora de um build.

## 6. Condições restantes para a liberação

1. Aprovação do proprietário para publicar este conteúdo.
2. Hospedagem dos arquivos e ativação/conferência da oferta visível no produto.
3. Se o lançamento também distribuir binários, bundles ou imagens novos, concluir a revisão desses artefatos efetivos antes de incluí-los.

Não há solicitação pendente de alteração de licença ou permissão enviada a autores. Não contatamos terceiros. As incertezas históricas foram delimitadas e documentadas, sem declarar certezas inexistentes.

Esta revisão técnica trata do conteúdo desta entrega e não é um parecer jurídico. A reconstrução histórica não foi idêntica byte a byte, e a atribuição preparada ainda não foi implantada em produção.
