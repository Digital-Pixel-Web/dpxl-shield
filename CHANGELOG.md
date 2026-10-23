# Changelog

Histórico completo de versões do DPXL Shield. O `readme.txt` traz só as versões recentes, como pede o diretório do WordPress.org.

## 1.12.0

* **Segurança: IP do visitante não pode mais ser falsificado.** Cabeçalhos como `X-Forwarded-For` e `CF-Connecting-IP` só são aceitos de proxies confiáveis (Cloudflare, rede local ou a constante `DPXL_SHIELD_TRUSTED_PROXIES`). Antes, qualquer visitante escolhia o próprio IP para escapar de bloqueios ou fazer o IP de outra pessoa ser bloqueado.
* **Segurança: o firewall não pode mais ser contornado** colocando um caminho do painel na query string, pelos endpoints anônimos `admin-ajax.php`/`admin-post.php` ou com um cookie de login forjado. Sessões são validadas.
* **Corrigido: a Proteção Estendida passa a rodar as regras do firewall** antes do WordPress carregar, e as checagens internas continuam rodando junto.
* **Corrigido: bloqueios manuais "permanentes" expiravam no mesmo instante.** Bloqueios automáticos não encurtam mais um permanente. Faixas IPv6 passam a funcionar.
* **Segurança: o reparo de arquivos não deixa mais uma cópia executável** do arquivo substituído em `wp-content`, e confere o arquivo baixado com o checksum oficial.
* **Corrigido: quem ativava o 2FA não conseguia mais entrar.** O formulário de login nunca chegava à tela do código e mostrava "senha incorreta" no lugar.
* **Segurança: 2FA limitado a 5 tentativas por login**, e as falhas contam para o bloqueio por força bruta.
* **Segurança:** leitura e exportação de configurações não incluem mais chaves de API.
* **Corrigido:** o feed de regras e a base GeoIP não conseguiam ser gravados numa instalação nova.
* **Corrigido: o plugin não carregava em PHP 7.4**, o mínimo que ele declara (um tipo de retorno do PHP 8 nas regras do firewall). A checagem de compatibilidade agora pega esse caso.
* **Alterado:** o XML-RPC só é bloqueado para requisições `system.multicall` (força bruta em lote), então Jetpack, apps móveis e pingbacks voltam a funcionar. O limite de login conta tentativas, não carregamentos da página.
* **Segurança:** um código do 2FA não pode mais ser reaproveitado num segundo login. A pasta de dados do firewall deixa de ser legível pela web.
* **Corrigido:** errar alguns códigos do 2FA não estoura mais o limite de login nem bane o usuário. Bloqueios no XML-RPC e na API REST passam a responder HTTP 403, e cada bloqueio deixa de gerar um aviso de tradução no debug.log.
* **Corrigido:** requisições bloqueadas pelo firewall passam a aparecer no Tráfego ao vivo e nos contadores do painel.
* **Corrigido:** a desinstalação agora apaga os segredos do 2FA, os códigos de recuperação, os IPs de login conhecidos e os transients do plugin.
* **Segurança:** o `system.multicall` é reconhecido mesmo disfarçado com referências de caractere XML ou CDATA.
* **Novo:** o Diagnóstico mostra como o IP do visitante está sendo detectado.

## 1.11.0
* **Novo: monitoramento do envio de e-mails.** O site avisa quando para de conseguir enviar mensagens. É a falha que esconde a si mesma: e-mail é o canal por onde todos os outros alertas viajam, então, quando o envio quebra, o aviso disso quebra junto. Por isso a interrupção é relatada por todos os caminhos que não dependem de e-mail — alerta dentro do painel, log de auditoria e as integrações de saída (Slack, Discord, PagerDuty, SIEM) — e o e-mail é tentado também, na chance de o problema ser só um destinatário ou uma mensagem.
* Quando o envio volta, um resumo sai por e-mail dizendo quanto tempo durou a interrupção. É o momento em que o leitor finalmente pode ser alcançado, e o tempo no escuro é o dado que ele precisa.
* O aviso sai depois de duas falhas seguidas, não da primeira: um destinatário recusado ou um tempo limite isolado não é uma interrupção, e tratar como tal é o que faz um alerta perder o sentido. O número é configurável em Configurações → Alertas.
* Uma interrupção gera um alerta, não um por mensagem — um servidor de e-mail quebrado falha toda a fila, e cem alertas iguais enterrariam o fato nos canais que ainda funcionam.
* O Diagnóstico ganhou uma linha para o envio de e-mails, com o último erro do servidor e a data do último envio bem-sucedido.

## 1.10.1
* **Corrigido: desativar ou excluir qualquer plugin avisava que o DPXL Shield tinha sido removido.** O código sabia a diferença — rebaixava a severidade quando o plugin era de outro — mas usava o mesmo tipo de evento nos dois casos, e é o tipo de evento que decide o título e o resumo do e-mail. Então remover um plugin qualquer gerava uma mensagem com o cabeçalho "O DPXL Shield foi excluído", dizendo que a proteção do site tinha acabado, enquanto o plugin seguia instalado e ativo. Aconteceu cinco vezes em dois meses num site real antes de alguém ligar o e-mail à causa. Os dois casos agora têm eventos próprios, com texto que nomeia o que de fato aconteceu.
* **Alterado: administrar plugins deixa de gerar e-mail.** Desativar e remover plugins é trabalho normal de quem cuida de um site. Esses eventos continuam no log de auditoria e seguem para as integrações, com quem fez e de onde, mas não interrompem mais ninguém por e-mail. O DPXL Shield sendo desativado ou removido continua sendo alerta crítico, que é o caso em que a proteção de fato some.
* **Novo: uma verificação de que todo evento disparado existe no catálogo.** O catálogo decide título, resumo e o bloco "o que fazer" a partir do tipo de evento, e nada ligava os dois lados — foi assim que dois fatos diferentes passaram a dividir um tipo só. Um teste agora lê os tipos disparados no código-fonte e falha nomeando qualquer um sem título, sem resumo ou sem o que fazer. É a quarta guarda do gênero, depois das listas de ícones, dos rótulos de campo dos alertas e das frases sem tradução.

## 1.10.0
* **Novo: aviso por e-mail a cada entrada de administrador.** Até aqui o alerta só saía na primeira vez que uma conta entrava de uma rede ainda não vista, então entrar do lugar de sempre era silencioso — e a entrada que não foi você parecia exatamente igual a esse silêncio. É o oposto de um alerta que grita lobo: ele só serve porque chega sempre, e é essa regularidade que faz a entrada estranha se destacar no meio das suas. O aviso traz quem entrou, de onde, com país e provedor quando conhecidos, e diz o que fazer em cada caso.
* Uma entrada de uma rede nova continua com o alerta próprio, que é o sinal mais forte, e o aviso de rotina não é enviado junto: um login gera um e-mail, nunca dois.
* Pode ser desligado em **Configurações → Alertas**, e o próprio e-mail diz isso — um alerta que o leitor não consegue silenciar é um que ele aprende a filtrar. Desligá-lo não afeta o aviso de entrada a partir de uma rede nova.

## 1.9.6
* **Corrigido: "não consegui conferir" era reportado como "comprometido".** Antes de soar o alarme de integridade de arquivo, o plugin pergunta ao WordPress.org se o arquivo em disco é a versão oficial. Essa pergunta tem três respostas, e duas delas caíam no mesmo lugar. `false` merece o alarme: o arquivo foi comparado com o manifesto oficial e difere. `null` é outra coisa — a comparação não pôde ser feita, seja porque a versão que o WordPress informa não corresponde aos arquivos em disco (o que acontece nos minutos em que uma atualização de core está em andamento), seja porque o arquivo não consta do manifesto daquela versão, seja porque a api.wordpress.org não respondeu. Nada disso é evidência de coisa alguma, e chamar isso de crítico é como o leitor aprende a ignorar o remetente. Numa instalação de homologação isso gerou de um a oito e-mails de "Arquivo crítico modificado" por dia, durante semanas, sobre o `wp-admin/includes/plugin.php` — um arquivo que o `wp core verify-checksums` reportava como idêntico byte a byte ao release oficial. Pararam sozinhos no instante em que uma atualização de core terminou e a referência foi regravada.
* **Novo: um evento próprio para esse caso.** Uma mudança que não pôde ser verificada passa a ser reportada como aviso, e não como alerta crítico, sob um tipo de evento próprio, e o alerta diz no próprio corpo se a comparação chegou a acontecer. O alarme para um arquivo que de fato difere do release oficial segue igual.

## 1.9.5
* **Corrigido: as últimas nove frases em inglês, todas escritas em JavaScript.** A camada de tradução só alcança as frases que o PHP pede a ela, então tudo o que o navegador escreve ficava fora do seu alcance — os estados vazios de Integrações e do log de auditoria, as duas confirmações para remover um webhook ou revogar um token, e o texto de ajuda abaixo do campo de segredo de assinatura. Visíveis apenas depois de você ter algo configurado, ou na hora de apagar.

## 1.9.4
* **Corrigido: a aba Integrações estava inalcançável.** O link existia na navegação e a tela existia, mas a lista de abas permitidas não conhecia o nome, então a requisição era silenciosamente reescrita para Tráfego ao Vivo — e o Tráfego ao Vivo então ficava eternamente em "Carregando…", porque o script que o preenche se orienta pelo nome da aba no endereço, que continuava dizendo integrations. Nada falhou em voz alta; a tela que guarda a configuração de webhooks e tokens de API simplesmente não abria. Descoberto ao conferir as traduções que aquela tela acabara de receber.
* **Novo: uma verificação de que as três listas de abas concordam.** A tela de Ferramentas guarda suas abas em três lugares — a lista de permitidas, a navegação e um arquivo por aba — e esta estava em dois deles.
* **Corrigido: os títulos de seção do Diagnóstico** ainda estavam em inglês acima das linhas traduzidas na 1.9.3.

## 1.9.3
* **Alterado: o resto do plugin passa a falar português.** Sessenta e quatro frases que as telas pediam à camada de tradução não estavam nela, então chegavam ao usuário em inglês dentro de páginas que no mais eram portuguesas — todos os parágrafos que explicam webhooks, tokens de API, a chave da Spamhaus e o feed do GeoLite2, além dos rótulos de filtro, dos limites de severidade e de uma dúzia de botões. A aba Diagnóstico estava em inglês de ponta a ponta: trinta e dois rótulos, valores e recomendações. E os próprios achados de varredura — a frase que descreve o que foi encontrado, que é também a que o relatório semanal e o e-mail de alerta carregam — eram escritos em inglês no ponto em que cada detector os produzia.
* **Novo: uma verificação de que nenhuma frase em inglês volte a chegar a uma tela.** A camada de tradução não tem como saber que uma frase foi esquecida, então um teste passou a ler todas as frases que as views pedem e a falhar nomeando as que parecem frase em inglês e não têm tradução. É a terceira guarda desse tipo, depois das listas de ícones e dos rótulos de campo dos alertas; as três existem porque a mesma classe de regressão voltou.
* **Corrigido: um tema desatualizado era reportado como "Theme"** no meio de uma frase em português, porque o tipo do componente vinha direto do WordPress.

## 1.9.2
* **Corrigido: a tabela de Tráfego ao Vivo nomeava as próprias categorias em inglês.** Cada linha dizia "human", "bot" ou "blocked" — identificadores crus vindos do código — enquanto a legenda de cores acrescentada na 1.9.0 nomeava as mesmas quatro categorias em português logo abaixo, e o filtro acima usava uma terceira redação. As três agora coincidem. A dica do ponto colorido também exibia o identificador.

## 1.9.1
* **Corrigido: a linha de estado da tela de Firewall era reescrita em inglês pelo navegador.** A página a renderiza em português e depois a atualiza por REST, para que o estado possa mudar sem recarregar — e essa segunda cópia nunca havia sido traduzida, então sobrescrevia a primeira em silêncio a cada carregamento. Agora as duas coincidem, e a linha nomeia o servidor detectado, que é o único dado que valia preservar da etapa de configuração que a 1.9.0 recolheu.

## 1.9.0
* **Alterado: todo achado de varredura passa a oferecer algo a fazer.** O único botão de um achado era Ignorar — inclusive num achado crítico, e inclusive num plugin desatualizado, que é a maior parte do que uma varredura encontra num site real. Um produto cuja única ação possível é descartar o aviso está ensinando as pessoas a descartar avisos. Arquivos reparáveis mantêm Reparar; um componente desatualizado ganha Atualizar agora, direto para a tela de atualizações do WordPress; e todo achado ganha um passo a passo de "Como resolver" escrito para o tipo de dúvida que ele provoca — conselho de apagar para uma assinatura confirmada, conselho de olhar antes de agir para uma heurística que não tem certeza. O caminho do arquivo pode ser copiado em um clique, para quem trabalha por FTP ou SSH. Ignorar continua lá, como link discreto em vez de botão principal.
* **Corrigido: o cartão do achado lia-se de trás para frente.** A etiqueta de severidade ocupava o lugar do título na grade, o que empurrava o título para a borda direita e deixava a descrição onde o título deveria estar. Agora: título primeiro, severidade à direita, descrição abaixo dos dois.
* **Alterado: a Proteção Estendida deixa de tomar a tela depois de ligada.** O fluxo de configuração — duas etapas concluídas, quatro caminhos absolutos, uma alternativa manual e um parágrafo explicando o procedimento — ficava para sempre no topo da tela de Firewall. Com a proteção ativa, agora é uma linha nomeando o servidor detectado, com o detalhe técnico atrás de um expansor. Com ela inativa, todo o fluxo continua ali, que é quando ele é o assunto da tela.
* **Removido: uma nota de desenvolvimento comparando o plugin ao Wordfence** estava sendo exibida aos usuários na tela de Firewall. Substituída por uma explicação do que a Proteção Estendida faz e por que importa.
* **Alterado: o Tráfego ao Vivo diz o que cobre e o que não cobre**, e os pontos coloridos ganharam legenda visível. O significado deles vivia num atributo `title`, invisível no toque e para quem não passasse o mouse.
* **Alterado: o Diagnóstico abre já executado.** A única tela que responde "este servidor está configurado corretamente?" abria em branco atrás de um botão, então não mostrava nada até você saber que precisava perguntar.
* **Novo: a Segurança de Login mostra quanto do site está de fato coberto** — quantos administradores concluíram a configuração do dois fatores, não apenas se você concluiu. É esse o número que o medidor do painel lê, e numa instalação real ele era zero enquanto o medidor marcava 100%.

## 1.8.4
* **Corrigido: os últimos rótulos em inglês nas telas de painel e firewall.** Olhar a 1.8.3 rodando numa instalação real revelou mais quatro: o painel de notificações vazio, a resposta de gravável/não gravável para o arquivo .htaccess, e os botões de intervalo de 7 e 30 dias.

## 1.8.3
* **Alterado: os medidores do painel contam o que está de fato ligado, em vez de escrever 100%.** `firewall_ok` era `Options::get('firewall_enabled')` e nada mais, então um site com a Proteção Estendida desligada, nenhuma regra de firewall carregada e nenhum administrador usando dois fatores ainda exibia três anéis verdes a 100%. Cada anel passa a ser a proporção das verificações daquele módulo que passam — cinco para o firewall, três para a varredura, três para o login — e a linha abaixo nomeia a primeira que não passa, como link direto para ela. Um módulo não alcança 100% enquanto algo que ele cobre estiver desligado.
* **Novo: "não verificado" como estado próprio, em cinza.** Uma verificação que nunca rodou deixa de ser dobrada em verde ou em vermelho. Um site que ninguém varreu ainda diz "nenhuma varredura foi concluída neste site", em vez de exibir um anel saudável; uma blocklist que recusou a consulta aparece como sem resposta, não como limpa. É a mesma distinção que o verificador de reputação passou a fazer na 1.7.0, enfim desenhada na tela. Cinza nunca vira verde sozinho.
* **Alterado: o banner de proteção tem quatro estados, e cada um que não é verde carrega o próximo passo.** Antes eram dois — "ativa" e "degradada, veja as notificações abaixo", que pedia ao leitor que saísse caçando. Agora ele diz qual proteção está faltando e coloca o botão de resolver no próprio banner.
* **Alterado: os três medidores da tela de Varredura relatam o que aconteceu.** As assinaturas de malware marcavam "100% / Carregadas" e a verificação de reputação marcava "100% / Checagens de blocklist", ambas escritas à mão independentemente do que tivesse rodado. Agora mostram a contagem real de assinaturas, o resultado real da reputação (limpo, listado ou sem resposta, nomeando o serviço que não respondeu) e há quanto tempo a última varredura terminou.
* **Alterado: contagens deixam de ficar dentro de um anel.** "14 regras" e "0 IPs bloqueados" eram desenhados no mesmo círculo usado para percentuais, o que se lia como "14% de alguma coisa, e tudo bem". Agora são números simples. O anel do WAF cobre duas verificações em vez de uma: estar ligado e carregar antes do WordPress.
* **Corrigido: três estados vazios e vários rótulos ainda estavam em inglês** em telas que no mais eram portuguesas — o gráfico de ataques, a tabela de IPs bloqueados e o tráfego ao vivo entre eles.

## 1.8.2
* **Corrigido: três pedaços de inglês deixados para trás pela 1.8.0.** O alerta de varredura concluída abria com "trate primeiro o que está marcado como crítico", mas a 1.8.1 ampliou esse alerta para disparar também em achados altos, então ele podia chegar apontando para uma seção que não existia; agora diz para começar pelos achados mais severos, sejam quais forem. Treze campos de contexto que os detectores enviam — a duração do bloqueio, a contagem de vazamentos, o número de achados, se o plugin desativado era este — não tinham rótulo em português, então cada um chegava como identificador em inglês humanizado ("Lockout seconds", "Hibp count") dentro de um e-mail no mais português. E um campo verdadeiro/falso ainda dizia "yes" ou "no". Os três são a mesma meia-tradução que a 1.8.0 se propôs a eliminar.
* **Novo: uma verificação que lê os detectores em vez de confiar numa lista.** Aqueles rótulos sumiram porque uma mudança em outro lugar acrescentou duas chaves de contexto e nada ligava os dois lados. Um teste agora percorre cada payload de alerta no código-fonte, coleta as chaves que cada um envia e falha nomeando qualquer chave sem rótulo — o mesmo tipo de guarda que as listas de ícones ganharam na 1.7.4.

## 1.8.1
* **Corrigido: o medidor de segurança do painel marcava 100% com uma assinatura de malware em aberto, e nenhum e-mail jamais saiu sobre isso.** O medidor, e o alerta enviado quando uma varredura termina, ambos perguntavam se havia algo *crítico*. O único achado aberto em duas instalações era uma assinatura de malware classificada como alta — então, de julho em diante, o painel reportava saúde perfeita sobre um achado aberto que a tela de Varredura vinha listando o tempo todo, e nenhum e-mail de alerta foi enviado a respeito. Os dois passam a tratar alto como crítico, que é a linha que a própria contagem de ameaças já desenhava. Médio fica deliberadamente de fora: são os achados sobre os quais a varredura diz não ter certeza, e deixar o medidor vermelho por causa de cada um deles é o mesmo problema de gritar lobo, pelo outro lado. Continuam listados e continuam contados.

## 1.8.0
* **Alterado: os e-mails de alerta passam a dizer quem, de onde e o que fazer.** Um alerta era um fato só e uma tabela de campos crus. Um desses campos dizia `Endereço IP: 2804:d45:b005:1800:dcd6:a6ff:45ec:ac02` e nada mais, o que não é algo sobre o que um leitor possa agir. Todo alerta passa a carregar quatro blocos em ordem fixa: o que aconteceu, quem foi e de onde veio, o que fazer a respeito, e os campos crus por último. A origem nomeia o país a partir da base GeoLite2 embutida e o provedor a partir do que a ferramenta de Whois já tiver buscado; onde o provedor é desconhecido, ele diz isso e aponta para a ferramenta, em vez de deixar um vazio que se lê como "conferido, não havia nada". Nada desse bloco vai à rede, então nenhum login fica mais lento para enfeitar um e-mail. Para IPv6, o bloco também nomeia a rede a que o endereço pertence — em conexões residenciais o endereço em si rotaciona, e a rede é o que o plugin de fato compara.
* **Alterado: todo alerta diz o que fazer, inclusive quando a resposta é nada.** Um alerta sobre o qual não se pode agir, e que não diz isso, é como as pessoas aprendem a ignorar o remetente. Um bloqueio agora abre com "nenhuma ação é necessária: o bloqueio é automático e expira sozinho"; um alerta de adulteração abre com "rode uma varredura completa agora". Três eventos que de fato disparam em atividade normal — login de uma rede nova, arquivo alterado, padrão de tráfego — também carregam uma linha explicando por que podem aparecer sem que nada esteja errado.
* **Alterado: o catálogo de alertas está em português.** Títulos, explicações e rótulos de campo ainda estavam em inglês enquanto o e-mail ao redor era português desde a 1.4.0, então todo alerta chegava meio traduzido, linha de assunto incluída. As mesmas frases alimentam as integrações de webhook, Slack e Discord, então esses payloads também estão em português agora. O que segue em inglês é a descrição de uma linha que cada detector repassa; ela saiu da frase de abertura para o bloco técnico, onde nada se perde.
* **Alterado: o botão do alerta abre a tela de que o alerta trata.** Todo alerta linkava para a página inicial do plugin, deixando o leitor caçar o que o e-mail acabara de contar. Um alerta de login abre a Segurança de Login, um alerta de varredura abre os resultados da varredura, um alerta de bloqueio abre a aba Bloqueios. A linha de assunto também ganhou uma exceção à própria regra: `crítico` agora se anuncia, porque um alerta de malware não aberto custa mais que o ruído. Tudo abaixo de crítico continua chegando sem gritar.

## 1.7.8
* **Corrigido: uma assinatura de malware acusava a opção de registro que todo plugin escreve.** A assinatura marcava qualquer arquivo que ligasse o registro de usuários, que é exatamente o que uma chave de registro faz quando você a liga — então um plugin cuja tela de login oferece essa chave foi acusado de casar com assinatura de malware em duas instalações, de julho em diante, e seguia casando a cada varredura. Ligar o registro é uma configuração; o que um backdoor faz, e nenhuma tela de configuração faz, é ligá-lo *e* fixar administrador como a função de toda conta nova. A assinatura agora exige as duas metades antes de reportar. Em 30 mil arquivos de duas instalações ela não casa com nada, onde antes casava com o único arquivo que nunca foi ameaça.

## 1.7.7
* **Alterado: dois tipos de achado deixam de contar como ameaça quando a própria varredura os classificou como médios.** A contagem de ameaças é o número que você olha para decidir se há algo a fazer, e dois achados a inflavam. Arquivos PHP dentro de um diretório em que um plugin compila — o WPML escreve ali seus templates de página como PHP, e o faz por projeto — já eram classificados como médios pela varredura, com o próprio achado dizendo que não são evidência de comprometimento; ainda assim contavam como ameaça. Componentes apenas atrás da última versão eram contados do mesmo jeito, embora essa verificação registre vulnerabilidade conhecida como alta ou crítica e atualização disponível como média, de modo que as duas eram indistinguíveis no distintivo. Ambos passam a contar como ameaça apenas quando a varredura os classificou como altos ou críticos, como arquivos expostos sempre foram tratados. Numa instalação a contagem foi de 40 para 1, em outra de 19 para 1. Nada foi escondido: todo achado rebaixado aparece em Recomendações com contagem própria, e o relatório semanal lista os componentes que precisam de atualização exatamente como antes.
* **Corrigido: a tela de Varredura podia exibir a contagem de ameaças anterior ao lado da nova.** A tela toma seu número de dois lugares — uma contagem ao vivo do que está aberto e um total gravado quando a última varredura terminou — e escreve os dois no mesmo ponto, então vencia quem respondesse por último. Os dois sempre concordaram até a regra acima mudar o que conta, momento em que o total gravado seguiria reportando o número antigo até a próxima varredura completa. A tela agora conta o que está aberto, sempre.

## 1.7.6
* **Corrigido: o painel reportava ameaças abertas que a tela de Varredura não mostrava.** O painel contava toda ameaça ainda aberta; a tela de Varredura listava apenas os achados que a varredura mais recente havia registrado pela primeira vez. Desde a 1.7.2 uma varredura deixa um achado já aberto no registro original — a data em que foi visto pela primeira vez é a honesta — então um problema que segue sendo detectado nunca é registrado de novo, e a tela de Varredura deixou de exibi-lo. Numa instalação isso significava um painel marcando 19 ameaças abertas ao lado de uma tela de Varredura marcando nenhuma, incluindo uma assinatura de malware aberta desde julho. As duas telas passam a contar o que está aberto, que é o que a última varredura encontrou: uma varredura fecha o que não vê mais, então os dois números saem dos mesmos registros e não podem divergir.
* **Corrigido: "Reparar todos os reparáveis" pulava arquivos já reportados antes.** Ele selecionava apenas o que a varredura mais recente havia registrado, então um arquivo de core ou de plugin modificado que seguia sendo detectado — exatamente o tipo que precisa de reparo — nunca entrava, embora a contagem do próprio botão o incluísse. Agora repara todo arquivo reparável em aberto.
* **Corrigido: uma varredura horária podia marcar todo achado aberto como resolvido.** A varredura horária só examina arquivos alterados desde a última varredura completa, mas fechava qualquer achado que não encontrasse — e ela não encontra quase nada, por projeto. Na primeira vez que achasse algo, todos os demais achados abertos do site teriam sido silenciosamente marcados como resolvidos. Agora ela só registra o que é novo; fechar achado fica com a varredura completa, que de fato olha em todo lugar.

## 1.7.5
* **Corrigido: uma consulta filtrada do Tráfego ao Vivo reportava total de zero resultados.** O endpoint de tráfego monta um conjunto de condições e o usa duas vezes — uma para a página de linhas que retorna, outra para contar quantas linhas casam no total. A contagem rodava sem vincular os valores do filtro, então os marcadores dos filtros de IP e URL chegavam ao banco como texto literal, a consulta falhava, e o total voltava zero enquanto as linhas voltavam corretas. A contagem agora vincula os mesmos valores da consulta de página. Nada no painel exibia esse total ainda, então nenhuma tela mostrava número errado; o valor só estava esperando para estar errado para quem o usasse primeiro.

## 1.7.4
* **Corrigido: a aba Tráfego ao Vivo nunca carregava.** Ficava em "Carregando…" pelo tempo que você a deixasse aberta, não fazia requisição alguma, e o botão "Mostrar filtros avançados" não fazia nada. Duas variáveis de que o carregador precisa eram declaradas logo abaixo da linha que o chamava, então ler uma delas lançava erro antes de a primeira requisição ser montada; o erro escapou do tratamento do carregador, e o código que liga os controles de filtro e de atualização ao vivo nunca era alcançado. Os dois sintomas tinham a mesma causa única, e é por isso que a aba estava inerte, não apenas lenta.
* **Corrigido: a tabela de Resumo do Firewall contradizia a si mesma.** As quatro linhas por tipo eram zeros escritos no JavaScript do painel, enquanto a linha de Total logo abaixo contava bloqueios reais — então o primeiro ataque genuíno produzia uma tabela reportando um total de bloqueios e, imediatamente acima, nada em categoria alguma. As linhas e o Total agora saem de uma consulta só sobre os mesmos registros, de modo que não podem divergir. Tipos que não bloquearam nada ficam de fora, e uma instalação sem bloqueio algum diz isso em vez de exibir uma grade de zeros.
* **Corrigido: a coluna Localização do Tráfego ao Vivo estava sempre vazia.** O firewall já geolocaliza toda requisição registrada, e o widget de países bloqueados do painel vinha lendo esse dado, mas a tabela de tráfego desenhava um traço em toda linha. Agora mostra o país de origem da requisição, quando conhecido.
* **Corrigido: quatro ícones apareciam como um círculo genérico de informação.** O painel guarda seu conjunto de ícones em dois lugares — um para a marcação construída no servidor, outro para as linhas construídas no navegador — e faltavam `lock`, `sliders`, `upload-cloud` e `users` na cópia do navegador. Cada um caía no glifo de informação sem erro algum, então o descompasso era invisível. As duas listas agora são idênticas e um teste falha se voltarem a divergir.

## 1.7.3
* **Corrigido: manter o Akismet atualizado era reportado como arquivos de core modificados.** O WordPress distribui o Akismet e os temas padrão, então seu manifesto de checksums os lista — 444 arquivos sob wp-content na 7.1.3. Esses componentes atualizam no próprio ritmo, independentemente do core, que é como devem funcionar; compará-los com o release do core, portanto, acusava um site bem mantido de ter 21 arquivos de core modificados. A integridade de core passa a cobrir o que é core de fato: wp-admin, wp-includes e a raiz.
* **Corrigido: o index.php de "Silence is golden" era reportado como código executável em uploads.** O WordPress e a maioria dos plugins deixam um desses em cada diretório que criam, para impedir a listagem da pasta — é proteção, não carga. Um arquivo chamado index.php contendo apenas tag de abertura e comentários deixa de ser reportado. Um que carregue código de verdade continua sendo.

## 1.7.2
* **Corrigido: os achados se acumulavam em vez de serem atualizados.** Cada varredura registrava seus achados de novo, então um arquivo que seguia casando produzia uma linha por varredura indefinidamente — num site, 34 arquivos haviam virado 2.380 achados abertos ao longo de 70 varreduras. O número de problemas críticos no painel é o que diz se há com que se preocupar, e nesse tamanho ele não diz nada. As varreduras agora reconciliam: um achado já aberto mantém a data original de detecção, um que sumiu é marcado como resolvido, duplicatas deixadas por varreduras anteriores são colapsadas, e uma severidade corrigida alcança o registro existente.
* **Corrigido: PHP gerado por plugins sob uploads era reportado como crítico.** A verificação existe porque upload de mídia nunca deveria ser código executável — mas vários plugins escrevem PHP nos próprios diretórios de trabalho sob uploads, sendo o WPML compilando templates Twig o caso comum. Esses passam a ser reportados como médios, com explicação, enquanto PHP nos diretórios de mídia segue crítico, que é por onde um upload malicioso de fato chega.
* Achados das detecções corrigidas na 1.7.1 se limpam sozinhos na varredura seguinte, incluindo os registros de divergência de core em `wp-includes/version.php` remanescentes de antes de esse arquivo entrar na lista de ignorados.

## 1.7.1
* **Corrigido: um administrador podia ser bloqueado do próprio site por 30 minutos.** O detector comportamental bloqueia qualquer IP que peça mais de 50 URLs únicas em um minuto. Trabalhar no wp-admin passa disso sem esforço — cada chamada admin-ajax leva query string própria, então cada uma conta como URL distinta — e nada isentava um administrador logado. Numa instalação isso trancou o dono do site para fora seis vezes antes de alguém ligar o alerta à causa. Administradores passam a ser isentos: quem já pode instalar plugins não ganha nada rastejando o site, então não havia sinal a perder aqui.
* **Corrigido: a assinatura "código PHP embutido em arquivo de imagem" acusava arquivos PHP comuns, inclusive do core do WordPress.** Ela foi escrita para um polyglot — uma imagem de verdade carregando PHP — mas rodava contra arquivos .php e casava qualquer menção a formato de imagem num raio de 100 caracteres de uma tag de abertura. Isso pegava o `wp-admin/includes/media.php`, e toda biblioteca que lê imagens: um parser de GIF casava pelo próprio namespace. A assinatura agora se aplica apenas a arquivos que dizem ser imagem, e olha somente a área de cabeçalho onde um polyglot se esconde. Imagens no diretório de uploads passam a ser varridas por ela, que é o único lugar por onde a ameaça pode chegar.
* **Corrigido: a detecção de card skimmer em JavaScript acusava bibliotecas de formulário e de construção de páginas.** Ela procurava no arquivo inteiro por um nome de campo de cartão, uma chamada de rede e uma URL, cada um de forma independente — então qualquer bundle contendo os três em qualquer lugar era reportado como skimmer. Num caso, o campo de cartão e a chamada de rede estavam a 1,8 MB de distância, em código sem relação. Os três agora precisam aparecer juntos, como num skimmer real, que lê um campo e o envia em seguida.
* Achados de varredura das duas assinaturas corrigidas, e achados de blocklist anteriores à 1.6.3, são limpos na atualização. Nunca foram reais, e deixados no lugar manteriam o painel vermelho e a contagem de críticos sem sentido.

## 1.7.0
* **Novo: suporte a chave Spamhaus DQS (Configurações → Global → Checagens de blocklist).** A Spamhaus recusa consultas que chegam por resolver DNS público, que é o que a maioria das hospedagens compartilhadas usa — então nesses servidores os espelhos públicos gratuitos não conseguem responder, e as checagens de blocklist não tinham como rodar, independentemente de como estivessem escritas. Uma chave do Data Query Service dá ao site uma zona de consulta própria e faz as checagens funcionarem; a Spamhaus oferece um nível gratuito para uso não comercial com volume baixo, e contas pagas nos demais casos. Sem chave, as checagens seguem rodando contra os espelhos públicos e reportam como indisponíveis onde estes recusarem.
* A chave fica de fora da exportação de configurações, como as credenciais de webhook. Uma chave é uma conta com cota de consultas: restaurar o mesmo pacote em vários sites apontaria todos para uma única chave e esgotaria a cota, bloqueando as checagens em todos de uma vez.
* Uma chave malformada cai de volta para os espelhos públicos em vez de ser colada dentro de um nome DNS, e espaços em volta vindos de copiar e colar são tolerados.
* Alterado: as respostas de blocklist passam a ser lidas conforme as faixas documentadas pela Spamhaus — listagens ocupam 127.0.0.0/16, enquanto 127.255.255.0/24 carrega códigos de erro. Endereços são comparados como números, não por prefixo de texto.
* Novo: uma resposta fora de 127.0.0.0/8 é reconhecida como um resolver reescrevendo nomes desconhecidos em vez de devolver NXDOMAIN, e reportada como indisponível. Antes, tal resposta teria sido lida como listagem, marcando todo site atrás daquele resolver.
* Novo: uma varredura cujas checagens de blocklist não puderam rodar passa a registrar isso, em severidade baixa, em vez de reportar resultado limpo. Uma checagem que nunca rodou não é atestado de saúde.

## 1.6.3
* **Corrigido: o site podia ser reportado como em blocklist sem estar listado em lugar algum.** A Spamhaus responde a uma listagem e a uma consulta recusada do mesmo jeito — com um registro DNS — e só o endereço as distingue. Listagens voltam como 127.0.1.x (DBL) ou 127.0.0.x (ZEN); a faixa 127.255.255.x é código de erro, mais frequentemente "consulta anônima por resolver público". Qualquer resposta estava sendo contada como listagem, então num servidor cujo DNS a Spamhaus trata como resolver público, todo domínio aparecia permanentemente em blocklist — um domínio que sequer existia voltava "listado".
* As respostas de blocklist agora são interpretadas. Uma checagem que não pôde rodar é reportada como indisponível: não levanta alerta, e também não é dobrada em "limpo", porque uma verificação de reputação que nunca rodou é coisa que você deve saber, não algo a esconder. Note que, em hospedagens que usam resolver DNS público, as checagens Spamhaus corretamente reportarão como indisponíveis até que uma chave DQS seja configurada — elas param de reportar listagens falsas, mas não conseguem rodar sem a chave.
* **Corrigido: apenas um dos endereços IP do site era verificado.** Sites atrás de DNS round-robin ou de uma CDN respondem com vários endereços, e só o primeiro era testado — e qual deles variava entre execuções, porque resolvers rodam a ordem. Um endereço em blocklist podia passar dias sem ser reportado e então surgir do nada. Todos os endereços passam a ser verificados, e um endereço listado marca o site.
* Corrigido: e-mails de alerta que levavam detalhes estruturados imprimiam a palavra "Array" no lugar dos valores. Afetava qualquer alerta com contexto aninhado — o alerta de blocklist exibia "Array, Array, Array" onde deveriam estar os resultados por checagem.

## 1.6.2
* **Corrigido: uma atualização de core do WordPress podia ser reportada como comprometimento, de hora em hora, indefinidamente.** O monitor de integridade comparava arquivos críticos de core contra uma referência registrada neste site. Uma referência só diz que o arquivo não é mais o que era — o que é igualmente verdade para uma atualização de rotina, e atualizações de core reescrevem esses arquivos legitimamente. Atualizações que não passam pelo atualizador do próprio WordPress nunca renovavam a referência: auto-atualizações em segundo plano, WP-CLI e painéis de hospedagem caem todos nessa lacuna. A referência velha então produzia um e-mail crítico de "arquivo modificado" a cada hora, para um arquivo que era WordPress oficial intocado.
* O monitor agora consulta o manifesto oficial do WordPress.org para a versão em uso antes de levantar qualquer coisa. Um arquivo que seja byte a byte o release oficial é adotado como nova referência, em silêncio. Um arquivo que difira do release oficial segue alertando, assim como um que não possa ser confirmado — o `wp-config.php` não é distribuído pelo core, e o WordPress.org pode estar inacessível. Desconhecido não é tratado como seguro.
* **Corrigido: "Login de admin de um IP novo" disparava em quase todo login de uma conexão doméstica inalterada.** O IPv6 residencial rotaciona a metade final do endereço a cada poucas horas, então um único roteador emite um fluxo infinito de endereços distintos. Num site real isso significou oito endereços "novos" em onze logins, todos da mesma rede — e um alerta que grita lobo é um alerta que se para de ler.
* A detecção de IP novo passa a comparar a rede em vez do endereço exato: o prefixo /64 para IPv6, o endereço inteiro para IPv4. Alargar também o IPv4 agruparia clientes sem relação do mesmo provedor e enfraqueceria um sinal que funciona. Endereços já registrados são dobrados em suas redes na leitura, então a mudança não anuncia redes que a conta já usou.

## 1.6.1
* **Corrigido: trocar a senha de um usuário pela tela de perfil falhava com erro fatal.** A verificação de senha vazada declarava o tipo errado para um de seus argumentos — o WordPress passa ali um objeto parcialmente construído, não um usuário completo — e o descompasso abortava o salvamento. Presente desde a 1.0.3 e disparado a cada troca de senha pela tela de perfil.
* Corrigido: criar um usuário novo também podia falhar na mesma verificação, que pressupunha um ID de usuário que ainda não existe naquele ponto. A rejeição de senha fraca continua valendo na criação; apenas o registro de controle é pulado.
* Corrigido: dois tratadores de falha de login exigiam um argumento que o WooCommerce e formulários de login personalizados nem sempre enviam, o que podia produzir erro fatal na página de login. Agora toleram a ausência dele.

## 1.6.0
* **Novo: API de integração somente leitura.** Sistemas que preferem puxar a receber agora podem ler o log de auditoria, o log de tráfego, os resultados de varredura e o estado do firewall por REST, autenticados com token. Isso fecha o trabalho de integrações iniciado na 1.5.0.
* Novo: os tokens de API são gerenciados em Ferramentas → Integrações. Cada integração ganha o próprio token, para que um possa ser revogado sem incomodar os demais. Os tokens são guardados com hash — o texto puro é exibido uma vez, na criação, e não pode ser recuperado depois.
* A API é somente leitura por projeto: não há endpoint que altere nada, então um token vazado não pode ser usado para mexer na proteção do seu site.
* As coleções são paginadas por cursor, não por deslocamento. Esses logs crescem entre as chamadas de um cliente, e com deslocamento o cliente silenciosamente releria ou pularia registros toda vez que isso acontecesse.
* Limite de requisições por token, deliberadamente abaixo do teto REST do próprio firewall, para que um cliente movimentado receba uma resposta clara de "limite excedido" em vez de ser bloqueado pelo WAF sem explicação.
* Falhas repetidas de autenticação vindas de um mesmo endereço são bloqueadas e registradas no log de auditoria — sondar em busca de um token válido é coisa que você deve conseguir ver.
* Compatível com hospedagem Apache/CGI, que remove o cabeçalho Authorization antes de o PHP vê-lo; as variantes reescritas são lidas como alternativa.

## 1.5.0
* **Novo: webhooks de saída (Ferramentas → Integrações).** Envie eventos de segurança para Slack, Discord, PagerDuty ou qualquer SIEM conforme acontecem. Até 10 destinos, cada um com seu limite de severidade — assim um canal de chat pode receber só os eventos críticos enquanto um SIEM recebe tudo. Cada destino recebe o formato de payload que de fato espera, e um botão "Testar" informa exatamente o que o destino respondeu.
* Novo: payloads genéricos (SIEM) podem ser assinados com HMAC-SHA256, incluindo horário, para que um payload capturado não possa ser reenviado depois.
* Alterado: a entrega de webhook é enfileirada durante a requisição e enviada depois que a resposta chega ao navegador, então um destino lento ou inacessível nunca acrescenta latência ao seu site. As falhas são registradas e exibidas por destino, em vez de sumirem em silêncio.
* Alterado: os destinos de webhook ficam fora do pacote de exportação de configurações. Eles carregam credenciais ativas — segredos de assinatura, chaves de roteamento do PagerDuty e, no caso de Slack e Discord, a própria URL — que não cabem num arquivo que você baixa e repassa.
* Alterado: os destinos precisam usar HTTPS. Esses payloads descrevem ataques contra o seu site e não trafegam em texto aberto.
* Nota: a implementação anterior de webhook nunca foi alcançável — a configuração de que dependia não tinha interface e nunca era registrada, então não havia como disparar. Esta versão a substitui.

## 1.4.1
* Corrigido: a tela de Ferramentas exibia "View not found" em todas as abas no pacote da 1.4.0. Um erro de empacotamento deixou os cinco templates de aba fora do zip — o código do plugin nunca foi afetado, apenas o arquivo gerado. O build agora verifica que toda view está presente antes de produzir um zip.

## 1.4.0
* **Agora roda em PHP 7.4.** A versão mínima de PHP cai de 8.1 para 7.4 — o mesmo piso que o próprio WordPress define — para que o plugin instale em hospedagens compartilhadas mais antigas. Toda construção de PHP 8 do código foi reescrita, e uma verificação em tempo de build (`composer check-php74`) agora reprova a release se alguma voltar.
* **A autenticação de dois fatores deixa de depender de biblioteca externa.** O TOTP (RFC 6238) passa a ser implementado no próprio plugin, conferido contra os vetores de teste oficiais da RFC. Isso removeu três dependências — incluindo uma com dois alertas de segurança publicados — e mantém o 2FA totalmente compatível com Google Authenticator, Authy, 1Password e qualquer outro aplicativo aderente ao padrão. As configurações de 2FA existentes seguem funcionando; não é preciso cadastrar de novo.
* Novo: a linha da base GeoLite2 no Diagnóstico passa a informar versão, estado da última atualização e idade, e avisa se ela ultrapassar a regra de 30 dias de atualidade da MaxMind, em vez de apenas dizer "presente".
* Novo: a atribuição à MaxMind passa a ser exibida no admin, como exigido agora que o plugin distribui a base GeoLite2 pelo próprio feed.
* Alterado: requisições sem User-Agent são classificadas como **Suspeitas**, não como **Robô**. Todo navegador e todo rastreador bem-comportado se identifica, então um User-Agent ausente é anômalo, não um rastreador — e deixa de se esconder no meio do tráfego do Googlebot. O Tráfego ao Vivo ganha um filtro "Suspeito".
* Alterado: os e-mails de alerta passam a usar o mesmo rodapé em português do relatório agendado, em vez de cair para o inglês quando enviados pelo cron.
* Alterado: o build de release passa a remover as fontes DejaVu Serif e Mono, não usadas, do motor de PDF, cortando cerca de 3 MB do download. A renderização do relatório é idêntica byte a byte.
* Corrigido: `Tested up to` passa a refletir o WordPress 7.0, e a seção de privacidade documenta os downloads do feed de ameaças e do GeoLite2, antes não declarados.

## 1.3.1
* Corrigido: o botão "Verificar agora" (Todas as Opções → Firewall) agora também baixa e atualiza a base GeoLite2 sob demanda, não apenas as regras do WAF — então você não precisa mais esperar a tarefa agendada para instalar a geolocalização. O resultado dos dois é exibido.

## 1.3.0
* Novo: a base de geolocalização GeoLite2 passa a se instalar e se atualizar sozinha pelo feed assinado — sem envio manual por site. Os dados de país (widget do painel, relatório de atividade, bloqueio por país) começam a funcionar por conta própria depois da próxima atualização agendada. A base é verificada (SHA-256 + manifesto assinado) antes do uso e mantida atual automaticamente. Inclui dados GeoLite2 criados pela MaxMind (https://www.maxmind.com).

## 1.2.1
* Corrigido: o widget "Principais países" do painel não fica mais eternamente em "carregando" — agora exibe os países mais bloqueados (últimos 7 dias), ou um estado vazio claro / "configure o GeoLite2" quando ainda não há dados de país.
* Novo: o tráfego de requisições é geolocalizado (pela base GeoLite2) e o país é armazenado, para que o widget do painel e a seção de países do relatório de atividade tenham dados. Requer o GeoLite2-Country.mmdb no diretório data/ do plugin.

## 1.2.0
* Novo: o relatório de atividade — tanto o e-mail quanto o PDF anexo — passa a cobrir o que um administrador de segurança espera ver de relance: componentes que precisam de atualização (vindos da varredura de vulnerabilidades), países mais bloqueados, usuários com mais falhas de login, ataques bloqueados recentemente e arquivos modificados recentemente, além do resumo já existente de ataques, logins e principais IPs.
* Corrigido: a contagem de "regras" do firewall passa a refletir as regras de fato em vigor (regras nativas mais as do feed de ameaças), então ela se move quando o feed atualiza, em vez de exibir um número fixo vindo de um arquivo embutido.

## 1.1.0
* Novo: regras do WAF que se atualizam sozinhas (Feed de Ameaças). O firewall passa a buscar um feed assinado de regras em agenda diária e a aplicá-lo sem esperar por uma release do plugin — fechando a lacuna em que as regras só mudavam na atualização. Toda atualização é verificada com assinatura Ed25519 e checksum SHA-256 antes de ser aplicada, e as regras nativas seguem como um piso imutável ao qual o feed só pode somar, nunca enfraquecer. Novos controles de "Feed de Ameaças" em Opções de Firewall (liga/desliga e "Verificar agora"), mais uma linha de estado em Ferramentas → Diagnóstico.
* Interno: o motor de regras do firewall passa a ser orientado a dados (`JsonRule` / `RuleRepository`), ao lado das regras nativas; a escrita do feed é atômica, com reversão de um nível e guarda de versão contra retrocesso. +36 testes (126 no total).

## 1.0.27
* Novo: relatório de segurança em PDF agendado. O relatório periódico de atividade passa a poder viajar como PDF anexo, na identidade visual da Digital Pixel, no mesmo e-mail diário, semanal ou mensal, e um botão "Baixar PDF" na tela de Todas as Opções gera o relatório sob demanda. Renderizado no próprio servidor, sem serviço externo.
* Os dados do PDF e do e-mail em HTML passam a vir de um coletor único (`ReportData`), então os dois sempre refletem os mesmos números.

## 1.0.26
* Interno: cobertura automatizada de testes estendida aos módulos críticos de segurança que ainda não a tinham — escalonamento de bloqueio por força bruta, referência e diferença de adulteração da autoproteção, códigos de recuperação do 2FA e o honeypot de formulário (86 testes no total). Refatorações puras para expor pontos testáveis; sem mudança de comportamento.

## 1.0.25
* Novo: scanner de vulnerabilidades (etapa 9 da varredura). Aponta plugins e temas instalados rodando versão desatualizada — a porta de entrada mais comum no mundo real — usando os próprios dados de atualização do WordPress, sem requisição externa e sem exigir chave de API. Opcionalmente enriquece os resultados com CVEs conhecidos da base de vulnerabilidades do WPScan, quando há um token configurado.
* Esquema: `scan_results.issue_type` ganha `vulnerable_version`; instalações existentes são migradas automaticamente na atualização.

## 1.0.24
* Robustez: o fluxo do WAF anterior ao WordPress passa a ser totalmente seguro contra nulos — a lista de IPs bloqueados, o bloqueador por país e o bloqueador de padrões personalizados todos degradam com elegância quando `$wpdb` não está disponível (contexto de Proteção Estendida), completando a guarda da v1.0.19.
* Interno: suíte de testes automatizados de volta ao verde (56 passando) e cobertura direta para a lógica de bypass do WAF antecipado e para a cadeia de hashes do log de auditoria.

## 1.0.23
* Interface: sistema visual unificado em todas as telas do admin — cartões com sombra suave, medidores refinados, cabeçalhos de tabela em versalete, abas sublinhadas e ícones SVG de seção.

## 1.0.22
* Interface: tela de Varredura redesenhada — indicador de progresso por etapa (cadeado → girando → confirmado), etiquetas de severidade e títulos de resultado legíveis no lugar de identificadores crus.
* Interface: todo emoji substituído por ícones SVG embutidos, para que os símbolos apareçam idênticos em qualquer navegador e sistema operacional.
* Varredura: nova seção "Recomendações" separa avisos de robustez e achados de baixa confiança das ameaças reais — eles deixam de inflar a contagem de problemas.

## 1.0.21
* Scanner: corrigidos falsos positivos em massa. A integridade de core passa a comparar sempre contra o manifesto de checksums en_US, então instalações localizadas (pt-BR, por exemplo) deixam de acusar arquivos intocados do core como modificados.
* Scanner: o version.php e outros arquivos de core que variam legitimamente ficam fora da comparação de checksum (seguem sendo varridos por conteúdo em busca de malware).
* Scanner: novo classificador de ameaça/recomendação — apenas achados de alta confiança contam como problema e disparam alerta crítico.
* Scanner: o cache de checksums passa a ser indexado pela versão do WordPress, então uma atualização de core invalida o manifesto velho em vez de comparar contra ele por um dia.

## 1.0.20
* Alertas: e-mails de alerta e de relatório de atividade redesenhados — linhas de assunto legíveis, estilo de severidade discreto (sem faixa vermelha de ponta a ponta) e títulos de evento em linguagem humana.
* Alertas: "login de admin de um IP novo" rebaixado de Crítico para Aviso; é um evento de rotina.

## 1.0.19
* Firewall: a Proteção Estendida deixa de provocar erro HTTP 500 no wp-admin e ao salvar no construtor de páginas (Elementor) — acrescentado um desvio por URI e por cookie de usuário logado para requisições que rodam antes de o WordPress carregar.
* Firewall: guarda contra `$wpdb` nulo no IpBlocklist, para o contexto anterior ao WordPress.
* Banco de dados: criação de tabelas autocorretiva no boot; acrescentada a origem de bloqueio `auto_anomaly` ao esquema.

## 1.0.14
* REST: proteção de buffer de saída impede que avisos avulsos do PHP corrompam respostas JSON em hospedagens com depuração ligada.
* Autoproteção: a referência de detecção de adulteração passa a considerar a versão — acabam os falsos alertas de "arquivos modificados" depois de uma atualização legítima.
* Login: corrigido o bloqueio de todos os administradores no login — a interceptação de 2FA passa a verificar se o 2FA está de fato configurado para o usuário, não apenas exigido pela função.
* Login: bloquear o nome de usuário "admin" passa a ser opcional (vinha silenciosamente ligado por padrão).

## 1.0.4 – 1.0.13
* Corrigido um erro de REST no painel e um problema de COUNT nas estatísticas de tráfego.
* Boot do plugin tornado resistente a erros no momento da ativação.
* Corrigidos quatro problemas na ferramenta de consulta WHOIS.
* Corrigido o tratamento de redirecionamento do `dpxl_2fa_required` no 2FA.

## 1.0.0
* Versão inicial.
* Web Application Firewall (modos estendido e básico).
* Scanner de integridade de arquivos com assinaturas de malware.
* Autenticação de dois fatores por TOTP.
* Proteção contra força bruta com bloqueio.
* Log de auditoria com cadeia de hashes SHA-256.
* Monitoramento de tráfego em tempo real e detecção de robôs.
* Bloqueio por país via GeoIP (MaxMind GeoLite2).
* Ferramenta de consulta WHOIS.
* Importação e exportação de configurações.
* Diagnóstico de 16 pontos.
* Autoproteção do plugin (detecção de adulteração e guarda de desativação).
