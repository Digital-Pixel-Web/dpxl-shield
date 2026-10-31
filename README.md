<p align="center">
  <img src="assets/img/dpxl-shield-mark.svg" width="96" height="96" alt="DPXL Shield">
</p>

<h1 align="center">DPXL Shield</h1>

<p align="center">
  <strong>Segurança para WordPress, gratuita e de código aberto.</strong><br>
  Firewall, varredura de malware, proteção de login e alertas — num plugin só, sem plano pago.
</p>

<p align="center">
  <a href="https://github.com/Digital-Pixel-Web/dpxl-shield/releases/latest"><img alt="Última versão" src="https://img.shields.io/github/v/release/Digital-Pixel-Web/dpxl-shield?label=vers%C3%A3o&color=111111"></a>
  <img alt="WordPress 6.4+" src="https://img.shields.io/badge/WordPress-6.4%2B-21759b">
  <img alt="PHP 7.4+" src="https://img.shields.io/badge/PHP-7.4%2B-777bb4">
  <a href="LICENSE"><img alt="Licença GPLv2+" src="https://img.shields.io/badge/licen%C3%A7a-GPLv2%2B-green"></a>
</p>

<p align="center">
  <a href="https://github.com/Digital-Pixel-Web/dpxl-shield/releases/latest"><strong>Baixar o plugin</strong></a> ·
  <a href="https://digitalpixel.com.br/shieldwp/">Site do projeto</a> ·
  <a href="#perguntas-frequentes">Perguntas frequentes</a> ·
  <a href="#english">English</a>
</p>

---

## Por que existe

A maioria dos sites WordPress invadidos não cai por um ataque sofisticado. Cai por senha fraca, plugin desatualizado ou um arquivo alterado que ninguém percebeu. O DPXL Shield cuida dessas portas de entrada e avisa você, em português claro, quando algo precisa da sua atenção.

Ele é mantido pela [Digital Pixel](https://digitalpixel.com.br/), que desenvolve e cuida de sites WordPress no dia a dia, e é distribuído de graça para a comunidade.

## O que ele faz

### 🧱 Bloqueia ataques antes que cheguem ao site
- **Firewall de aplicação (WAF)** com regras para injeção de SQL, XSS, inclusão de arquivos, travessia de diretórios e execução de comandos.
- **Proteção Estendida (opcional):** o firewall passa a rodar *antes* do WordPress carregar, via `auto_prepend_file`. O plugin faz a configuração e desfaz sozinho se a hospedagem não aceitar.
- **Bloqueio de IPs e faixas** (IPv4 e IPv6), **bloqueio por país** e **limite de requisições** no login, no XML-RPC e na API REST.
- **Regras próprias** por user-agent, referer ou URL, e lista de endereços liberados.
- **Armadilhas (honeypots):** campos invisíveis no login, cadastro e comentários, e endereços-isca (`.env`, `phpinfo.php`, `.git/config`…) que só robôs visitam.

### 🔍 Procura problemas no seu site
- **Integridade do WordPress:** compara cada arquivo do core com os checksums oficiais do WordPress.org.
- **Malware:** procura assinaturas conhecidas de backdoors, webshells e código ofuscado.
- **Plugins e temas desatualizados**, com consulta opcional de vulnerabilidades conhecidas (CVE) via WPScan.
- **Conteúdo suspeito** em posts e páginas: iframes, scripts externos e links escondidos.
- **Reputação do domínio** no Google Safe Browsing e na Spamhaus (com chave própria).
- **Reparo em um clique** de arquivos do core e de plugins do WordPress.org, com backup do arquivo original.

### 🔐 Protege o login
- **Bloqueio progressivo** contra tentativa e erro de senha (5 minutos, 1 hora, 24 horas).
- **Autenticação em dois fatores (2FA)** com Google Authenticator, Authy, 1Password e similares, com códigos de recuperação.
- **Verificação de senha vazada** (Have I Been Pwned), sem enviar a senha: só os 5 primeiros caracteres do hash.
- Mensagens de erro de login genéricas, bloqueio de enumeração de usuários e opção de desligar o XML-RPC.

### 📣 Avisa quando importa
- **E-mail a cada entrada de administrador** e alerta especial quando a entrada vem de uma rede nova.
- **Alertas de eventos críticos:** arquivo do core alterado, malware encontrado, plugin de segurança desativado.
- **Relatório semanal ou mensal** por e-mail, com PDF.
- **Monitoramento do próprio envio de e-mails:** se o site parar de conseguir mandar e-mail, você fica sabendo por outro canal.
- **Integrações:** webhooks assinados para Slack, Discord, PagerDuty ou qualquer SIEM, e API REST somente leitura com tokens.

### 🧾 Mostra o que está acontecendo
- **Tráfego ao vivo**, com separação entre pessoas, robôs, suspeitos e bloqueados.
- **Log de auditoria** de logins, usuários, plugins, temas e configurações, encadeado por hash para revelar edições.
- **Diagnóstico** do servidor e da configuração, e consulta WHOIS/GeoIP com bloqueio em um clique.

## O que ele não faz

Ser claro sobre os limites também é segurança.

- **Não faz backup.** Use um plugin ou serviço de backup à parte. Segurança não substitui cópia de segurança.
- **Não é um firewall na nuvem.** Ele roda no seu servidor; não segura ataques de negação de serviço (DDoS) de grande volume. Para isso, use uma CDN como a Cloudflare.
- **Não limpa um site já invadido sozinho.** Ele encontra e repara arquivos do core e de plugins do WordPress.org; temas e arquivos personalizados precisam de revisão humana.
- **Não atualiza seus plugins.** Ele aponta o que está desatualizado e leva você à tela de atualizações.
- **Não envia alertas por WhatsApp ou SMS.** Os canais são e-mail e webhooks.
- **Não obriga o 2FA por função de usuário** (ainda): cada pessoa ativa o próprio.

## Instalação

1. Baixe o arquivo **`dpxl-shield.zip`** na [página de releases](https://github.com/Digital-Pixel-Web/dpxl-shield/releases/latest).
   > Use o pacote da release, não o botão verde "Code → Download ZIP". O pacote da release já inclui as dependências.
2. No painel do WordPress, vá em **Plugins → Adicionar novo → Enviar plugin** e envie o arquivo.
3. Ative o plugin e abra **DPXL Shield → Painel**.

Depois, recomendamos:

- **Ativar o 2FA** na sua conta, em **DPXL Shield → Segurança de Login**.
- **Ligar a Proteção Estendida** em **DPXL Shield → Firewall**. O plugin pede um backup do `.htaccess` antes de mexer em qualquer coisa.
- Conferir o **Diagnóstico** em **DPXL Shield → Ferramentas**.

### Site atrás de proxy ou CDN

O DPXL Shield só acredita no IP informado por cabeçalhos como `X-Forwarded-For` quando a conexão vem de um proxy confiável, para que ninguém consiga se passar por outro endereço. Cloudflare e proxies na rede local já são reconhecidos. Se o site usa outra CDN ou proxy, informe os endereços dela no `wp-config.php`:

```php
define('DPXL_SHIELD_TRUSTED_PROXIES', '192.0.2.0/24, 198.51.100.10');
```

O Diagnóstico avisa quando encontra um cabeçalho de proxy que está sendo ignorado.

## Requisitos

| | Mínimo |
|---|---|
| WordPress | 6.4 |
| PHP | 7.4 (extensões `openssl`, `json`, `mbstring`) |
| Opcional | APCu para cache em memória; `auto_prepend_file` liberado para a Proteção Estendida |

## Privacidade

Os dados ficam no banco do seu site. O plugin não envia telemetria e nada vai para servidores da Digital Pixel. As únicas conexões externas são:

| Serviço | Para quê | Quando |
|---|---|---|
| `api.wordpress.org` | checksums oficiais do core | varredura |
| `raw.githubusercontent.com`, `downloads.wordpress.org` | arquivos originais para reparo | ao reparar um arquivo |
| `api.pwnedpasswords.com` | senha vazada (k-anonimato) | login e troca de senha |
| `cdn.jsdelivr.net` | atualização assinada das regras do firewall | diariamente, pode ser desligado |
| `github.com` | base de países GeoLite2 | quando há versão nova, pode ser desligado |
| `ip-api.com` | WHOIS/GeoIP | quando você faz uma consulta |
| `safebrowsing.googleapis.com`, Spamhaus | reputação do domínio | só com chave configurada |
| `wpscan.com` | vulnerabilidades conhecidas | só com token configurado |

Este produto inclui dados GeoLite2 criados pela MaxMind, disponíveis em [maxmind.com](https://www.maxmind.com).

## Perguntas frequentes

**Deixa o site mais lento?**
O firewall é leve e usa cache em memória quando o servidor tem APCu. O registro de tráfego é gravado depois que a página já foi entregue ao visitante.

**Funciona junto com outro plugin de segurança?**
Funciona, mas dois firewalls fazendo o mesmo trabalho só somam custo. Se for manter os dois, desligue o firewall de um deles.

**E se eu ficar trancado fora do site?**
Os bloqueios automáticos por erro de senha expiram sozinhos. Se precisar de acesso imediato, renomeie a pasta `wp-content/plugins/dpxl-shield` por FTP: o plugin é desativado e a Proteção Estendida vira um arquivo inofensivo.

**É gratuito mesmo?**
É. Sem versão paga, sem recurso bloqueado e sem anúncio dentro do painel.

## Para desenvolvedores

```bash
composer install
composer check        # verificação de compatibilidade com PHP 7.4 + testes
tools/build-zip.sh    # gera o pacote de release em ../dpxl-shield-<versão>.zip
```

Para lançar uma versão: atualize a versão em `dpxl-shield.php` (cabeçalho e `DPXL_SHIELD_VERSION`) e o `Stable tag` do `readme.txt`, escreva a seção no `CHANGELOG.md` e crie a tag (`git tag v1.12.1 && git push origin v1.12.1`). O GitHub Actions roda os testes, gera o zip e publica a release com o arquivo `dpxl-shield.zip`.

O código fica em `src/`, organizado por módulo (`Firewall`, `Scanner`, `LoginSecurity`, `Alerts`…). Os testes usam PHPUnit e Brain Monkey e rodam sem WordPress instalado.

Encontrou uma falha de segurança? Não abra uma issue pública: use o relato privado em [Security → Report a vulnerability](https://github.com/Digital-Pixel-Web/dpxl-shield/security/advisories/new) (veja [SECURITY.md](SECURITY.md)).

Sugestões e correções são bem-vindas por issue ou pull request.

## Licença

GPLv2 ou posterior. Feito pela [Digital Pixel](https://digitalpixel.com.br/) para a comunidade WordPress.

---

## English

**DPXL Shield** is a free, open-source WordPress security plugin: a web application firewall that can run before WordPress loads, a malware and file-integrity scanner, brute-force protection, TOTP two-factor authentication, email alerts, live traffic and a tamper-evident audit log. It has no paid tier and sends no telemetry.

Download the release package from the [Releases page](https://github.com/Digital-Pixel-Web/dpxl-shield/releases/latest) (not the source-code ZIP, which lacks dependencies) and upload it under **Plugins → Add New → Upload Plugin**. The admin interface is currently in Brazilian Portuguese; an English interface is planned.
