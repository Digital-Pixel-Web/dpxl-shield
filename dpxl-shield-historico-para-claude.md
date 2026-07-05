# DPXL Shield — Histórico de Ajustes e Contexto para o Claude

## Objetivo geral

Estamos construindo o plugin **DPXL Shield**, um plugin de segurança para WordPress inspirado no fluxo de experiência do Wordfence, mas com identidade visual da **Digital Pixel / DPXL Shield**.

O plugin deve ter:

- firewall/WAF;
- proteção estendida via `auto_prepend_file`;
- scan de malware/integridade;
- segurança de login e 2FA;
- ferramentas como tráfego ao vivo, auditoria, consulta Whois, importação/exportação e diagnóstico;
- interface administrativa em **português do Brasil**;
- fluxo seguro para alteração de `.htaccess`, `.user.ini` e remoção na desinstalação.

---

## Arquivos base usados durante o processo

O desenvolvimento partiu de diferentes versões do plugin, sempre instalando por cima da anterior. As versões geradas ao longo da conversa foram:

1. `dpxl-shield-corrigido.zip`
2. `dpxl-shield-wordfence-flow.zip`
3. `dpxl-shield-auto-htaccess.zip`
4. `dpxl-shield-auto-htaccess-manual-fallback.zip`
5. `dpxl-shield-safe-uninstall.zip`
6. `dpxl-shield-enable-feedback.zip`
7. `dpxl-shield-litespeed-validation-fix.zip`
8. `dpxl-shield-scan-progress-fix.zip`
9. `dpxl-shield-scan-tuning.zip`
10. `dpxl-shield-ptbr-logo.zip`
11. `dpxl-shield-ptbr-2fa.zip`
12. `dpxl-shield-ptbr-2fa-shield-icon.zip`
13. `dpxl-shield-ptbr-consistencia-tools.zip`
14. `dpxl-shield-whois-url-fix.zip`
15. `dpxl-shield-litespeed-userini-fallback.zip`

A versão mais recente a considerar é:

```txt
dpxl-shield-litespeed-userini-fallback.zip
```

Ela foi gerada depois que o usuário enviou novamente o arquivo `dpxl-shield(1).zip` e reportou erro no fluxo da Proteção Estendida em LiteSpeed.

---

## 1. Correções iniciais do dashboard e REST API

### Problema identificado

O dashboard e algumas telas ficavam presas em estados como:

```txt
Loading...
Checking extended protection status...
```

Também havia aviso persistente:

```txt
DPXL Shield — Extended Protection is not active. Your firewall loads after WordPress, reducing protection.
```

O link “Enable now” não funcionava corretamente.

### Causas prováveis

- A REST API não estava registrada no momento correto.
- O JS administrativo dependia de endpoints que não existiam ou não retornavam dados.
- O link apontava para uma aba inexistente `tab=extended`.
- A tela de Firewall tinha apenas as abas `firewall` e `blocking`.
- O JS da tela Firewall tinha bloco vazio para carregar Top IPs e gauges.

### Ajustes feitos

- REST API registrada corretamente.
- Endpoint de status do Firewall criado/ajustado.
- Endpoint de Top IPs bloqueados criado/ajustado.
- Link “Enable now” redirecionado para área real da tela Firewall.
- JS passou a carregar gauges e tabela de Top IPs.
- Cache de `admin.js` e `admin.css` passou a usar `filemtime()`.

---

## 2. Proteção Estendida — fluxo tipo Wordfence

### Objetivo

Reproduzir o comportamento do Wordfence:

1. usuário baixa backup do `.htaccess`;
2. plugin aplica a configuração automaticamente;
3. plugin valida se o WAF carrega antes do WordPress;
4. se falhar, faz rollback;
5. se não puder gravar, mostra instrução manual.

### Comportamento esperado

O botão **Enable Extended Protection** não deve apenas gravar uma option no banco. Ele deve configurar `auto_prepend_file` para carregar um loader antes do WordPress.

Fluxo esperado:

```txt
Clique no botão
↓
Baixa backup do .htaccess atual
↓
Aplica regra auto_prepend_file
↓
Cria/usa loader seguro
↓
Executa teste loopback real
↓
Se validar: marca Proteção Estendida como ativa
↓
Se falhar: rollback + mensagem clara + fallback manual
```

### Ajustes feitos

- Botão **Download Backup & Enable** criado.
- Botão **Enable Extended Protection** também inicia o fluxo completo.
- Feedback visual em etapas:
  - baixando backup;
  - atualizando `.htaccess`;
  - validando proteção;
  - recarregando tela.
- Fallback via `admin-post.php`, caso REST/JS falhe.
- Rollback automático se validação falhar.
- Bloco manual de fallback mantido sempre disponível na tela, recolhido por padrão.

---

## 3. Segurança na desinstalação

### Problema identificado

Ao desinstalar o plugin, o site poderia cair porque o `.htaccess` mantinha:

```apache
auto_prepend_file "/wp-content/plugins/dpxl-shield/dpxl-shield-waf.php"
```

Quando o plugin era removido, o PHP tentava carregar um arquivo inexistente.

### Decisão técnica

Não apontar o `auto_prepend_file` diretamente para dentro da pasta do plugin.

### Ajuste feito

Criado um **loader seguro intermediário** na raiz do WordPress:

```txt
/dpxl-shield-prepend.php
```

O `.htaccess` passa a apontar para esse arquivo:

```apache
php_value auto_prepend_file "/caminho/absoluto/dpxl-shield-prepend.php"
```

Esse loader tenta carregar o WAF real:

```txt
/wp-content/plugins/dpxl-shield/dpxl-shield-waf.php
```

Mas se o plugin não existir mais, ele simplesmente não faz nada.

### Limpeza na desativação/desinstalação

Na desativação e no `uninstall.php`, o plugin deve:

- remover bloco gerenciado do `.htaccess`;
- remover diretivas de `.user.ini` quando existirem;
- remover/neutralizar diretivas locais de `php.ini`, quando possível;
- transformar `dpxl-shield-prepend.php` em no-op;
- evitar que o site caia caso o plugin seja removido manualmente.

---

## 4. LiteSpeed e validação da Proteção Estendida

### Problema recorrente

Mesmo com o `.htaccess` gravado corretamente, em LiteSpeed aparecia erro:

```txt
Loopback test completed with HTTP 200, but the DPXL Shield prepend marker was not detected.
On LiteSpeed this usually means the <IfModule LiteSpeed> / php_value directive was ignored by the PHP handler or server cache served the response without PHP.
```

### O que foi identificado

O `.htaccess` era gravado com blocos como:

```apache
# BEGIN DPXL Shield Extended Protection
<IfModule LiteSpeed>
    php_value auto_prepend_file "/home/.../dpxl-shield-prepend.php"
</IfModule>
<IfModule lsapi_module>
    php_value auto_prepend_file "/home/.../dpxl-shield-prepend.php"
</IfModule>
<IfModule mod_php.c>
    php_value auto_prepend_file "/home/.../dpxl-shield-prepend.php"
</IfModule>
<IfModule mod_php5.c>
    php_value auto_prepend_file "/home/.../dpxl-shield-prepend.php"
</IfModule>
<IfModule mod_php7.c>
    php_value auto_prepend_file "/home/.../dpxl-shield-prepend.php"
</IfModule>
<IfModule mod_php8.c>
    php_value auto_prepend_file "/home/.../dpxl-shield-prepend.php"
</IfModule>
# END DPXL Shield Extended Protection
```

A gravação estava correta, mas o servidor não aplicava `php_value` no `.htaccess`.

### Ajustes feitos

- Adicionado suporte a `<IfModule LiteSpeed>`.
- Mantido suporte a `lsapi_module`, `mod_php`, `mod_php5`, `mod_php7`, `mod_php8`.
- Validação deixou de testar apenas a home, para evitar cache.
- Plugin passou a criar um **arquivo PHP temporário de teste** e chamar esse arquivo por loopback.
- Loader seguro envia marcador/header:
  - `X-DPXL-Shield-Prepend: active`
  - `X-DPXL-Shield-Extended: active`
- Validação passou a aceitar marcador no header e/ou no corpo da resposta.

### Ajuste mais recente

Como o LiteSpeed pode ignorar `php_value` no `.htaccess`, foi implementado fallback automático via `.user.ini`.

Fluxo atual desejado:

```txt
Tentar .htaccess
↓
Validar por loopback
↓
Se falhar por marcador ausente
↓
Tentar .user.ini com auto_prepend_file
↓
Validar novamente
↓
Se funcionar: marcar ativo e informar método .user.ini
↓
Se falhar: manter modo básico + mostrar fallback manual
```

---

## 5. Scan — progresso e redução de falsos positivos

### Problema inicial

A tela de Scan mostrava estados inconsistentes:

```txt
Scanning: malware_scan...
Files Scanned: 0
No security issues found. Your site is clean.
```

Isso mostrava scan em andamento e resultado final ao mesmo tempo.

### Ajustes feitos

- Progresso real de arquivos escaneados.
- Exibição do arquivo atual.
- Status por etapa:
  - queued;
  - running;
  - failed;
  - cancelled;
  - idle.
- Botão **Cancel Scan** passou a chamar endpoint real.
- Proteção contra scan órfão/travado.
- Mensagem “site limpo” só aparece depois que o scan termina.

### Segundo problema

O scan estava funcionando, mas exagerado/alarmista.

Ele encontrava muitos resultados, vários como `CRITICAL`, incluindo arquivos normais de plugins, temas e posts com links externos.

### Ajustes feitos

- Resultados filtrados para mostrar apenas o último scan.
- Deduplicação de resultados.
- Redução de falsos positivos em:
  - plugins conhecidos;
  - temas;
  - `vendor`;
  - `tests`;
  - `node_modules`;
  - arquivos minificados;
  - bibliotecas comuns.
- Links externos normais em posts/páginas deixaram de ser classificados como problema grave.
- `CRITICAL` reservado para:
  - PHP em `/uploads`;
  - `.env` exposto;
  - backup de `wp-config`;
  - `.git` exposto;
  - webshell claro;
  - malware forte por assinatura;
  - alteração crítica de core.
- Heurísticas em plugins/temas passaram a ser classificadas com mais cautela.
- Botão **Repair All Repairable** só aparece quando houver arquivos realmente reparáveis.

---

## 6. Interface em português e identidade visual

### Solicitação

O usuário pediu:

- plugin todo em português;
- títulos das páginas usando o logo DPXL;
- título no estilo Wordfence, com ícone ao lado;
- menu lateral mantendo ícone de escudo.

### Ajustes feitos

- Tradução de grande parte das telas administrativas para PT-BR.
- Submenu traduzido:
  - Painel;
  - Firewall;
  - Varredura;
  - Segurança de Login;
  - Ferramentas;
  - Todas as Opções.
- Títulos com logo DPXL:
  - Painel do DPXL Shield;
  - Firewall do DPXL Shield;
  - Varredura do DPXL Shield;
  - Segurança de Login do DPXL Shield;
  - Ferramentas do DPXL Shield;
  - Todas as Opções do DPXL Shield.
- Ícone do menu lateral voltou a ser escudo.
- Logo DPXL mantido nos títulos das páginas.

### Arquivos envolvidos

- `src/Admin/AdminMenu.php`
- `assets/css/admin.css`
- `assets/img/dpxl-shield-mark.svg`
- views em `src/Admin/Views/`

---

## 7. Ferramentas — consistência das abas

### Problema identificado

Na tela **Ferramentas**, ao clicar nas sub-abas:

- Tráfego ao vivo;
- Log de auditoria;
- Consulta Whois;
- Importação/Exportação;
- Diagnóstico;

a tela mudava de forma inconsistente.

Apenas **Tráfego ao vivo** continha o wrapper completo com título e menu. As outras telas eram partials sem o mesmo cabeçalho/menu, causando quebra visual.

### Ajuste feito

Criado/ajustado um wrapper único para Ferramentas:

```txt
src/Admin/Views/tools.php
```

Esse wrapper deve conter:

- título “Ferramentas do DPXL Shield”;
- logo DPXL;
- menu de abas sempre igual;
- include do partial correto.

O método `renderTools()` em `AdminMenu.php` deve carregar sempre `tools.php`, e não diretamente `tools/{tab}.php`.

### Fluxo esperado

```php
public function renderTools(): void {
    $tab = sanitize_key($_GET['tab'] ?? 'live-traffic');
    $tabs = ['live-traffic', 'audit-log', 'whois', 'import-export', 'diagnostics'];
    $tab = in_array($tab, $tabs, true) ? $tab : 'live-traffic';

    include self::VIEWS_DIR . 'tools.php';
}
```

Dentro de `tools.php`, incluir o partial:

```php
$partial = __DIR__ . '/tools/' . $currentTab . '.php';
include $partial;
```

---

## 8. Whois Lookup — correção para URL, domínio e IP

### Problema identificado

Na tela **Consulta Whois**, o usuário digitou:

```txt
https://www.globo.com
```

O plugin transformou incorretamente em:

```txt
httpswww.globo.com
```

E retornou:

```txt
Source: invalid_ip
```

### Comportamento correto

A consulta Whois deve aceitar:

```txt
8.8.8.8
globo.com
www.globo.com
https://www.globo.com
https://www.globo.com/alguma/pagina?x=1
```

E normalizar assim:

```txt
https://www.globo.com/qualquer/coisa
↓
www.globo.com
↓
resolver DNS para IP
↓
fazer Whois do IP
```

### Ajustes esperados

- Normalizar entrada:
  - remover protocolo;
  - extrair host;
  - remover path/query/hash;
  - remover porta;
  - tratar IPv4 e IPv6;
  - aceitar domínio puro.
- Se for domínio:
  - resolver via DNS (`dns_get_record`, `gethostbynamel` ou equivalente);
  - selecionar IP válido;
  - fazer Whois do IP resolvido.
- Se for IP:
  - fazer Whois direto.
- Se não houver IP válido:
  - retornar erro claro em português;
  - esconder/desabilitar botões:
    - Bloquear este IP;
    - Bloquear faixa /24;
    - Adicionar à lista de permissões.
- Resultado deve mostrar:
  - consulta original;
  - host normalizado;
  - IP resolvido;
  - organização/ASN/país/faixa, quando disponível.

### Arquivos prováveis

- `src/Tools/WhoisLookup.php`
- `src/Admin/RestApi.php`
- `src/Admin/Views/tools/whois.php`
- `assets/js/admin.js`

---

## 9. 2FA — QR Code e recovery codes

### Problema identificado

A tela de 2FA mostrava:

```txt
Loading QR code...
Loading recovery codes...
Loading...
```

Ou seja, a tela estava visualmente montada, mas sem fluxo funcional.

### Ajustes feitos

- QR Code gerado localmente.
- Chave manual carregando.
- Ativação do 2FA via REST.
- Recovery codes gerados após ativar.
- Download dos códigos funcionando.
- JS específico para QR Code local adicionado.
- Tela traduzida para PT-BR.

### Arquivos prováveis

- `src/LoginSecurity/TwoFactorAuth.php`
- `src/LoginSecurity/BackupCodes.php`
- `src/Admin/RestApi.php`
- `src/Admin/Views/login-security.php`
- `assets/js/admin.js`
- `assets/js/qrcode-local.js`

---

## 10. Pontos importantes para manter

### Não quebrar site na desinstalação

Nunca apontar `auto_prepend_file` diretamente para:

```txt
wp-content/plugins/dpxl-shield/dpxl-shield-waf.php
```

Sempre apontar para:

```txt
/dpxl-shield-prepend.php
```

### Não fingir Proteção Estendida ativa

O plugin só pode mostrar Proteção Estendida ativa se o teste real detectar o prepend.

Critério:

```txt
DPXL_SHIELD_PREPEND_LOADED
ou header X-DPXL-Shield-Prepend: active
ou header X-DPXL-Shield-Extended: active
```

### Sempre manter fallback manual

Mesmo com configuração automática, a tela deve sempre conter um bloco de configuração manual para:

- `.htaccess`;
- `.user.ini`;
- `php.ini`;
- Nginx/PHP-FPM.

### Em LiteSpeed

A ordem de tentativa recomendada agora é:

1. `.htaccess`;
2. validação;
3. se falhar, `.user.ini`;
4. validação;
5. se falhar, instrução manual.

### Ao desativar/desinstalar

Limpar:

- bloco do `.htaccess`;
- diretiva do `.user.ini`;
- diretiva do `php.ini` local quando possível;
- loader seguro ou deixá-lo no-op.

---

## 11. Pendências/revisão recomendada

1. Garantir que o arquivo mais recente (`dpxl-shield-litespeed-userini-fallback.zip`) contenha também:
   - correção do Whois;
   - consistência das abas em Ferramentas;
   - PT-BR ampliado;
   - logo nos títulos;
   - ícone de escudo no menu;
   - 2FA funcional.

2. Revisar strings ainda em inglês, especialmente:
   - textos longos da Proteção Estendida;
   - labels em All Options;
   - mensagens REST;
   - mensagens JS;
   - botões e estados de Diagnóstico;
   - retornos de Whois.

3. Testar em ambiente real:
   - Apache;
   - LiteSpeed;
   - OpenLiteSpeed;
   - PHP-FPM com `.user.ini`;
   - ambiente onde `.htaccess` não é gravável;
   - ambiente com cache de servidor.

4. Testar uninstall:
   - desativar plugin;
   - apagar plugin;
   - verificar se site continua abrindo;
   - confirmar se `.htaccess` e `.user.ini` foram limpos.

5. Testar Whois:
   - IP direto;
   - domínio sem protocolo;
   - URL com `https://`;
   - URL com path/query;
   - domínio inválido.

6. Testar Scan:
   - iniciar;
   - cancelar;
   - reexecutar;
   - verificar se não mostra resultados antigos;
   - verificar se não gera falsos positivos excessivos.

7. Testar 2FA:
   - carregar QR Code;
   - baixar recovery codes;
   - ativar;
   - fazer logout;
   - login com código correto;
   - login com recovery code;
   - desativar.

---

## 12. Mensagem curta para orientar o Claude

Claude, considere o plugin DPXL Shield como um plugin WordPress de segurança em desenvolvimento. O objetivo atual é estabilizar a versão mais recente, mantendo todas as melhorias já feitas:

- interface em PT-BR;
- título com logo DPXL;
- ícone de escudo no menu;
- Ferramentas com wrapper único e abas consistentes;
- Whois aceitando IP, domínio e URL completa;
- 2FA com QR Code/recovery codes;
- scan com progresso real e menos falso positivo;
- Proteção Estendida estilo Wordfence;
- backup do `.htaccess` antes de alterações;
- loader seguro `/dpxl-shield-prepend.php`;
- rollback se validação falhar;
- limpeza segura na desativação/desinstalação;
- fallback automático para `.user.ini` quando LiteSpeed ignora `php_value` no `.htaccess`.

Não remova nenhuma dessas melhorias ao corrigir bugs novos.

---

## 13. Critérios de aceite gerais

### Proteção Estendida

- botão baixa backup e aplica configuração;
- se `.htaccess` falhar em LiteSpeed, tenta `.user.ini`;
- só mostra ativo se teste real confirmar;
- não derruba site ao desinstalar;
- fallback manual sempre visível/expandível.

### Interface

- nenhuma aba de Ferramentas perde o título/menu;
- textos principais em PT-BR;
- títulos com logo DPXL;
- menu lateral com escudo.

### Whois

- `https://www.globo.com` deve virar `www.globo.com`;
- domínio deve resolver para IP;
- botões de bloqueio só aparecem se houver IP válido.

### Scan

- não mostrar “site limpo” enquanto scan está rodando;
- progresso deve sair de zero;
- resultados não devem ser históricos/duplicados;
- severidade não deve ser alarmista.

### 2FA

- QR Code aparece;
- chave manual aparece;
- código do app ativa 2FA;
- recovery codes baixam;
- login exige 2FA depois de ativado.
