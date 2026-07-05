# DPXL Shield — Blueprint Técnico de Arquitetura
**Versão:** 1.4 — Extended Protection bypass + $wpdb null-guard (v1.0.19)  
**Data:** 2026-07-05

---

## 1. Identidade e Posicionamento

**Nome:** DPXL Shield  
**Tagline:** "Security that runs before WordPress does."
**Desenvolvido por:** Digital Pixel  
**Author URI:** https://digitalpixel.com.br/  
**Plugin URI:** https://digitalpixel.com.br/dpxl-shield  
**Text Domain:** `dpxl-shield`  
**Plugin Folder:** `dpxl-shield/`  
**PHP Namespace:** `DPXL\\Shield`

### Diferenciação em relação ao Wordfence

| Dimensão | Wordfence | DPXL Shield |
|---|---|---|
| Regras WAF para free | 30 dias de delay | Tempo real (sem delay) |
| Extended protection | Manual, complexo | Automático (wizard + rollback) |
| Auto-proteção do scanner | Vulnerável a tampering | Checksums criptograficamente assinados |
| Detecção comportamental | Não (só assinaturas) | Sim (anomalia de taxa + padrões) |
| Honeypots | Não | Sim (decoy endpoints) |
| Log de auditoria | Requer Wordfence Central | Imutável local (hash chain), sem dependência externa |
| PHP em /uploads/ | Alerta passivo | Bloqueia execução no servidor |
| Modelo de ameaça ao próprio plugin | Não tratado | Módulo dedicado de auto-defesa |
| Bloqueio por país | Premium | Free |
| Custom Pattern blocking | Sim (user-agent, referrer, hostname) | Sim |
| Whois Lookup integrado | Sim | Sim |
| Repair de arquivos corrompidos | Sim (core + plugins) | Sim (core + plugins + DPXL Shield) |
| Reputation/Blocklist check | Sim | Sim (Google Safe Browsing + Spamhaus) |
| All Options unificado com busca | Sim | Sim |

### Modelo Free / Premium

**Free (todos os recursos de proteção core):**
- WAF com regras em tempo real
- Scanner de malware e integridade de arquivos
- Login security + 2FA
- Honeypots
- Bloqueio de execução PHP em /uploads/
- Log de tráfego (últimas 24h)
- Alertas por e-mail

**Premium (escala e gestão):**
- Wordfence Central equivalente (múltiplos sites em dashboard único)
- Log de tráfego estendido (90 dias)
- Relatórios PDF agendados
- API de integração (SIEM, Slack, PagerDuty)
- Suporte prioritário
- Threat intelligence feed proprietário com IOCs exclusivos

> **Princípio:** proteção não é paywalled. Gestão e escala são.

---

## 2. Arquitetura de Alto Nível

```
[Internet Request]
       │
       ▼
[Nginx / Apache]
       │
       ▼
[PHP Runtime]
       │
       ├─── auto_prepend_file ──► [DPXL Shield Loader] ◄─── Extended Mode
       │                                │
       │                         [WAF Engine]
       │                         [IP Blocklist]
       │                         [Rate Limiter]
       │                                │
       │                         BLOCK ─┤─ PASS
       │                                │
       ▼                                ▼
[WordPress Core]               [WordPress Core]
       │
[plugins_loaded hook]
       │
[DPXL Shield Plugin Init] ◄─── Basic Mode (fallback)
       │
  ┌────┴────────────────────────────────┐
  │           MÓDULOS ATIVOS            │
  ├─────────────────────────────────────┤
  │ LoginSecurity │ TrafficMonitor      │
  │ FileIntegrity │ SelfProtection      │
  │ AlertManager  │ AdminUI             │
  └─────────────────────────────────────┘
```

---

## 3. Módulos — Responsabilidades

### 3.1 Bootstrap / Loader
**Arquivo:** `src/Bootstrap/Loader.php`  
**Referenciado em:** `auto_prepend_file` via `dpxl-shield-waf.php` (raiz do plugin)

Responsabilidades:
- Carregar apenas o mínimo necessário para o WAF funcionar (sem carregar WordPress)
- Instanciar `FirewallEngine`, `IpBlocklist`, `RateLimiter`
- Decidir BLOCK vs PASS antes de qualquer bootstrap do WordPress
- Registrar tempo de início para métricas de overhead

Lógica de modo:
```php
// dpxl-shield-waf.php (referenciado pelo auto_prepend_file)
if (!defined('ABSPATH')) {
    require_once __DIR__ . '/src/Bootstrap/Loader.php';
    DPXL Shield\Bootstrap\Loader::handleEarlyRequest();
}
```

**Bypass obrigatório pré-WordPress (v1.0.19):**

`handleEarlyRequest()` roda _antes_ do WordPress. `is_admin()` e `current_user_can()` não existem neste contexto. Sem bypass, page builders como Elementor fazem POST com HTML/CSS que dispara regras XSS, o WAF tenta chamar `IpBlocklist::blockIp()`, que precisa de `$wpdb` — que ainda é `null` — resultando em erro fatal 500.

Regras de bypass (sem nenhuma função WordPress):

```php
$uri = $_SERVER['REQUEST_URI'] ?? '';

// 1. wp-admin e wp-login.php: WordPress gerencia auth internamente.
if (str_contains($uri, '/wp-admin/') || str_contains($uri, '/wp-login.php')) {
    return;
}

// 2. REST API / admin-ajax com cookie de sessão WordPress.
//    Não é possível validar o cookie pré-WP, mas a presença de
//    wordpress_logged_in_* indica que o usuário está logado.
$isAuthEndpoint = str_contains($uri, '/wp-json/') || str_contains($uri, 'admin-ajax.php');
if ($isAuthEndpoint) {
    foreach (array_keys($_COOKIE) as $cookieName) {
        if (str_starts_with((string) $cookieName, 'wordpress_logged_in_')) {
            return;
        }
    }
}
```

O WAF Extended Protection processa apenas requisições públicas não autenticadas.

### 3.2 FirewallEngine
**Arquivo:** `src/Firewall/FirewallEngine.php`

Responsabilidades:
- Receber `$_REQUEST`, `$_SERVER`, `$_COOKIE`, `php://input`
- Executar pipeline de regras em ordem de prioridade
- Retornar decisão: PASS | BLOCK | CHALLENGE | LOG_ONLY
- Registrar motivo do bloqueio

Pipeline de avaliação:
```
Whitelist check → IP Blocklist → Rate Limit → Rule Engine → Behavioral → PASS
```

### 3.3 RuleEngine
**Arquivo:** `src/Firewall/Rules/RuleEngine.php`

Sistema de regras plugável. Cada regra implementa `RuleInterface`:

```php
interface RuleInterface {
    public function getId(): string;
    public function getPriority(): int;
    public function evaluate(Request $request): RuleResult;
}
```

**Regras implementadas (MVP):**

| ID | Tipo | Alvo |
|---|---|---|
| `sqli-001` | Específica | SQL Injection em GET/POST |
| `sqli-002` | Específica | SQL Injection em cookies |
| `xss-001` | Específica | XSS refletido em parâmetros |
| `xss-002` | Específica | XSS em User-Agent / Referer |
| `lfi-001` | Específica | Path traversal (`../`) |
| `rfi-001` | Específica | Remote File Inclusion |
| `wp-001` | WordPress | Acesso direto a `xmlrpc.php` |
| `wp-002` | WordPress | Enumeração de usuários via `?author=N` |
| `wp-003` | WordPress | Upload de arquivo PHP disfarçado |
| `wp-004` | WordPress | Acesso a arquivos sensíveis (`.env`, `wp-config.php`) |
| `generic-001` | Heurística | Payload com `eval(base64_decode(` |
| `generic-002` | Heurística | Payload com `system(`, `exec(`, `passthru(` |
| `generic-003` | Heurística | Headers HTTP anômalos (tamanho, encoding) |

**Formato das regras em JSON** (`rules/waf-rules.json`):
```json
{
  "version": "2026.07.01",
  "rules": [
    {
      "id": "sqli-001",
      "name": "SQL Injection - GET/POST parameters",
      "priority": 10,
      "targets": ["GET", "POST"],
      "pattern": "(?i)(union\\s+select|select\\s+.*\\s+from|insert\\s+into|drop\\s+table|or\\s+1=1)",
      "pattern_type": "regex",
      "action": "block",
      "log": true
    }
  ]
}
```

### 3.3b REST Output Buffer Protection
**Arquivos:** `dpxl-shield.php`, `src/Admin/RestApi.php`

Ambientes com `WP_DEBUG_DISPLAY = true` e `html_errors = On` (ex: Hostinger em modo de homologação) geram output PHP (`<br /><b>Notice</b>:...`) durante `plugins_loaded` que contamina a resposta JSON do REST API, causando erros de parse no frontend ("Unexpected token '<'").

Defesa em duas camadas:

**Camada 1 — `dpxl-shield.php` (early buffer):**
```php
// Detecta requisições REST e abre buffer antes de qualquer coisa carregar
if (!defined('DPXL_SHIELD_EXTENDED_ACTIVE')) {
    $dpxlRequestUri = $_SERVER['REQUEST_URI'] ?? '';
    if (str_contains($dpxlRequestUri, '/wp-json/') || str_contains($dpxlRequestUri, '?rest_route=')) {
        ob_start();
    }
    unset($dpxlRequestUri);
}
```

**Camada 2 — `RestApi::cleanRestOutputBuffer()` (hook `rest_api_init`, prioridade -999):**
```php
public function cleanRestOutputBuffer(): void {
    if (ob_get_level() > 0 && ob_get_length() > 0) {
        $stray = ob_get_contents();
        ob_clean();
        if ($stray && defined('WP_DEBUG') && WP_DEBUG) {
            error_log('[DPXL Shield] REST pre-response output suppressed: '
                . substr(wp_strip_all_tags((string) $stray), 0, 500));
        }
    }
}
```

- Prioridade -999 garante limpeza antes do registro de qualquer rota REST
- Em modo `WP_DEBUG`, o output suprimido é logado em `error_log` para diagnóstico da causa raiz

### 3.4 IpBlocklist
**Arquivo:** `src/Firewall/IpBlocklist.php`

Fontes:
- Lista interna (IPs manualmente bloqueados pelo admin)
- Lista automática (IPs bloqueados por rate limit ou firewall)
- Lista de reputação (feed externo de IPs maliciosos conhecidos)
- Suporte a CIDR notation (`192.168.1.0/24`)
- Cache em memória (APCu se disponível, fallback para transient WordPress)

**Contexto pré-WordPress — `$wpdb` null-guard (v1.0.19):**

`blockIp()` usa `$wpdb` para persistir o bloqueio no banco. Em Extended Protection (`auto_prepend_file`), `$wpdb` é `null` antes do WordPress carregar. Guard obrigatório no início do método:

```php
public static function blockIp(...): bool {
    global $wpdb;
    if (!$wpdb instanceof \wpdb) {
        return false; // pré-WordPress — não trava, apenas não persiste
    }
    // ...
}
```

`isBlocked()` já tem fallback correto: quando `get_transient` não existe (pré-WP), lê o flat-file `data/blocked-ips.php` em vez de consultar o banco.

### 3.4b CountryBlocker
**Arquivo:** `src/Firewall/CountryBlocker.php`

Responsabilidades:
- Resolver país do IP via banco MaxMind GeoLite2 (arquivo local `.mmdb`, sem latência de API)
- Suportar modo **blocklist** (bloquear países listados) e modo **allowlist** (permitir apenas países listados)
- Exceções: IPs na whitelist manual ignoram o bloqueio por país
- Aplicado no pipeline do FirewallEngine após o IpBlocklist check (prioridade 15)

Implementação:
```php
// Usa a lib oficial maxmind/db-reader-php
$reader = new \MaxMind\Db\Reader(DPXL_SHIELD_PATH . '/data/GeoLite2-Country.mmdb');
$record = $reader->get($ip);
$countryCode = $record['country']['iso_code'] ?? null;
```

Banco de dados: `GeoLite2-Country.mmdb` (~6MB) atualizado mensalmente via cron.  
Licença: MaxMind GeoLite2 — gratuita mediante cadastro (sem custo de API).

---

### 3.4c CustomPatternBlocker
**Arquivo:** `src/Firewall/CustomPatternBlocker.php`

Permite ao admin criar regras de bloqueio baseadas em padrões customizados, além de IP e país:

| Campo avaliado | Exemplo de uso |
|---|---|
| User-Agent | Bloquear bots específicos (`sqlmap`, `nikto`, scrapers) |
| Referer | Bloquear tráfego vindo de domínios suspeitos |
| Hostname | Bloquear por hostname reverso do IP |
| URL Pattern | Bloquear padrões específicos de URI |

Cada regra customizada tem: padrão (string ou regex), tipo de match (contém/igual/regex), ação (block/log), expiração opcional.

Armazenamento: tabela `dpxl_shield_custom_patterns`.

---

### 3.5 RateLimiter
**Arquivo:** `src/Firewall/RateLimiter.php`

Limites configuráveis por tipo de endpoint:

| Endpoint | Padrão | Janela |
|---|---|---|
| `/wp-login.php` | 5 req | 1 min por IP |
| `xmlrpc.php` | 3 req | 1 min por IP |
| REST API `/wp-json/` | 60 req | 1 min por IP |
| Qualquer 404 | 20 req | 1 min por IP |
| Global (todo tráfego) | configurável | configurável |

Storage: tabela `dpxl_shield_rate_buckets` com limpeza automática via cron.

### 3.6 MalwareScanner
**Arquivo:** `src/Scanner/MalwareScanner.php`

Funcionamento em 3 camadas:

**Camada 1 — Integridade vs. WP.org:**
- Compara checksums SHA-256 de core, temas e plugins com API `api.wordpress.org/core/checksums`
- Qualquer diferença = arquivo modificado (alerta imediato)

**Camada 2 — Assinaturas de malware:**
- Banco de assinaturas local (`data/signatures.dat`) em formato binário comprimido
- Scan por regex de padrões conhecidos: backdoors PHP, skimmers, spam injectors
- Atualização via cron (pull da API do DPXL Shield)

**Camada 2b — Reputation / Blocklist Check:**
- Verifica se o domínio/IP do site está em blacklists externas:
  - **Google Safe Browsing API** (phishing, malware, unwanted software)
  - **Spamhaus DBL** (domain blocklist)
  - **MX Toolbox DNSBL** (spam blacklists via DNS lookup)
- Executado uma vez por dia via cron (não em cada requisição)
- Resultado armazenado em cache na `wp_options` com TTL de 24h
- Alerta `CRITICAL` se o site for encontrado em qualquer lista

**Camada 3 — Heurística:**
- Detecta: `eval(base64_decode`, `str_rot13`, `gzinflate`, funções de execução de shell em contexto suspeito
- Arquivos PHP em `/uploads/` → alerta crítico + opção de bloqueio automático
- Arquivos PHP com data de criação mais recente que o último deploy

**Estágios do scan (em ordem de execução):**

| # | Stage | O que verifica |
|---|---|---|
| 1 | Spamvertising Check | Se URLs do site aparecem em listas de spam de e-mail |
| 2 | Spam/Blocklist Check | Se domínio/IP está em Google Safe Browsing, Spamhaus, SURBL |
| 3 | Server State | Versão PHP, WordPress, configurações perigosas (debug mode, file edit) |
| 4 | File Changes | Arquivos modificados desde o último scan |
| 5 | Malware Scan | Assinaturas de malware em todos os arquivos PHP |
| 6 | Content Safety | Links e iframes suspeitos em posts/páginas |
| 7 | Public Files | Arquivos sensíveis acessíveis publicamente (.env, wp-config backup, etc.) |
| 8 | Password Strength | Usuários com senhas fracas ou comprometidas (via HaveIBeenPwned) |
| 9 | Vulnerability Scan | Versões de plugins/temas com CVEs conhecidos |
| 10 | User & Option Audit | Usuários admin inesperados, opções WordPress alteradas |

**Repair de arquivos:**
- Botão **"Repair File"** por resultado individual: restaura arquivo do repositório WP.org
- Botão **"Repair All Repairable"**: restaura em massa todos os arquivos de core/plugin com versão disponível
- Arquivos de tema e arquivos customizados: não reparáveis automaticamente (apenas alerta)
- Antes de reparar: cria backup do arquivo atual em `wp-content/shieldwp-backups/`

**Agendamento:**
- Scan completo: diário (horário configurável, fora do horário de pico)
- Scan incremental (só arquivos alterados): a cada hora via cron
- Scan on-demand: disponível no painel

### 3.7 FileIntegrityMonitor
**Arquivo:** `src/Scanner/FileIntegrityMonitor.php`

Diferente do scanner periódico, este módulo faz monitoramento **contínuo**:

- Registra checksums de todos os arquivos de core + plugin durante a ativação
- A cada requisição WordPress (hook `init` prioridade 1), verifica arquivos críticos:
  - `wp-config.php`
  - `wp-includes/functions.php`
  - `wp-includes/pluggable.php`
  - Arquivos do próprio DPXL Shield
- Mudança detectada → alerta imediato + entrada no audit log

### 3.8 LoginSecurity
**Arquivo:** `src/LoginSecurity/LoginSecurity.php`

Sub-módulos:

**BruteForceProtection:**
- Hook: `wp_login_failed` → incrementa contador por IP + username
- Lockout progressivo: 5 falhas → 5min, 10 falhas → 1h, 20 falhas → 24h
- CAPTCHA challenge após 3 falhas (hCaptcha, sem Google)
- Proteção do `wp-login.php` no nível do Loader (antes do WordPress)
- **Fix v1.0.14:** `brute_force_block_admin_username` tem default `false` — bloquear username "admin" só quando a opção está explicitamente ativada pelo admin. O default anterior era `true` hardcoded na chamada `Options::get()`, bloqueando silenciosamente qualquer site com usuário "admin".

**TwoFactorAuth (2FA):**
- TOTP (RFC 6238) — compatível com Google Authenticator, Authy, 1Password
- Backup codes (8 códigos de uso único gerados na ativação)
- Enforçamento por role: admin obrigatório, outros roles configurável — mas enforçamento é **advisory** (não bloqueia login)
- Hook: `wp_authenticate_user` para interceptar antes de logar
- **Fix v1.0.14:** `interceptLogin()` verifica `isEnabled($user->ID)` (2FA configurada para este usuário), não `isRequired()` (role configurada para exigir 2FA). `isRequired()` retornava `true` para qualquer administrator mesmo sem 2FA configurada, bloqueando todos os admins com `WP_Error('dpxl_2fa_required')` — mascarado como "credenciais incorretas" pelo `login_hide_errors`. Usuários cujo role exige 2FA mas que ainda não a configuraram são permitidos entrar e direcionados ao perfil para ativar.

**LoginAudit:**
- Registra: IP, user-agent, timestamp, resultado (sucesso/falha), geolocalização (via IP-API free)
- Alerta por e-mail em login de IP novo para usuário admin

**PasswordAudit:**
- Verifica senhas contra HaveIBeenPwned API (k-anonymity — só envia hash parcial)
- Força reset se senha comprometida

### 3.9 HoneypotModule
**Arquivo:** `src/Honeypot/HoneypotManager.php`

Estratégias:

**Honeypot em formulários:**
- Injeta campo oculto via CSS em `wp_login_form`, `comment_form`, `register_form`
- Qualquer bot que preencher o campo → IP bloqueado automaticamente

**Decoy endpoints:**
- Registra URLs de isca via `add_rewrite_rule`: `/wp-admin/install.php` falso, `/.env` falso, `/phpinfo.php` falso
- Qualquer acesso → IP bloqueado + alerta de alta severidade
- Nunca retorna conteúdo real, sempre 403 + log

**User enumeration trap:**
- Requisições para `/?author=1`, `/?author=2`, etc. → bloqueia IP após 2 tentativas

### 3.10 SelfProtection
**Arquivo:** `src/SelfProtection/TamperDetector.php`

O módulo mais crítico — resolve o gap fatal do Wordfence.

**Mecanismo de integridade:**
- Durante a ativação do plugin, gera checksums SHA-256 de todos os arquivos do DPXL Shield
- Armazena em 3 locais distintos:
  1. `wp_options` com chave ofuscada + valor criptografado (AES-256)
  2. Arquivo `.shieldwp-integrity` fora do diretório do plugin (em `wp-content/`)
  3. Arquivo de lock em diretório temporário do servidor

**Verificação:**
- A cada boot do plugin (hook `plugins_loaded` prioridade -10): compara checksums
- Se qualquer arquivo do plugin foi modificado → alerta crítico + opção de auto-restauração

**Baseline version-aware (v1.0.14):**
- Na verificação, compara `DPXL_SHIELD_VERSION` com `dpxl_shield_integrity_version` (wp_options)
- Se a versão avançou, re-grava o baseline automaticamente e retorna sem comparar — evita falsos positivos após atualizações legítimas do plugin
- Incrementar `DPXL_SHIELD_VERSION` em qualquer update garante que o baseline seja recalculado na primeira requisição pós-deploy

**Anti-desativação:**
- Hook `deactivated_plugin`: registra quem desativou, quando e de qual IP
- Opção de proteção: requerer senha adicional para desativar o plugin (diferente da senha admin)
- Se plugin for desativado de forma não-padrão (diretório renomeado) → alerta via e-mail/webhook

**UI Anti-spoofing:**
- Todo elemento do painel que indica estado de proteção carrega seu valor via endpoint REST autenticado, não via PHP render estático
- Impossível fazer CSS spoofing porque o valor vem de uma chamada AJAX signed com nonce

### 3.11 TrafficMonitor
**Arquivo:** `src/Traffic/TrafficLogger.php`

- Registra cada requisição: IP, método, URI, status HTTP, user-agent, referrer, tempo de resposta, resultado do WAF, país (via GeoLite2)
- Detecção de bots: fingerprint de user-agent + comportamento (sem JS, sem cookies, velocidade de requisição)
- Retenção: 24h (free), 90 dias (premium)
- View em tempo real no painel (polling a cada 5s via REST)

**Sistema de tipos de tráfego (color dots):**

| Cor | Tipo | Critério |
|---|---|---|
| 🟢 Verde | Humano legítimo | Navegador real, JS ativo, comportamento normal |
| 🟡 Amarelo | Bot/Crawler | User-agent de bot conhecido (Googlebot, etc.) |
| 🔴 Vermelho | Bloqueado | Bloqueado pelo WAF, brute force, IP bloqueado |
| 🟠 Laranja | Suspeito | Não bloqueado mas flagged (taxa alta, padrão anômalo) |
| ⚪ Cinza | Desconhecido | Não classificado |

**Filtros avançados disponíveis:**
- Por tipo (todos / humanos / bots / bloqueados / suspeitos)
- Por país
- Por IP específico
- Por URL/endpoint
- Por código de resposta HTTP
- Por intervalo de tempo
- Por user-agent

**AnomalyDetector:**
- Análise de padrões: mesmo IP acessando 50 URLs diferentes em 60s → scanner detectado
- Spike de 404s → tentativa de descoberta de estrutura
- Padrão de acesso a endpoints REST específicos → possível reconnaissance

### 3.12 AlertManager
**Arquivo:** `src/Alerts/AlertManager.php`

Níveis de severidade: `CRITICAL | HIGH | MEDIUM | LOW | INFO`

Canais de notificação:
- E-mail (padrão, free)
- Webhook HTTP (para Slack, Discord, PagerDuty — premium)
- Dashboard notification (sempre)

Rate limiting de alertas: máximo 1 e-mail do mesmo tipo por hora (evita flood de alertas em ataque volumétrico).

**Activity Report (semanal/mensal):**
- Diferente dos alertas de evento individual, o Activity Report é um **e-mail periódico de resumo**
- Conteúdo: total de ataques bloqueados, top IPs bloqueados, top países, logins bem-sucedidos/falhos, resultados de scan, mudanças de arquivos detectadas
- Frequência configurável: diário / semanal / mensal
- Pode ser disparado on-demand ("Send Report Now")
- Template HTML responsivo

Eventos que geram alerta `CRITICAL`:
- Arquivo do core WordPress modificado
- Arquivo do DPXL Shield modificado
- Novo usuário admin criado
- Plugin desativado
- Acesso a decoy endpoint
- Login bem-sucedido de IP nunca visto para usuário admin
- PHP encontrado em `/uploads/`
- Site encontrado em blacklist (Google Safe Browsing, Spamhaus)

### 3.13b WhoisLookup
**Arquivo:** `src/Tools/WhoisLookup.php`

- Consulta WHOIS de qualquer IP **ou hostname** diretamente no painel (sem sair do WordPress)
- Hostname é resolvido para IP via `gethostbyname()` antes da consulta
- Disponível em: botão "Whois" em qualquer linha do Live Traffic e da tabela de IPs bloqueados
- Estratégia:
  1. Query TCP direta ao servidor WHOIS correto via `fsockopen()` porta 43 (ARIN/RIPE/APNIC/LACNIC/AFRINIC)
  2. Fallback: `https://ipinfo.io/{ip}/json` (free tier, HTTPS, sem chave)
- Retorna: organização, ASN, país, range de IPs, abuse contact, resposta WHOIS bruta
- Resultados em cache via transients WordPress por 1 hora (evita hammering dos servidores WHOIS)
- Ação rápida a partir do resultado: "Block This IP", "Block Range /24", "Add to Whitelist"
- Nota: `fsockopen` porta 43 é bloqueada em muitos hosts compartilhados; o fallback ipinfo.io é o caminho mais comum

### 3.13c ImportExport
**Arquivo:** `src/Tools/ImportExport.php`

- Exporta todas as configurações do plugin em JSON assinado (inclui hash para detectar adulteração)
- Importa configurações com validação de schema e confirmação de sobrescrita
- Itens exportados: todas as opções, regras customizadas, IPs whitelisted, IPs bloqueados manuais, configurações de 2FA (exceto segredos), configurações de alertas
- Itens NÃO exportados: logs de tráfego, resultados de scan (muito grandes), segredos TOTP

### 3.13d Diagnostics
**Arquivo:** `src/Tools/Diagnostics.php`

Painel de diagnóstico do ambiente. Verifica e exibe:

| Item | Verificação |
|---|---|
| Versão PHP | Mínimo 8.1, máximo suportado |
| Versão WordPress | Atual vs. última disponível |
| Extended Protection | Ativo / inativo / com erro |
| Permissões de arquivo | wp-config.php, uploads/, plugins/ |
| APCu / OPcache | Disponível e ativo |
| Extensões PHP | openssl, hash, mbstring, json, curl |
| MaxMind GeoLite2 | Arquivo presente e versão |
| Cron WordPress | Funcionando (última execução) |
| Espaço em disco | Disponível para logs e backups |
| Conexão com API DPXL Shield | Status |
| MySQL version | Compatibilidade |

Botão **"Copy Diagnostics"**: copia saída formatada para suporte.

### 3.13 PhpExecutionBlocker
**Arquivo:** `src/Hardening/PhpExecutionBlocker.php`

Ao ativar o plugin, injeta automaticamente regras no servidor para bloquear execução PHP em diretórios que não deveriam ter PHP executável:

**Para Apache** (via `.htaccess` em `/uploads/`):
```apache
<FilesMatch "\.php$">
    Order Deny,Allow
    Deny from all
</FilesMatch>
```

**Para Nginx** (gera configuração e instrui o admin):
```nginx
location ~* /wp-content/uploads/.*\.php$ {
    deny all;
    return 403;
}
```

**Para LiteSpeed:** usa mesma sintaxe do Apache.

Detecta o servidor automaticamente via `$_SERVER['SERVER_SOFTWARE']`.

---

### 3.14 AuditLog
**Arquivo:** `src/Audit/AuditLog.php`

**Categorias de eventos com código de cor:**

| Cor | Categoria | Exemplos de evento |
|---|---|---|
| 🟡 Amarelo | Authentication | Login, logout, falha de login, 2FA ativado/desativado |
| 🟣 Roxo | User/Permissions | Usuário criado, role alterada, usuário deletado |
| 🔵 Azul | Plugin/Themes/Updates | Plugin ativado/desativado/instalado/deletado, update aplicado |
| 🔴 Vermelho | Firewall | IP bloqueado, regra acionada, ataque bloqueado |
| 🟢 Verde | Site Settings | Opção WordPress alterada, permalink modificado, configuração DPXL Shield alterada |
| 🩶 Cinza | Content | Post/página criada, editada, deletada |

**Modos de logging:**
- `DISABLED` — nenhum evento registrado
- `PREVIEW` — eventos registrados localmente apenas (sem envio externo)
- `SIGNIFICANT_EVENTS` — autenticação, firewall, user/permissions, plugin/updates, site settings (padrão recomendado)
- `ALL_EVENTS` — inclui também content events (pode gerar muito volume)

**Hash chain (integridade):**
- Cada entrada contém `chain_hash = SHA256(id || timestamp || category || event || hash_anterior)`
- Função "Verify Log Integrity" no painel: percorre toda a cadeia e valida
- Se cadeia quebrada: alerta crítico + indicação do registro adulterado

## 4. Estrutura de Pastas

```
dpxl-shield/
├── dpxl-shield.php                    # Main plugin file (headers WP)
├── dpxl-shield-waf.php                # Referenciado pelo auto_prepend_file
├── uninstall.php
├── composer.json
├── vendor/                         # Autoload PSR-4
│
├── src/
│   ├── Bootstrap/
│   │   ├── Loader.php              # Early WAF boot (antes do WP)
│   │   ├── PluginInit.php          # Boot normal como plugin WP
│   │   └── AutoPrepend.php         # Configuração do auto_prepend_file
│   │
│   ├── Firewall/
│   │   ├── FirewallEngine.php
│   │   ├── Request.php             # Value object da requisição
│   │   ├── RuleResult.php
│   │   ├── IpBlocklist.php
│   │   ├── CountryBlocker.php      # Bloqueio por país (MaxMind GeoLite2)
│   │   ├── CustomPatternBlocker.php # Bloqueio por user-agent, referer, hostname
│   │   ├── AllowlistManager.php    # URLs e IPs na whitelist
│   │   ├── RateLimiter.php
│   │   └── Rules/
│   │       ├── RuleInterface.php
│   │       ├── RuleEngine.php
│   │       ├── AbstractRule.php
│   │       ├── SqlInjectionRule.php
│   │       ├── XssRule.php
│   │       ├── LfiRule.php
│   │       ├── RfiRule.php
│   │       ├── WordPressRule.php   # wp-login, xmlrpc, author enum
│   │       └── GenericHeuristicRule.php
│   │
│   ├── Scanner/
│   │   ├── MalwareScanner.php
│   │   ├── ScanOrchestrator.php    # Coordena os estágios do scan
│   │   ├── FileIntegrityMonitor.php
│   │   ├── ChecksumVerifier.php
│   │   ├── SignatureDatabase.php
│   │   ├── WpOrgChecksumApi.php
│   │   ├── ReputationChecker.php   # Google Safe Browsing + Spamhaus
│   │   ├── ContentSafetyChecker.php # Links/iframes em posts
│   │   ├── PasswordStrengthAudit.php
│   │   └── FileRepair.php          # Restauração de arquivos do WP.org
│   │   # VulnerabilityScanner.php — planejado (Fase 5), ainda não implementado
│   │
│   ├── LoginSecurity/
│   │   ├── LoginSecurity.php
│   │   ├── BruteForceProtection.php
│   │   ├── TwoFactorAuth.php
│   │   ├── BackupCodes.php
│   │   ├── LoginAudit.php
│   │   └── PasswordAudit.php
│   │
│   ├── Honeypot/
│   │   ├── HoneypotManager.php
│   │   ├── FormHoneypot.php
│   │   └── DecoyEndpoints.php
│   │
│   ├── SelfProtection/
│   │   ├── TamperDetector.php
│   │   ├── IntegrityStore.php
│   │   └── DeactivationGuard.php
│   │
│   ├── Traffic/
│   │   ├── TrafficLogger.php
│   │   ├── TrafficClassifier.php   # Classifica tipo (humano/bot/bloqueado/suspeito)
│   │   ├── BotDetector.php
│   │   └── AnomalyDetector.php
│   │
│   ├── Audit/
│   │   ├── AuditLog.php            # Hash chain log imutável
│   │   └── AuditEvents.php         # Constantes de tipos de evento
│   │
│   ├── Hardening/
│   │   ├── PhpExecutionBlocker.php
│   │   ├── ServerDetector.php
│   │   └── WpHardening.php
│   │
│   ├── Alerts/
│   │   ├── AlertManager.php
│   │   ├── EmailChannel.php
│   │   ├── ActivityReport.php      # Relatório periódico de atividade
│   │   └── WebhookChannel.php
│   │
│   ├── Tools/
│   │   ├── WhoisLookup.php         # Consulta WHOIS de IPs
│   │   ├── ImportExport.php        # Import/export de configurações
│   │   └── Diagnostics.php         # Diagnóstico do ambiente
│   │
│   ├── Admin/
│   │   ├── AdminMenu.php
│   │   ├── RestApi.php
│   │   └── Views/
│   │       ├── dashboard.php
│   │       ├── firewall.php        # Firewall + Blocking tabs
│   │       ├── scanner.php
│   │       ├── login-security.php
│   │       ├── tools/
│   │       │   ├── live-traffic.php
│   │       │   ├── audit-log.php
│   │       │   ├── whois.php
│   │       │   ├── import-export.php
│   │       │   └── diagnostics.php
│   │       └── all-options.php     # Página única com todas as opções + busca
│   │
│   └── Core/
│       ├── Plugin.php
│       ├── Database.php
│       ├── Options.php
│       ├── Logger.php
│       └── Cron.php
│
├── data/
│   ├── blocked-ips.php             # Flat-file blocklist para modo Extended (lido antes do WP)
│   └── early-config.php            # Configuração lida pelo WAF antes do WordPress iniciar
│   # GeoLite2-Country.mmdb é baixado em runtime (não incluído no zip do plugin)
│   # signatures.dat é gerado/atualizado via cron (não incluído no zip do plugin)
│
├── rules/
│   └── waf-rules.json
│
└── assets/
    ├── js/
    │   ├── admin.js
    │   └── qrcode-local.js         # Geração de QR Code local para setup 2FA (sem CDN externo)
    ├── css/
    │   └── admin.css
    └── img/
        └── dpxl-shield-mark.svg    # Logo DPXL Shield (SVG, usado no painel)
```

---

## 5. Banco de Dados

Todas as tabelas usam o prefixo padrão do WordPress (`{$wpdb->prefix}`) + `dpxl_shield_`.

### `dpxl_shield_traffic_log`
```sql
CREATE TABLE {prefix}dpxl_shield_traffic_log (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    timestamp     DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip            VARCHAR(45)     NOT NULL,
    method        VARCHAR(10)     NOT NULL,
    uri           TEXT            NOT NULL,
    query_string  TEXT,
    status_code   SMALLINT        NOT NULL,
    user_agent    TEXT,
    referer       TEXT,
    waf_action    ENUM('pass','block','challenge','log_only') NOT NULL DEFAULT 'pass',
    waf_rule_id   VARCHAR(50),
    response_time FLOAT,
    is_bot        TINYINT(1)      NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    INDEX idx_ip (ip),
    INDEX idx_timestamp (timestamp),
    INDEX idx_waf_action (waf_action)
);
```

### `dpxl_shield_blocked_ips`
```sql
CREATE TABLE {prefix}dpxl_shield_blocked_ips (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    ip           VARCHAR(45)     NOT NULL,
    cidr         VARCHAR(50),
    reason       VARCHAR(255)    NOT NULL,
    source       ENUM('manual','auto_waf','auto_brute','auto_rate','auto_honeypot','auto_country','auto_anomaly') NOT NULL,
    blocked_at   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at   DATETIME,
    is_permanent TINYINT(1)      NOT NULL DEFAULT 0,
    block_count  INT UNSIGNED    NOT NULL DEFAULT 1,
    last_attempt DATETIME,
    PRIMARY KEY (id),
    UNIQUE KEY uk_ip (ip),
    INDEX idx_expires (expires_at),
    INDEX idx_permanent (is_permanent)
);
```

> Campos `block_count` e `last_attempt` permitem a coluna "Last Attempt" na tabela de bloqueios e a ação "Make Permanent".

### `dpxl_shield_country_blocks`
```sql
CREATE TABLE {prefix}dpxl_shield_country_blocks (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    country_code CHAR(2)         NOT NULL,
    country_name VARCHAR(100)    NOT NULL,
    mode         ENUM('block','allow') NOT NULL DEFAULT 'block',
    created_at   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_country (country_code)
);
```

### `dpxl_shield_custom_patterns`
```sql
CREATE TABLE {prefix}dpxl_shield_custom_patterns (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    field      ENUM('user_agent','referer','hostname','url') NOT NULL,
    pattern    VARCHAR(500)    NOT NULL,
    match_type ENUM('contains','equals','regex') NOT NULL DEFAULT 'contains',
    action     ENUM('block','log_only') NOT NULL DEFAULT 'block',
    reason     VARCHAR(255),
    created_at DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    PRIMARY KEY (id),
    INDEX idx_field (field)
);
```

### `dpxl_shield_login_events`
```sql
CREATE TABLE {prefix}dpxl_shield_login_events (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    timestamp  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_login VARCHAR(60)     NOT NULL,
    ip         VARCHAR(45)     NOT NULL,
    user_agent TEXT,
    result     ENUM('success','failure','blocked','2fa_required','2fa_failed') NOT NULL,
    country    VARCHAR(2),
    PRIMARY KEY (id),
    INDEX idx_ip (ip),
    INDEX idx_user (user_login),
    INDEX idx_timestamp (timestamp)
);
```

### `dpxl_shield_scan_results`
```sql
CREATE TABLE {prefix}dpxl_shield_scan_results (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    scan_id      VARCHAR(36)     NOT NULL,  -- UUID do scan
    scanned_at   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    file_path    TEXT            NOT NULL,
    issue_type   ENUM('modified_core','modified_plugin','malware_signature','heuristic','php_in_uploads','unknown') NOT NULL,
    severity     ENUM('critical','high','medium','low') NOT NULL,
    signature_id VARCHAR(50),
    details      TEXT,
    status       ENUM('new','acknowledged','resolved','false_positive') NOT NULL DEFAULT 'new',
    PRIMARY KEY (id),
    INDEX idx_scan_id (scan_id),
    INDEX idx_status (status)
);
```

### `dpxl_shield_file_checksums`
```sql
CREATE TABLE {prefix}dpxl_shield_file_checksums (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    file_path    VARCHAR(500)    NOT NULL,
    checksum     CHAR(64)        NOT NULL,  -- SHA-256
    file_type    ENUM('core','plugin','theme','shieldwp') NOT NULL,
    recorded_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_path (file_path(255)),
    INDEX idx_file_type (file_type)
);
```

### `dpxl_shield_audit_log`
```sql
CREATE TABLE {prefix}dpxl_shield_audit_log (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    timestamp   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type  VARCHAR(50)     NOT NULL,
    severity    ENUM('critical','high','medium','low','info') NOT NULL,
    actor_ip    VARCHAR(45),
    actor_user  BIGINT UNSIGNED,
    description TEXT            NOT NULL,
    context     JSON,
    chain_hash  CHAR(64)        NOT NULL,  -- Hash encadeado do registro anterior
    PRIMARY KEY (id),
    INDEX idx_severity (severity),
    INDEX idx_event_type (event_type),
    INDEX idx_timestamp (timestamp)
);
```

> O campo `chain_hash` implementa um hash chain: `SHA256(id || timestamp || event_type || description || hash_anterior)`. Qualquer adulteração retroativa quebra a cadeia e é detectada.

### `dpxl_shield_rate_buckets`
```sql
CREATE TABLE {prefix}dpxl_shield_rate_buckets (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    bucket_key VARCHAR(100)    NOT NULL,  -- "ip:endpoint"
    count      INT UNSIGNED    NOT NULL DEFAULT 0,
    window_start DATETIME      NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_bucket (bucket_key),
    INDEX idx_window (window_start)
);
```

---

## 6. Hooks WordPress Utilizados

| Hook | Prioridade | Módulo | Finalidade |

|---|---|---|---|
| `auto_prepend_file` | N/A | Loader | Carregar WAF antes do WordPress |
| `muplugins_loaded` | -99 | PluginInit | Boot mais cedo possível como plugin |
| `plugins_loaded` | -20 | TamperDetector | Verificação de integridade do plugin (version-aware: re-grava baseline quando versão avança) |
| `plugins_loaded` | -10 | PluginInit | Boot do plugin |
| `init` | 1 | FileIntegrityMonitor | Verificar arquivos críticos por requisição |
| `init` | 10 | HoneypotManager | Registrar decoy endpoints |
| `wp_login_failed` | 10 | BruteForceProtection | Registrar falha de login |
| `wp_authenticate_user` | 10 | TwoFactorAuth | Interceptar para 2FA |
| `wp_login` | 10 | LoginAudit | Registrar login bem-sucedido |
| `user_register` | 10 | LoginAudit | Alertar criação de novo usuário |
| `set_user_role` | 10 | AlertManager | Alertar promoção a admin |
| `activated_plugin` | 10 | TrafficLogger | Registrar ativação de plugin |
| `deactivated_plugin` | 10 | DeactivationGuard | Registrar/alertar desativação |
| `deleted_plugin` | 10 | AlertManager | Alertar deleção de plugin |
| `upgrader_process_complete` | 10 | FileIntegrityMonitor | Regravar checksums pós-update |
| `save_post` | 99 | TrafficLogger | Detectar edições suspeitas de conteúdo |
| `rest_api_init` | -999 | RestApi | Limpar output buffer antes de qualquer rota REST (previne PHP notices contaminando JSON) |
| `rest_api_init` | 10 | RestApi | Registrar endpoints do painel DPXL Shield |
| `wp_footer` | 99 | FormHoneypot | Injetar campo honeypot em formulários |
| `login_form` | 10 | FormHoneypot | Honeypot no formulário de login |
| `comment_form_before` | 10 | FormHoneypot | Honeypot em comentários |
| `shutdown` | 10 | TrafficLogger | Finalizar log da requisição com status HTTP real |

---

## 7. Sistema de Regras WAF — Formato e Pipeline

### Formato das regras (JSON versionado)

```json
{
  "meta": {
    "version": "2026.07.01",
    "checksum": "sha256-do-arquivo",
    "rules_count": 42
  },
  "rules": [
    {
      "id": "sqli-001",
      "name": "SQL Injection via GET/POST",
      "description": "Detects common SQL injection patterns in request parameters",
      "priority": 10,
      "enabled": true,
      "targets": ["GET", "POST", "COOKIE"],
      "exclude_targets": [],
      "pattern": "(?i)(union\\s+(all\\s+)?select|select\\s+.+\\s+from|insert\\s+into|drop\\s+table|alter\\s+table|or\\s+['\"]?1['\"]?\\s*=\\s*['\"]?1)",
      "pattern_type": "regex",
      "action": "block",
      "log": true,
      "severity": "high",
      "tags": ["sqli", "owasp-a03"]
    },
    {
      "id": "wp-002",
      "name": "WordPress User Enumeration",
      "priority": 20,
      "enabled": true,
      "targets": ["GET"],
      "pattern": "\\?author=\\d+",
      "pattern_type": "regex",
      "action": "block",
      "log": true,
      "severity": "medium",
      "tags": ["wordpress", "reconnaissance"]
    },
    {
      "id": "generic-001",
      "name": "PHP Code Execution via eval+base64",
      "priority": 5,
      "enabled": true,
      "targets": ["GET", "POST", "COOKIE", "BODY"],
      "pattern": "eval\\s*\\(\\s*(base64_decode|gzinflate|str_rot13|gzuncompress)",
      "pattern_type": "regex",
      "action": "block",
      "log": true,
      "severity": "critical",
      "tags": ["webshell", "rce"]
    }
  ]
}
```

### Pipeline de decisão do FirewallEngine

```
1. Whitelist check (IP do admin, IPs confiáveis) → PASS imediato
2. IpBlocklist check → BLOCK imediato (sem avaliar regras)
3. RateLimiter check → BLOCK se limite excedido
4. RuleEngine → avaliar regras por prioridade (menor = mais urgente)
   4a. Se qualquer regra retorna BLOCK → registrar + bloquear
   4b. Se action = "challenge" → retornar CAPTCHA
   4c. Se action = "log_only" → registrar + PASS
5. AnomalyDetector (comportamental) → analisar padrões de tráfego
   5a. Scanner detectado → BLOCK + adicionar IP à blocklist
6. PASS → requisição chega ao WordPress normalmente
```

---

## 8. Inovações Técnicas — Soluções para os Gaps do Wordfence

### Gap 1 — Delay de 30 dias nas regras WAF
**Solução:** Regras WAF totalmente open-source (repositório público no GitHub). Atualização via pull diário do JSON. Nenhuma regra de proteção é paywalled. O premium paga por gestão, relatórios e suporte — não por proteção.

### Gap 2 — Auto-proteção do scanner
**Solução:** Sistema de integridade em 3 camadas (ver SelfProtection module). O verificador de checksums lê os hashes de 3 locais independentes e usa maioria simples. Para adulterar o sistema, o atacante precisaria modificar 3 locais diferentes simultaneamente, dois dos quais estão fora do diretório do plugin.

### Gap 3 — Extended protection inacessível
**Solução:** Wizard de configuração automática que:
1. Detecta servidor (Apache/Nginx/LiteSpeed/OpenLiteSpeed)
2. Tenta configurar `auto_prepend_file` via `.htaccess`, `php.ini`, `php.ini` local na raiz WP, ou `user.ini`
3. Faz requisição de teste para verificar se o modo extended está ativo
4. Se falhar, mantém modo basic e explica claramente o que está faltando
5. Oferece snippet de configuração para o admin do servidor

### Gap 4 — Detecção apenas por assinatura
**Solução:** AnomalyDetector analisa padrões comportamentais além de payloads:
- Volume de requisições por IP em janelas temporais
- Diversidade de URLs acessadas (indicador de crawler)
- Taxa de 404s (indicador de descoberta de estrutura)
- Padrão de acesso a endpoints REST específicos em sequência
- Acesso rápido a múltiplos endpoints de login em IPs diferentes (credential stuffing distribuído)

### Gap 5 — UI spoofing do painel
**Solução:** Todos os indicadores de status no painel carregam via chamadas REST autenticadas e asssinadas com nonce WordPress. O HTML renderizado pelo PHP não contém o estado — apenas o container. O estado real é injetado via JavaScript após autenticação. Um CSS externo não consegue fazer spoofing porque não há elementos de estado no HTML original.

### Gap 6 — PHP executável em /uploads/
**Solução:** PhpExecutionBlocker configura automaticamente regras no servidor durante ativação do plugin. Além disso, o scanner alerta imediatamente se qualquer arquivo `.php`, `.php5`, `.phtml` for encontrado no diretório de uploads.

### Gap 7b — Audit Log dependente de serviço externo
**Solução:** O Wordfence só grava o audit log completo quando conectado ao Wordfence Central. Nosso audit log funciona 100% local, com hash chain garantindo integridade sem depender de nenhum serviço externo. Nenhum dado de log sai do servidor do usuário.

### Gap 7 — Log adulterável
**Solução:** Hash chain no `audit_log`. Cada entrada contém o hash da entrada anterior. Qualquer adulteração retroativa quebra a cadeia. Verificação da integridade do log disponível no painel com um clique.

---

## 8b. Allowlist de URLs

Permite ao admin declarar URLs que o WAF deve ignorar completamente (ex: endpoint de integração com sistema legado que usa parâmetros que parecem SQLi).

```php
// Armazenado em wp_options como JSON
[
  "/meu-endpoint-legado",
  "/wp-json/meu-plugin/v1/.*"  // suporte a regex
]
```

Gerenciado em: `src/Firewall/AllowlistManager.php`  
Configurável em: All Options > Firewall Options > Allowlisted URLs

---

## 9. Requisitos Mínimos

- PHP 8.1+
- WordPress 6.4+
- MySQL 5.7+ / MariaDB 10.4+
- Extensões PHP: `openssl`, `hash`, `mbstring`, `json`
- Recomendado: `APCu` para cache de rate limiting

---

## 9b. Dependências Adicionais (v1.1)

```json
{
  "require": {
    "maxmind-db/reader": "^1.11"
  }
}
```

> `maxmind-db/reader`: leitura do arquivo `.mmdb` para geolocalização por país.  
> O arquivo `GeoLite2-Country.mmdb` é baixado separadamente durante a ativação (MaxMind requer cadastro gratuito para download).

---

## 10. Sequência de Desenvolvimento (Fases)

### Fase 1 — Core e WAF (MVP)
1. Estrutura de pastas + Composer + autoload PSR-4
2. Database.php: criação de todas as tabelas
3. FirewallEngine + RuleEngine + regras básicas (SQLi, XSS, LFI, WP-específicas)
4. IpBlocklist + RateLimiter
5. Loader.php (modo basic como plugin normal)
6. Admin UI básica: dashboard + firewall settings
7. TrafficLogger básico
8. AlertManager (e-mail)

### Fase 2 — Scanner e Login
1. MalwareScanner (integração com WP.org checksums API)
2. SignatureDatabase (banco de assinaturas MVP)
3. FileIntegrityMonitor
4. BruteForceProtection
5. TwoFactorAuth (TOTP)
6. LoginAudit
7. Admin UI: scanner + login security

### Fase 3 — Hardening e Proteção Avançada
1. PhpExecutionBlocker + ServerDetector
2. HoneypotManager (formulários + decoy endpoints)
3. SelfProtection / TamperDetector
4. AnomalyDetector (behavioral WAF)
5. PasswordAudit (HaveIBeenPwned)
6. AutoPrepend wizard (Extended Protection)
7. CountryBlocker (MaxMind GeoLite2)
8. CustomPatternBlocker (user-agent, referer, hostname)
9. AllowlistManager (URLs na whitelist)
10. ReputationChecker (Google Safe Browsing + Spamhaus)

### Fase 4 — Tools e Gestão
1. Audit log com hash chain + modos de logging
2. WhoisLookup integrado
3. ImportExport de configurações
4. Diagnostics
5. ActivityReport (e-mail periódico de resumo)
6. All Options page com busca
7. FileRepair (restauração de arquivos core/plugin)
8. ContentSafetyChecker + PasswordStrengthAudit

### Fase 5 — Polimento e Premium
1. WebhookChannel (Slack, Discord, PagerDuty)
2. Admin Central (multi-site dashboard) — Premium
3. Relatórios PDF — Premium
4. REST API pública para integrações — Premium
5. Testes automatizados (PHPUnit)
6. Submission para WordPress.org

---

## 11. Dependências (Composer)

```json
{
  "name": "digital-pixel/dpxl-shield",
  "require": {
    "php": ">=8.1",
    "maxmind-db/reader": "^1.11",
    "paragonie/constant_time_encoding": "^2.0",
    "spomky-labs/otphp": "^11.0"
  },
  "require-dev": {
    "phpunit/phpunit": "^10.0",
    "brain/monkey": "^2.6"
  },
  "autoload": {
    "psr-4": {
      "DPXL\\Shield\\": "src/"
    }
  },
  "autoload-dev": {
    "psr-4": {
      "DPXL\\Shield\\Tests\\": "tests/"
    }
  }
}
```

> `maxmind-db/reader`: leitura do arquivo `.mmdb` para geolocalização por país  
> `paragonie/constant_time_encoding`: encoding/decoding em tempo constante (previne timing attacks)  
> `spomky-labs/otphp`: geração e verificação de TOTP para 2FA  
> `brain/monkey`: mocking de funções WordPress em testes unitários

---

---

## 12. Status de Implementação (v1.3)

| Módulo | Arquivo | Status |
|---|---|---|
| Bootstrap / Loader | `src/Bootstrap/` | ✅ Implementado (bypass wp-admin/REST v1.0.19) |
| FirewallEngine + RuleEngine | `src/Firewall/` | ✅ Implementado |
| IpBlocklist + RateLimiter | `src/Firewall/` | ✅ Implementado ($wpdb null-guard v1.0.19) |
| CountryBlocker (MaxMind) | `src/Firewall/CountryBlocker.php` | ✅ Implementado (requer mmdb) |
| CustomPatternBlocker | `src/Firewall/CustomPatternBlocker.php` | ✅ Implementado |
| AllowlistManager | `src/Firewall/AllowlistManager.php` | ✅ Implementado |
| REST Output Buffer Protection | `dpxl-shield.php` + `src/Admin/RestApi.php` | ✅ Implementado (v1.0.14) |
| MalwareScanner + ScanOrchestrator | `src/Scanner/` | ✅ Implementado |
| FileIntegrityMonitor + FileRepair | `src/Scanner/` | ✅ Implementado |
| ReputationChecker | `src/Scanner/ReputationChecker.php` | ✅ Implementado |
| VulnerabilityScanner | — | ❌ Não implementado (Fase 5) |
| LoginSecurity + BruteForce + 2FA | `src/LoginSecurity/` | ✅ Implementado (corrigido v1.0.14) |
| HoneypotManager (formulários + decoys) | `src/Honeypot/` | ✅ Implementado |
| SelfProtection / TamperDetector | `src/SelfProtection/` | ✅ Implementado (version-aware v1.0.14) |
| TrafficLogger + BotDetector | `src/Traffic/` | ✅ Implementado |
| AnomalyDetector | `src/Traffic/AnomalyDetector.php` | ✅ Implementado |
| AuditLog (hash chain) | `src/Audit/` | ✅ Implementado |
| PhpExecutionBlocker + WpHardening | `src/Hardening/` | ✅ Implementado |
| AlertManager + EmailChannel | `src/Alerts/` | ✅ Implementado |
| WebhookChannel | `src/Alerts/WebhookChannel.php` | ✅ Implementado |
| ActivityReport | `src/Alerts/ActivityReport.php` | ✅ Implementado |
| WhoisLookup | `src/Tools/WhoisLookup.php` | ✅ Implementado (corrigido v1.2) |
| ImportExport | `src/Tools/ImportExport.php` | ✅ Implementado |
| Diagnostics | `src/Tools/Diagnostics.php` | ✅ Implementado |
| Admin REST API | `src/Admin/RestApi.php` | ✅ Implementado |
| Testes unitários (PHPUnit) | `tests/Unit/` | ✅ Parcial (4 suites) |

### Correções v1.0.19

| Bug | Causa | Fix |
|---|---|---|
| HTTP 500 fatal em `wp-admin/post.php` e no save do Elementor | Extended Protection ativo (`auto_prepend_file`): `Loader::handleEarlyRequest()` executava o WAF em _todas_ as requisições sem bypass para wp-admin. HTML/CSS do Elementor disparava regra XSS → `FirewallEngine` chamava `IpBlocklist::blockIp()` → `$wpdb->get_var()` em `null` pré-WordPress → `Error: Call to member function get_var() on null` | Bypass URI-based em `Loader::handleEarlyRequest()` para `/wp-admin/` e `/wp-login.php`; bypass cookie-based para `/wp-json/` e `admin-ajax.php` com cookie `wordpress_logged_in_*` |
| Mesmo 500 poderia ocorrer em qualquer requisição pública bloqueada | `IpBlocklist::blockIp()` usava `global $wpdb` sem verificar se estava disponível | Guard `if (!$wpdb instanceof \wpdb) { return false; }` no início de `blockIp()` |
| `auto_anomaly` rejeitado pelo MySQL na tabela `dpxl_shield_blocked_ips` | ENUM da coluna `source` não incluía `'auto_anomaly'`; `AnomalyDetector` passava esse valor | `'auto_anomaly'` adicionado ao ENUM. `Database::maybeCreateTables()` adicionado ao boot para auto-healing sem depender do activation hook |

### Correções v1.0.14

| Bug | Causa | Fix |
|---|---|---|
| REST API retornava JSON inválido (`Unexpected token '<'`) | PHP notices/warnings durante `plugins_loaded` contaminavam o body JSON quando `WP_DEBUG_DISPLAY = On` + `html_errors = On` | Two-layer output buffering: `ob_start()` em `dpxl-shield.php` + `cleanRestOutputBuffer()` em `rest_api_init` prioridade -999 |
| TamperDetector gerava falsos positivos após edições legítimas | Baseline SHA-256 não era atualizado após modificações de código; todo request gerava alerta CRITICAL | Verificação version-aware: quando `DPXL_SHIELD_VERSION` muda, re-grava baseline e retorna sem comparar. Nova option: `dpxl_shield_integrity_version` |
| Login bloqueado para todos os admins | `TwoFactorAuth::interceptLogin()` chamava `isRequired()` que retorna `true` para qualquer administrator (mesmo sem 2FA configurada), gerando `WP_Error('dpxl_2fa_required')` → mascarado como "credenciais incorretas" por `login_hide_errors` | `interceptLogin()` agora chama `isEnabled($user->ID)` — só bloqueia se 2FA foi efetivamente configurada |
| Login bloqueado para username "admin" | `brute_force_block_admin_username` ausente de `Options::$defaults`; `Options::get()` retornava fallback hardcoded `true` | Default alterado para `false` — bloquear username "admin" requer opt-in explícito do admin |

*Documento atualizado em 2026-07-05 — versão 1.4.*
