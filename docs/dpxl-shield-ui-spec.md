# DPXL Shield — Especificação de UI/UX do Painel Admin
**Versão:** 1.3 — Redesign visual e sistema de ícones SVG (v1.0.20–1.0.23)  
**Data:** 2026-07-24  
**Referência visual:** Análise das telas do Wordfence 7.0  
**Nota de implementação:** Labels no painel são em Português (pt-BR). Esta spec usa Inglês para clareza, mas os textos reais estão em PT-BR (ex: "Tráfego ao vivo", "Log de auditoria", "Consulta Whois").

---

## 0. Atualizações v1.0.20–1.0.23 (redesign)

Esta seção registra as mudanças de UI implementadas; o restante da spec continua válido como referência de estrutura e comportamento.

**Sistema de ícones SVG — sem emojis (v1.0.22).** Todo o painel deixou de usar emojis (rendem inconsistente entre SO/navegador). Ícones agora são SVG inline estilo Feather com `stroke=currentColor`, de fonte única: `src/Admin/Icons.php` (`Icons::svg()/render()`) + espelho `ICONS`/`icon()` em `assets/js/admin.js`. As "color dots" semânticas de tráfego/audit (§8) permanecem como bolinhas coloridas — a mudança é só o fim dos glifos emoji em botões, status e cabeçalhos.

**Tela de Varredura redesenhada (v1.0.22).** Progress stepper horizontal com linha conectora e estados cadeado (pendente) → spinner (ativo) → check (concluído); barra de progresso determinada no scan de malware; cards de resultado com ícone de severidade + chip colorido + título humano (ex: "Arquivo do core modificado" no lugar do slug `modified_core`). Nova **seção "Recomendações"** colapsável, separando avisos de hardening e achados de baixa confiança das ameaças reais (ver `ScanClassifier` na arquitetura).

**Sistema visual unificado em todas as telas (v1.0.23).** Refinamento da camada de CSS compartilhada (`assets/css/admin.css`): cards com sombra sutil e raio 10px; gauges com anel fino + hover; tabelas com cabeçalho small-caps; tab-nav em estilo underline; banner de proteção claro com borda + ícone. Ícones SVG de seção nos cabeçalhos (bell/shield/activity/globe/clock/lock/list/search/settings/upload-cloud).

**E-mails redesenhados (v1.0.20).** Fora do painel, mas parte da identidade visual: `EmailTemplate` (shell compartilhado) + `EventCatalog` (títulos legíveis). Ver arquitetura §3.12.

**Paleta de tokens (CSS `:root`):** `--dpxl-heading` #1d2327, `--dpxl-text` #3c434a, `--dpxl-muted` #787c82, `--dpxl-border` #dcdcde, `--dpxl-radius` 6px / `--dpxl-radius-lg` 10px, `--dpxl-shadow`. As cores semânticas (§1) permanecem: primary #2271b1, ok #00a32a, warn #dba617, error #d63638, orange #f0b849.

---

## 1. Princípios de Design

- **Densidade informacional:** painel denso, não minimalista — admins de segurança querem dados, não white space
- **Estado sempre visível:** o status de proteção (ativo/inativo/degradado) deve estar visível em qualquer tela
- **Ação imediata:** toda informação crítica deve ter uma ação a 1 clique de distância
- **Cores com significado consistente:** usar o mesmo sistema de cores em todas as telas
- **Sem dependência de servidor externo para renderizar estado:** todos os indicadores de status vêm via REST autenticado, nunca de HTML estático

### Paleta de cores
| Cor | Uso |
|---|---|
| `#2271b1` (azul WP) | Ações primárias, links, elementos ativos |
| `#00a32a` (verde) | Status OK, proteção ativa, humano legítimo |
| `#dba617` (amarelo) | Avisos, bot/crawler, atenção necessária |
| `#d63638` (vermelho) | Erros, bloqueios, ataques, crítico |
| `#f0b849` (laranja) | Suspeito, atenção moderada |
| `#3c434a` (cinza escuro) | Texto principal |
| `#f6f7f7` (cinza claro) | Backgrounds de tabelas alternadas |

---

## 2. Navegação (Menu Lateral)

```
🔒 DPXL Shield
├── Dashboard
├── Firewall
│   └── [sub-tabs: Firewall | Blocking]
├── Scan
├── Login Security
│   └── [sub-tabs: Two-Factor Auth | Settings]
├── Tools
│   └── [sub-tabs: Live Traffic | Audit Log | Whois Lookup | Import/Export | Diagnostics]
├── All Options
└── Help
```

**Badges de notificação:** o item "Dashboard" exibe um badge com contagem de notificações não lidas (amarelo). O item "Scan" exibe badge vermelho se houver issues não resolvidos.

---

## 3. Tela: Dashboard

### Layout geral
```
┌─────────────────────────────────────────────────────────────┐
│  🔒 DPXL Shield Dashboard          [Learn more ↗]             │
├─────────────────────────────────────────────────────────────┤
│  ████████████████  DPXL Shield Protection Active  ████████████ │  ← Banner verde (ativo) ou vermelho (problema)
├───────────────────┬─────────────────┬───────────────────────┤
│  ● Firewall       │  ● Scan         │  ● Login Security     │  ← 3 gauges circulares
│    100%           │    100%         │    100%               │
│  Protection from  │  Detection of   │  Brute Force +        │
│  known threats    │  security issues│  2FA Active           │
│  [Manage Firewall]│  [Manage Scan]  │  [Manage Login]       │
├───────────────────┴─────────────────┴───────────────────────┤
│  Notifications (N)              │  Firewall Summary         │
│  ┌─────────────────────────┐    │  ┌─────────────────────┐  │
│  │ ⚠ Plugin X needs update │    │  │ Today  Week  Month  │  │
│  │ ● New admin login from  │    │  │ Complex    1   6  24 │  │
│  │   IP 1.2.3.4            │    │  │ Brute Force 1  1  38 │  │
│  └─────────────────────────┘    │  │ Blocklist   0  0   0 │  │
│                                 │  │ Country     0  2   5 │  │
│                                 │  │ Total       2  9  67 │  │
│                                 │  └─────────────────────┘  │
├─────────────────────────────────┴───────────────────────────┤
│  Total Attacks Blocked                    [24 Hours][30 Days]│
│                                                             │
│  ████ Chart de linha com ataques ao longo do tempo ████    │
│                                           Last updated: 2m  │
├─────────────────────────────────────────────────────────────┤
│  Top Countries (Last 7 Days)    │  Recent Login Attempts    │
│  ┌─────────────────────────┐    │  [Successful] [Failed]    │
│  │ 🇷🇺 Russia      12      │    │  ┌─────────────────────┐  │
│  │ 🇨🇳 China        8      │    │  │ user  IP   time     │  │
│  │ 🇸🇬 Singapore    4      │    │  │ admin 1.2.3.4 2m    │  │
│  └─────────────────────────┘    │  └─────────────────────┘  │
└─────────────────────────────────┴───────────────────────────┘
```

### Gauges circulares (status dos módulos)
- **100% verde:** módulo ativo e sem problemas
- **Parcial amarelo:** ativo mas em modo degradado (ex: extended protection inativo)
- **Ícone vermelho ⚠:** módulo com problema crítico (ex: arquivos modificados, scan encontrou malware)
- Clicar no gauge leva direto à tela do módulo

### Widget "Firewall Summary"
- Tabela fixa com colunas: Block Type | Today | Week | Month
- Linhas: Complex (WAF rules), Brute Force, Blocklist, Country, Custom Pattern
- Linha "Total" com soma
- Clique em qualquer número → abre Live Traffic filtrado por aquele tipo

### Widget "Total Attacks Blocked"
- Gráfico de linha (Chart.js)
- Toggle 24 Hours / 30 Days
- Dados via REST, atualizados a cada 5 minutos
- Tooltip com valor exato ao passar o mouse

### Widget "Top Countries"
- Top 5 países por volume de ataques (últimos 7 dias)
- Flag emoji + nome do país + contagem
- Link "Block This Country" ao lado de cada linha

### Widget "Recent Login Attempts"
- Tabs: Successful | Failed
- Colunas: Username | IP | Date
- Máximo 10 linhas, link "Show more" → abre Login Security

---

## 4. Tela: Firewall

### Sub-tabs: [Firewall] [Blocking]

---

### 4a. Tab Firewall

```
┌─────────────────────────────────────────────────────────────┐
│  ● WAF (100%)  ● Rules (100%)  ● IP Blocklist  ● Brute Force │  ← 4 gauges
│  [Manage WAF]  [Manage Rules]  [Manage Blocklist] [Manage BF]│
├─────────────────────────────────────────────────────────────┤
│  Rate Limiting  │  Blocking  │  Country Blocking  │  Options │  ← Atalhos rápidos
├─────────────────────────────────────────────────────────────┤
│  Top IPs Blocked       [24h][7 Days][30 Days]               │
│  IP              Country          Block Count               │
│  1.2.3.4         🇷🇺 Russia             12  [Whois][Block]   │
│  5.6.7.8         🇨🇳 China               8  [Whois][Block]   │
├─────────────────────────────────────────────────────────────┤
│  Firewall Summary       │  Total Attacks Chart               │
│  (mesma tabela dashboard)│  (mesmo widget dashboard)         │
├─────────────────────────┴───────────────────────────────────┤
│  Login Attempts         [Successful][Failed]                 │
│  Username  IP           Date                                 │
│  admin     1.2.3.4      Jul 4, 2026 10:21 PM                │
└─────────────────────────────────────────────────────────────┘
```

---

### 4b. Tab Blocking

```
┌─────────────────────────────────────────────────────────────┐
│  Blocking                         [⚙ BLOCKING OPTIONS]      │
├─────────────────────────────────────────────────────────────┤
│  Block Type:  [IP Address]  [Country]  [Custom Pattern]      │
├─────────────────────────────────────────────────────────────┤
│  [Filter by Type, Detail, or Reason...]  [FILTER]           │
│  [UNBLOCK]  [MAKE PERMANENT]  [EXPORT ALL IPs]              │
│  ☐ Show DPXL Shield Automatic Blocks                           │
├──┬───────────────┬──────────┬────────────┬──────────────────┤
│☐ │ Block Type    │ Detail   │ Reason     │ Expiration       │
│  │ Block Count   │ Rule Added│ Last Attempt│                 │
├──┼───────────────┼──────────┼────────────┼──────────────────┤
│  │ (empty state) │          │            │                  │
│  │ No blocks active │       │            │                  │
└──┴───────────────┴──────────┴────────────┴──────────────────┘
```

**Block Type = Country → formulário inline:**
```
Modo: ● Block countries below  ○ Allow only countries below
Países: [lista com checkboxes + bandeiras + contagem de bloqueios]
[SAVE CHANGES]
```

**Block Type = Custom Pattern → formulário inline:**
```
Field:   [User-Agent ▼]   [Referer ▼]   [Hostname ▼]   [URL ▼]
Pattern: [___________________________________]
Match:   ● Contains  ○ Equals  ○ Regex
Action:  ● Block  ○ Log Only
Reason:  [___________________]  (opcional)
Expires: [never ▼]
[ADD RULE]
```

**Ações em linha (hover sobre qualquer linha):**
- [Unblock] — remove imediatamente
- [Make Permanent] — remove `expires_at`, seta `is_permanent = 1`
- [Whois] — abre Whois Lookup para aquele IP em modal

---

## 5. Tela: Scan

```
┌─────────────────────────────────────────────────────────────┐
│  Scan                                                        │
├─────────────────────────────────────────────────────────────┤
│  ● Scan Type: Standard  │  ● Malware Signatures  │  ● Rep   │  ← 3 gauges
│  [Manage Scan]          │  Signatures up to date  │  Checks  │
├─────────────────────────────────────────────────────────────┤
│  [START NEW SCAN]       [Scan Options & Scheduling ⚙]       │
├─────────────────────────────────────────────────────────────┤
│  ○ ─── ○ ─── ○ ─── ○ ─── ○ ─── ○ ─── ○ ─── ○ ─── ○ ─── ○  │  ← Barra de progresso
│  Spam  Block  Server  Files  Malware  Content  Public  Pass  │
│  Check Check  State  Changed  Scan    Safety   Files  Audit  │
├─────────────────────────────────────────────────────────────┤
│  Idle                          [EMAIL LOG] [VIEW LOG] [SHOW] │
├─────────────────────────────────────────────────────────────┤
│  Results Found (N)   │  Ignored Results (N)                  │
│  [DELETE ALL DELETABLE]  [REPAIR ALL REPAIRABLE]            │
├──────────┬───────────┬──────────┬───────────┬───────────────┤
│ Posts &  │ Themes &  │ Users    │ URLs      │ Results       │
│ Files: 0 │ Plugins: 0│ Checked:0│ Checked: 0│ Found: 0      │
├─────────────────────────────────────────────────────────────┤
│  ✅ No new issues found.                                      │
└─────────────────────────────────────────────────────────────┘
```

**Estado com resultados:**
```
┌─────────────────────────────────────────────────────────────┐
│  🔴 CRITICAL  wp-includes/functions.php modified            │
│  Core file differs from repository version.                 │
│  [VIEW FILE DIFF]  [REPAIR FILE]  [MARK AS IGNORED]         │
├─────────────────────────────────────────────────────────────┤
│  🟠 HIGH  Malware signature found in wp-content/cache/x.php │
│  Matches signature: generic-001 (eval+base64)               │
│  [VIEW FILE]  [DELETE FILE]  [MARK AS IGNORED]              │
├─────────────────────────────────────────────────────────────┤
│  🟡 MEDIUM  Plugin "Example Plugin" v1.2 has known CVE      │
│  CVE-2025-1234 (CVSS 7.8) — Update to v1.3 available        │
│  [UPDATE NOW]  [MARK AS IGNORED]                            │
└─────────────────────────────────────────────────────────────┘
```

**Scan em progresso:**
- Barra de estágios com ícone de check (✅) nos concluídos, spinner (⟳) no atual, círculos (○) nos pendentes
- Texto de status dinâmico: "Scanning wp-content/plugins... (234/512 files)"
- Botão "CANCEL SCAN" disponível durante execução

---

## 6. Tela: Login Security

### Sub-tabs: [Two-Factor Authentication] [Settings]

---

### 6a. Tab Two-Factor Authentication

```
┌─────────────────────────────────────────────────────────────┐
│  Two-Factor Authentication                [Learn more ↗]    │
│  Editing User: digitalpixel (you)                           │
├────────────────────────────┬────────────────────────────────┤
│  1. Scan Code or Enter Key │  2. Enter Code from App        │
│                            │                                 │
│  ┌──────────────────────┐  │  Download Recovery Codes       │
│  │                      │  │  (opcional)                    │
│  │   [QR CODE IMAGE]    │  │                                 │
│  │                      │  │  ba76 8bc9 f2bb a5ba           │
│  └──────────────────────┘  │  90e1 ed86 4eb5 b27b           │
│                            │  2990 36d8 6478 f4c2           │
│  [XXXXXXXXXXXXXXXXXXXXXXX] │  8475 cf26 a3c1 575a           │
│  ← Chave manual            │  2126 be44 6b29 dc92           │
│                            │                                 │
│                            │  [⬇ DOWNLOAD CODES]            │
│                            │                                 │
│                            │  [  123456  ]  [ACTIVATE]      │
└────────────────────────────┴────────────────────────────────┘
│  Server Time: ...   Browser Time: ...   Detected IP: ...    │
└─────────────────────────────────────────────────────────────┘
```

**Estado pós-ativação:**
```
✅ Two-Factor Authentication is ACTIVE for this account.
[DEACTIVATE 2FA]  [REGENERATE RECOVERY CODES]
```

**Comportamento de intercepção no login (v1.0.14):**
- O login só é interceptado para o desafio 2FA se o usuário **tiver 2FA configurada** (`dpxl_shield_totp_enabled` = true no user meta).
- Usuários cujo role está na lista "Enforce 2FA by Role" mas que ainda **não configuraram** 2FA são autenticados normalmente e redirecionados ao perfil com aviso para ativar.
- **Nunca** bloquear o login de um admin que não configurou 2FA — isso causaria lockout permanente.

---

### 6b. Tab Settings (Login Security)

```
┌─────────────────────────────────────────────────────────────┐
│  Brute Force Protection                                      │
│  ─────────────────────────────────────────────────────────  │
│  Lock out after X failed login attempts          [20    ]   │
│  Lock out after X forgot password attempts       [5     ]   │
│  Count failures over X minutes                  [5     ]   │
│  Amount of time a user is locked out (minutes)  [60    ]   │
│  Immediately lock out invalid usernames          ● On ○ Off │
│  Immediately lock out "admin" usernames          ○ On ● Off │  ← default Off (v1.0.14)
│  Notify by email when locked out                 ● On ○ Off │
├─────────────────────────────────────────────────────────────┤
│  Enforce 2FA by Role                                        │
│  ☑ Administrator  ☐ Editor  ☐ Author  ☐ Contributor        │
├─────────────────────────────────────────────────────────────┤
│  Additional Options                                         │
│  Check passwords against breach database (HaveIBeenPwned)  │
│  ● On ○ Off                                                 │
│  Require password reset if compromised           ● On ○ Off │
│  Hide WordPress login errors (generic message)   ● On ○ Off │
│  Disable XML-RPC authentication                  ● On ○ Off │
├─────────────────────────────────────────────────────────────┤
│                        [SAVE CHANGES]                        │
└─────────────────────────────────────────────────────────────┘
```

---

## 7. Tela: Tools

### Sub-tabs: [Live Traffic] [Audit Log] [Whois Lookup] [Import/Export] [Diagnostics]

---

### 7a. Tab Live Traffic

```
┌─────────────────────────────────────────────────────────────┐
│  Live Traffic                             [Learn more ↗]    │
│  Traffic logging mode: Security-related traffic only.       │
│  Login and firewall activity will appear below.             │
├─────────────────────────────────────────────────────────────┤
│  [All Hits ▼]   [Show Advanced Filters ▼]      ● Live Update│
├──┬──────────────┬──────────────────────┬───────┬────────────┤
│  │ Type         │ Location             │ Page  │ IP         │
│  │              │                      │Visited│ Response   │
├──┼──────────────┼──────────────────────┼───────┼────────────┤
│🟢│ Human        │ 🇧🇷 Belo Horizonte   │/      │ 1.2.3.4    │
│  │              │    Brazil            │       │ 200  [👁]   │
├──┼──────────────┼──────────────────────┼───────┼────────────┤
│🔴│ Blocked      │ 🇸🇬 Singapore        │/xmlrpc│ 5.6.7.8    │
│  │              │                      │ .php  │ 403  [👁]   │
├──┼──────────────┼──────────────────────┼───────┼────────────┤
│🟡│ Bot          │ 🇺🇸 United States     │/      │ 9.10.11.12 │
│  │              │                      │       │ 200  [👁]   │
└──┴──────────────┴──────────────────────┴───────┴────────────┘
```

**Filtros avançados (expandido):**
```
Type:     [All ▼]         Country:  [All ▼]
IP:       [________]      Response: [All ▼]
URL:      [________]      Date:     [From] [To]
User-Agent: [________]
[APPLY FILTERS]  [RESET]
```

**Modal de detalhe (botão 👁):**
```
┌─────────────────────────────────────────┐
│  Request Detail                   [✕]  │
│  IP: 1.2.3.4                           │
│  Country: 🇧🇷 Brazil / Belo Horizonte  │
│  Time: Jul 4, 2026 10:21:05 PM         │
│  Method: POST                          │
│  URL: /wp-login.php                    │
│  Response: 200                         │
│  User-Agent: Mozilla/5.0...            │
│  WAF Result: PASS                      │
│  ─────────────────────────────────     │
│  [BLOCK THIS IP]  [WHOIS LOOKUP]       │
│  [BLOCK IP RANGE /24]  [WHITELIST]     │
└─────────────────────────────────────────┘
```

---

### 7b. Tab Audit Log

```
┌─────────────────────────────────────────────────────────────┐
│  Audit Log                               [Learn more ↗]     │
├─────────────────────────────────────────────────────────────┤
│  ▼ Audit Log Options                                        │
│  Logging mode: [Disabled][Preview][● Significant Events][All]│
│  [RESTORE DEFAULTS]  [CANCEL CHANGES]  [SAVE CHANGES]       │
├─────────────────────────────────────────────────────────────┤
│  ⚠ Integrity: [VERIFY LOG CHAIN]  Last verified: 2h ago     │
├─────────────────────────────────────────────────────────────┤
│  Recent Events                                              │
├──────┬─────────────────────────┬──────────────────────────  │
│ Type │ Time                    │ Event                       │
├──────┼─────────────────────────┼──────────────────────────  │
│  🔵  │ Jul 4, 2026 10:20 PM   │ Plugin Activated: Akismet   │
│  🟡  │ Jul 4, 2026 10:15 PM   │ User Login: admin (success) │
│  🟣  │ Jul 4, 2026 9:45 PM    │ User Role Changed: editor→admin│
│  🔴  │ Jul 4, 2026 9:30 PM    │ IP Blocked: 1.2.3.4 (WAF)  │
└──────┴─────────────────────────┴──────────────────────────  │
│  ● Authentication  ● User/Permissions  ● Plugin/Updates      │
│  ● Firewall        ● Site Settings     ● Content             │
└─────────────────────────────────────────────────────────────┘
```

---

### 7c. Tab Whois Lookup

```
┌─────────────────────────────────────────────────────────────┐
│  Whois Lookup                                               │
├─────────────────────────────────────────────────────────────┤
│  IP or Domain: [1.2.3.4 or example.com    ] [LOOKUP]        │
├─────────────────────────────────────────────────────────────┤
│  Results for: 1.2.3.4                                       │
│  ─────────────────────────────────────────────────────────  │
│  Organization:  DigitalOcean LLC                            │
│  Country:       SG                                          │
│  ASN:           AS14061                                     │
│  IP Range:      1.2.3.0/24                                  │
│  Abuse Contact: abuse@digitalocean.com                      │
│  Source:        ipinfo.io                                   │
│  ─────────────────────────────────────────────────────────  │
│  ▶ Raw WHOIS response (expandable)                          │
│  ─────────────────────────────────────────────────────────  │
│  [BLOCK THIS IP]  [BLOCK RANGE /24]  [ADD TO WHITELIST]     │
└─────────────────────────────────────────────────────────────┘
```

**Comportamento de lookup:**
- Aceita IP (`1.2.3.4`) ou hostname (`example.com`). Hostname é resolvido para IP via DNS antes da consulta.
- Lookup via socket TCP porta 43 ao servidor WHOIS correto (ARIN/RIPE/APNIC/LACNIC/AFRINIC), com fallback para `https://ipinfo.io` se a porta 43 for bloqueada (comum em shared hosting).
- Resultados em cache por 1 hora (transients WP) para evitar rate limiting.
- Ao navegar via botão "Whois" no Live Traffic ou na tabela de IPs bloqueados, a aba abre com o IP pré-preenchido e a consulta é executada automaticamente.

**Estado de erro:**
```
❌ Cannot resolve "notadomain" to an IP address.
```
```
❌ Both WHOIS socket and ipinfo.io lookup failed. Check outbound connectivity.
```

---

### 7d. Tab Import/Export

```
┌─────────────────────────────────────────────────────────────┐
│  Import / Export Options                                    │
├─────────────────────────────────────────────────────────────┤
│  Export                                                     │
│  Download all DPXL Shield settings as a signed JSON file.     │
│  Includes: WAF rules, blocking config, scan settings,      │
│  alert preferences, login security settings.               │
│  Does NOT include: logs, scan results, TOTP secrets.       │
│  [EXPORT OPTIONS]                                           │
├─────────────────────────────────────────────────────────────┤
│  Import                                                     │
│  [Choose File]  dpxl-shield-export-2026-07-04.json            │
│  ⚠ This will overwrite your current settings.              │
│  [IMPORT OPTIONS]                                           │
└─────────────────────────────────────────────────────────────┘
```

---

### 7e. Tab Diagnostics

```
┌─────────────────────────────────────────────────────────────┐
│  Diagnostics                        [COPY DIAGNOSTICS]      │
├─────────────────────────────────────────────────────────────┤
│  Environment                                                │
│  ✅ PHP Version: 8.3.4 (supported)                          │
│  ✅ WordPress: 6.8.1 (latest)                               │
│  ✅ MySQL: 8.0.32                                           │
│  ─────────────────────────────────────────────────────────  │
│  DPXL Shield                                                   │
│  ✅ Extended Protection: Active (auto_prepend_file)          │
│  ✅ Plugin Integrity: All files verified                     │
│  ✅ GeoLite2 Database: Present (updated 3 days ago)         │
│  ✅ WordPress Cron: Running (last: 4 minutes ago)           │
│  ─────────────────────────────────────────────────────────  │
│  Server                                                     │
│  ✅ OpenSSL: Available                                       │
│  ✅ APCu: Available and active                              │
│  ✅ mbstring: Available                                      │
│  ⚠ Disk Space: 2.1 GB free (low, recommend 5+ GB)          │
│  ─────────────────────────────────────────────────────────  │
│  Permissions                                                │
│  ✅ wp-config.php: 640 (correct)                            │
│  ✅ /uploads/: 755 (correct)                                │
│  🔴 /wp-content/plugins/: 777 (too permissive, fix!)       │
└─────────────────────────────────────────────────────────────┘
```

---

## 8. Tela: All Options

```
┌─────────────────────────────────────────────────────────────┐
│  All Options          [RESTORE DEFAULTS] [CANCEL] [SAVE]    │
├─────────────────────────────────────────────────────────────┤
│  [🔍 Search All Options...                    ▼] [EXPAND ALL]│
├─────────────────────────────────────────────────────────────┤
│  Global Options                                             │
│  ▶ General Options                                          │
│  ▶ Dashboard Notification Options                           │
│  ▶ Email Alert Preferences                                  │
│  ▶ Activity Report                                          │
├─────────────────────────────────────────────────────────────┤
│  Firewall Options                                           │
│  ▶ Basic Firewall Options                                   │
│  ▶ Advanced Firewall Options                                │
│  ▶ Brute Force Protection                                   │
│  ▶ Rate Limiting                                            │
│  ▶ Country Blocking                                         │
│  ▶ Custom Pattern Blocking                                  │
│  ▶ Allowlisted URLs                                         │
├─────────────────────────────────────────────────────────────┤
│  Scan Options                                               │
│  ▶ Scan Scheduling                                          │
│  ▶ Basic Scan Type Options                                  │
│  ▶ Performance Options                                      │
│  ▶ Advanced Scan Options                                    │
├─────────────────────────────────────────────────────────────┤
│  Tool Options                                               │
│  ▶ Live Traffic Options                                     │
│  ▼ Audit Log Options          ← expandido                   │
│    Logging mode: [Disabled][Preview][● Significant][All]    │
│    [SAVE CHANGES]                                           │
│  ▶ Import/Export Options                                    │
│  ▶ Login Security Options                                   │
└─────────────────────────────────────────────────────────────┘
```

**Busca em tempo real:** ao digitar no campo de busca, as seções são filtradas e apenas as opções que contenham o termo ficam visíveis (expand automático das seções relevantes, colapso das demais).

---

## 9. Componentes Reutilizáveis

### Status Gauge (círculo de progresso)
```html
<!-- Componente: dpxl-shield-gauge -->
<div class="dpxl-gauge" data-value="100" data-status="ok">
  <svg>...</svg>
  <span class="dpxl-gauge__label">Firewall</span>
  <span class="dpxl-gauge__sub">Protection active</span>
  <a class="dpxl-gauge__action">Manage Firewall</a>
</div>
```
- `data-status`: `ok` (verde), `warning` (amarelo), `error` (vermelho)
- Valor vem via REST, não via PHP render

### Traffic Dot (indicador de tipo)
```html
<span class="dpxl-dot dpxl-dot--green" title="Human"></span>  <!-- 🟢 -->
<span class="dpxl-dot dpxl-dot--red" title="Blocked"></span>   <!-- 🔴 -->
<span class="dpxl-dot dpxl-dot--yellow" title="Bot"></span>    <!-- 🟡 -->
<span class="dpxl-dot dpxl-dot--orange" title="Suspicious">    <!-- 🟠 -->
```

### Audit Category Dot
Classes são baseadas em **cor**, não em categoria. O mapeamento categoria → cor é feito no JS:

```js
// admin.js — auditDot()
const map = {
    authentication:  'yellow',  // 🟡
    user_permissions:'purple',  // 🟣
    plugin_themes:   'blue',    // 🔵
    firewall:        'red',     // 🔴
    site_settings:   'green',   // 🟢
    content:         'gray',    // ⚪
};
```

```html
<span class="dpxl-audit-dot dpxl-audit-dot--yellow" title="Authentication"></span>
<span class="dpxl-audit-dot dpxl-audit-dot--purple" title="User/Permissions"></span>
<span class="dpxl-audit-dot dpxl-audit-dot--blue"   title="Plugin/Updates"></span>
<span class="dpxl-audit-dot dpxl-audit-dot--red"    title="Firewall"></span>
<span class="dpxl-audit-dot dpxl-audit-dot--green"  title="Site Settings"></span>
<span class="dpxl-audit-dot dpxl-audit-dot--gray"   title="Content"></span>
```

### Alert Banner (topo das telas)
```html
<!-- Sucesso -->
<div class="dpxl-notice dpxl-notice--success">Settings saved.</div>
<!-- Aviso -->
<div class="dpxl-notice dpxl-notice--warning">
  Extended Protection is not active.
  <a>Fix this</a>
</div>
<!-- Crítico -->
<div class="dpxl-notice dpxl-notice--error">
  🔴 Malware found in 2 files. <a>View Results</a>
</div>
```

---

## 10. Estados Especiais

### Estado vazio (sem dados)
- Live Traffic sem registros: "No traffic logged yet. Traffic will appear here as visitors access your site."
- Scan sem issues: "✅ No security issues found. Your site is clean."
- Blocking sem bloqueios ativos: "No blocks are currently active."

### Estado de carregamento
- Dados via REST: skeleton loading (barras cinzas animadas) em lugar dos valores enquanto carrega
- Nunca mostrar 0 durante carregamento (confunde com "nenhum ataque")

### Estado de erro de conectividade
- Se REST falhar: "Unable to load data. Check your server connectivity." com botão de retry
- Indicadores de status nunca ficam em estado desconhecido silencioso — sempre erro explícito

### Extended Protection não configurado
- Banner amarelo fixo em todas as telas: "⚠ Extended Protection is not active. Your firewall loads after WordPress, reducing protection. [Enable Now]"
- "Enable Now" abre wizard modal passo a passo

---

*Documento atualizado em 2026-07-05 — versão 1.2. Serve como referência de UI para o desenvolvimento frontend do painel.*

---

**Plugin:** DPXL Shield  
**Desenvolvido por:** [Digital Pixel](https://digitalpixel.com.br/)  
**Ícone oficial:** dpxl-shield-icon.png (logo DPXL Shield fundo preto)
