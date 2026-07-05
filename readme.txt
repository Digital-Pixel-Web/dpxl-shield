=== DPXL Shield ===
Contributors: digitalpixelbr
Tags: security, firewall, malware scanner, login protection, two-factor authentication
Requires at least: 6.3
Tested up to: 6.7
Requires PHP: 8.1
Stable tag: 1.0.3
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Enterprise-grade WordPress security: WAF, malware scanner, 2FA, brute force protection, audit log, and real-time traffic monitoring.

== Description ==

**DPXL Shield** is a comprehensive security plugin built for WordPress sites that demand reliability and transparency. It runs a Web Application Firewall (WAF) *before* WordPress loads — so threats are stopped at the door, not inside your house.

= Core Features =

**Web Application Firewall**
* Extended mode: loads via `auto_prepend_file` — runs before WordPress, PHP sessions, or plugins
* Basic mode: hooks into `plugins_loaded` with the same rule engine
* Built-in rules for SQL injection, XSS, path traversal, remote file inclusion, and shell injection
* GeoIP country blocking (MaxMind GeoLite2)
* IP blocklist with CIDR range support
* Custom regex pattern blocking
* IP allowlist / whitelist management
* Rate limiting per IP

**Malware Scanner**
* Full-site file integrity scan with SHA-256 hashing
* WordPress core file verification against official checksums
* Plugin signature checking
* Malware signature database (100+ patterns)
* Content safety scanning (iframes, external scripts, hidden links)
* Password strength and HIBP breach audit for all users
* Site reputation check (Google Safe Browsing + Spamhaus)
* One-click file repair for modified core and plugin files

**Login Security**
* Brute force protection with configurable lockout thresholds
* TOTP-based two-factor authentication (RFC 6238 — compatible with Google Authenticator, Authy, etc.)
* Per-role 2FA enforcement
* Honeypot hidden fields
* Login activity log

**Audit Log**
* SHA-256 hash chain — every entry is cryptographically linked to the previous one
* Tamper detection: chain verification UI in admin
* Four logging modes: Disabled, Preview (last 100), Significant Events, All Events
* Covers: logins, logouts, user changes, plugin activation, theme switches, option changes, firewall events

**Real-Time Traffic**
* Per-request logging with WAF decision, response time, status code
* Traffic classification: Human / Bot / Blocked / Suspicious / Unknown
* Advanced bot detection (confidence score 0–100)
* Anomaly detection: scanner sweeps, 404 floods, REST API abuse — auto-blocks offending IPs
* Live traffic view with 5-second auto-refresh and detail modal

**Alerts**
* Configurable email alerts for critical security events
* Webhook channel (premium)
* Weekly / monthly activity report email
* Deactivation and deletion guard — alerts you even if a plugin is deleted

**Tools**
* WHOIS & GeoIP lookup with one-click block/allowlist
* Import / Export settings (signed JSON bundle, integrity-verified on import)
* 16-point diagnostic check
* Self-protection: plugin tamper detection, PHP execution blocking in uploads

= Privacy =

DPXL Shield processes visitor IP addresses solely for security purposes and stores them in your own database. It makes optional outbound requests to:

* `api.pwnedpasswords.com` — k-anonymity password breach check (first 5 SHA-1 chars only)
* `ip-api.com` — WHOIS/GeoIP fallback (no account required)
* `safebrowsing.googleapis.com` — site reputation check (requires free API key)
* `raw.githubusercontent.com` — core file repair downloads

No data is sent to Digital Pixel servers.

== Installation ==

1. Upload the `dpxl-shield` folder to `/wp-content/plugins/`.
2. Activate the plugin through the **Plugins** menu in WordPress.
3. Navigate to **DPXL Shield → Dashboard** to review your site's security status.

**Optional — Extended WAF Mode (recommended):**

Add the following line to your `php.ini` or `.user.ini`:

```
auto_prepend_file = /absolute/path/to/wp-content/plugins/dpxl-shield/dpxl-shield-waf.php
```

Or, if your host allows it, add to `.htaccess`:

```apache
php_value auto_prepend_file /absolute/path/to/wp-content/plugins/dpxl-shield/dpxl-shield-waf.php
```

Extended mode blocks malicious requests before WordPress or any other plugin loads — providing maximum performance and protection.

== Frequently Asked Questions ==

= Will DPXL Shield slow down my site? =

No. The WAF pipeline is highly optimised and uses APCu in-process caching. Traffic logging writes on `shutdown` (after the response is sent). Extended mode has zero impact on WordPress boot time for legitimate requests.

= Is Extended WAF mode required? =

No. Basic mode (the default) hooks into `plugins_loaded` and runs the same rule engine. Extended mode is recommended for sites under active attack because it stops threats before WordPress initialises.

= Does 2FA work with WooCommerce / custom login pages? =

DPXL Shield hooks into `wp_authenticate` and `wp_login`, which are fired by all standard WordPress login flows. Custom forms that bypass these hooks will need additional integration.

= How does the hash chain work? =

Every audit log entry stores a SHA-256 hash of its own timestamp, event type, description, and the previous entry's hash. This creates a tamper-evident chain — modifying any entry invalidates all subsequent hashes. You can verify the chain at any time from **Tools → Audit Log**.

= Can I move my settings to another site? =

Yes. Use **Tools → Import / Export** to download a signed JSON bundle. The bundle is SHA-256-signed at export time and verified on import, so it cannot be tampered with.

= What data does the scanner check? =

The file scanner computes SHA-256 of every PHP file and compares it against a baseline taken at activation. For WordPress core files it also fetches official checksums from the WordPress API. Malware patterns are matched using a curated PCRE signature database.

== Screenshots ==

1. Dashboard — live threat gauge, attack chart, recent logins
2. Firewall — active rules, blocked IP management, country blocking
3. Scanner — staged scan progress, results with severity levels
4. Login Security — 2FA QR code setup, brute force settings
5. Live Traffic — colour-coded request stream with detail modal
6. Audit Log — hash-chain verified event log
7. Tools — WHOIS lookup, import/export, diagnostics

== Changelog ==

= 1.0.0 =
* Initial release.
* Web Application Firewall (extended + basic modes).
* File integrity scanner with malware signatures.
* TOTP two-factor authentication.
* Brute force protection with lockout.
* SHA-256 hash-chain audit log.
* Real-time traffic monitoring and bot detection.
* GeoIP country blocking (MaxMind GeoLite2).
* WHOIS lookup tool.
* Import / Export settings.
* 16-point diagnostics.
* Plugin self-protection (tamper detection, deactivation guard).

== Upgrade Notice ==

= 1.0.0 =
First stable release. No upgrade path from pre-release versions.
