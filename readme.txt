=== DPXL Shield ===
Contributors: digitalpixelbr
Tags: security, firewall, malware scanner, login protection, two-factor authentication
Requires at least: 6.4
Tested up to: 6.7
Requires PHP: 8.1
Stable tag: 1.2.1
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
* Vulnerability scanner — flags outdated plugins/themes (offline) with optional WPScan CVE lookup
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
* `wpscan.com` — known-CVE lookup for installed plugins/themes (only when a WPScan API token is configured; the base outdated-component check runs entirely offline)

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

= 1.2.1 =
* Fixed: the dashboard "Top Countries" widget no longer spins on "loading" forever — it now shows the top blocked countries (last 7 days), or a clear empty / "configure GeoLite2" state when there is no country data yet.
* New: request traffic is geolocated (via the GeoLite2 database) and the country is stored, so the dashboard widget and the activity report's countries section have data. Requires GeoLite2-Country.mmdb in the plugin's data/ directory.

= 1.2.0 =
* New: The activity report — both the email and the attached PDF — now covers what a security admin expects at a glance: components that need updates (from the vulnerability scan), most-blocked countries, top failed-login usernames, recently blocked attacks, and recently modified files, on top of the existing attacks/logins/top-IPs summary.
* Fixed: the firewall "rules" count now reflects the rules actually in force (built-in rules plus threat-feed rules), so it moves when the feed updates instead of showing a static number from a bundled file.

= 1.1.0 =
* New: Self-updating WAF rules (Threat Feed). The firewall now pulls a signed rule feed on a daily schedule and applies it without waiting for a plugin release — closing the gap where rules only changed on upgrade. Every update is verified with an Ed25519 signature and a SHA-256 checksum before it is applied, and the built-in rules remain an immutable floor the feed can only add to, never weaken. New "Threat Feed" controls under Firewall Options (on/off and "Check now") plus a status line in Tools → Diagnostics.
* Internal: the firewall rule engine is now data-driven (`JsonRule` / `RuleRepository`) alongside the built-in rules; feed writes are atomic with one-level rollback and an anti-rollback version guard. +36 tests (126 total).

= 1.0.27 =
* New: Scheduled PDF security report. The periodic activity report can now travel as a branded PDF attachment on the same daily/weekly/monthly email, and a "Download PDF" button on the All Options screen produces the report on demand. Rendered on-server with no external service.
* Data for the PDF and the HTML email now share a single collector (`ReportData`), so both always reflect the same figures.

= 1.0.26 =
* Internal: extended automated test coverage to the previously-untested security-critical modules — brute-force lockout escalation, self-protection baseline/tamper diff, 2FA backup codes and the form honeypot (86 tests total). Pure refactors to expose testable seams; no behavior change.

= 1.0.25 =
* New: Vulnerability scanner (Scan stage 9). Flags installed plugins and themes running an outdated version — the most common real-world entry point — using WordPress's own update data, with no external request and no API key required. Optionally enriches results with known CVEs from the WPScan vulnerability database when an API token is configured.
* Schema: `scan_results.issue_type` gains `vulnerable_version`; existing installs are migrated automatically on upgrade.

= 1.0.24 =
* Hardening: the pre-WordPress WAF pipeline is now fully null-safe — the IP blocklist, country blocker and custom-pattern blocker all fall back gracefully when `$wpdb` is unavailable (Extended Protection context), completing the v1.0.19 guard.
* Internal: restored the automated test suite to green (56 passing) and added direct coverage for the early-WAF bypass logic and the audit-log hash chain.

= 1.0.23 =
* UI: unified visual system across every admin screen — cards with soft shadows, refined gauges, small-caps table headers, underline tabs, and SVG section icons.

= 1.0.22 =
* UI: redesigned Scan screen — progress stepper (lock → spinner → check), severity chips, and human-readable result titles instead of raw slugs.
* UI: replaced every emoji with inline SVG icons so glyphs render identically across browsers and operating systems.
* Scan: new "Recommendations" section separates hardening advisories and low-confidence findings from real threats — they no longer inflate the problem count.

= 1.0.21 =
* Scanner: fixed mass false positives. Core integrity now always compares against the en_US checksum manifest, so localized (e.g. pt-BR) installs no longer flag untouched core files as modified.
* Scanner: version.php and other legitimately-varying core files are excluded from the checksum diff (still scanned for malware by content).
* Scanner: new threat/recommendation classifier — only high-confidence findings count as problems and fire critical alerts.
* Scanner: checksum cache is now keyed by WordPress version, so a core update busts a stale manifest instead of comparing against it for a day.

= 1.0.20 =
* Alerts: redesigned alert and activity-report emails — readable subject lines, muted severity styling (no full-width red banner), and human event titles.
* Alerts: "admin login from a new IP" downgraded from Critical to Notice; it is a routine event.

= 1.0.19 =
* Firewall: Extended Protection no longer triggers an HTTP 500 on wp-admin or page-builder (Elementor) saves — added a URI and logged-in-cookie bypass for requests that run before WordPress loads.
* Firewall: `$wpdb` null-guard in IpBlocklist for the pre-WordPress context.
* Database: self-healing table creation on boot; added the `auto_anomaly` block source to the schema.

= 1.0.14 =
* REST: output-buffer protection stops stray PHP notices from corrupting JSON responses on debug-enabled hosts.
* Self-protection: the tamper-detection baseline is now version-aware — no more false "files modified" alerts after a legitimate update.
* Login: fixed all administrators being blocked at login — 2FA interception now checks whether 2FA is actually configured for the user, not just required by role.
* Login: blocking the "admin" username is now opt-in (it was silently enabled by default).

= 1.0.4 – 1.0.13 =
* Fixed a REST error on the dashboard and a COUNT bug in the traffic statistics.
* Made plugin boot resilient to activation-time errors.
* Fixed four bugs in the WHOIS lookup tool.
* Fixed the 2FA `dpxl_2fa_required` redirect handling.

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

= 1.0.21 =
Major reduction in scanner false positives. Run a new scan after updating to see the corrected results.

= 1.0.19 =
Important fix: prevents HTTP 500 errors on wp-admin and page-builder saves when Extended Protection is active. Recommended for all users.

= 1.0.14 =
Critical login fix: resolves administrators being unable to log in. Update immediately if you use per-role 2FA enforcement.

= 1.0.0 =
First stable release. No upgrade path from pre-release versions.
