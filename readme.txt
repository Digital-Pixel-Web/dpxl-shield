=== DPXL Shield ===
Contributors: digitalpixelbr
Tags: security, firewall, malware scanner, login protection, two-factor authentication
Requires at least: 6.4
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 1.7.3
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
* Weekly / monthly activity report email, with a branded PDF attachment
* Deactivation and deletion guard — alerts you even if a plugin is deleted

**Integrations**
* Outbound webhooks to Slack, Discord, PagerDuty or any SIEM — up to 10 endpoints, each with its own severity threshold
* HMAC-SHA256 signed payloads so your receiver can verify they came from your site
* Read-only REST API with bearer-token authentication — pull the audit log, traffic log, scan results and firewall status into your own tooling
* One token per integration, revocable independently; tokens are stored hashed and shown only once

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
* `cdn.jsdelivr.net` — signed threat-feed manifest and WAF rule updates (daily; can be disabled)
* `github.com` — GeoLite2 country database download, served as a release asset (only when a newer database is published; can be disabled)

These are plain downloads: the plugin sends no site data, no identifiers, and no telemetry with them. No data is sent to Digital Pixel servers.

= Third-party data =

This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com.

The GeoLite2 Country database powers country blocking and the country breakdown in the dashboard and reports. It is distributed through the plugin's signed update feed and refreshed automatically so it stays current.

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

= 1.7.3 =
* **Fixed: keeping Akismet up to date was reported as modified core files.** WordPress ships Akismet and the default themes, so its checksum manifest lists them — 444 files under wp-content in 7.1.3. Those components update on their own schedule, independently of core, which is how they are meant to work; comparing them against the core release therefore reported a well-maintained site as having 21 modified core files. Core integrity now covers what is actually core: wp-admin, wp-includes and the root.
* **Fixed: the "Silence is golden" index.php was reported as executable code in uploads.** WordPress and most plugins drop one of these into every directory they create, to stop the folder being listed — it is a protection, not a payload. A file named index.php containing nothing but an opening tag and comments is no longer reported. One carrying actual code still is.

= 1.7.2 =
* **Fixed: findings piled up instead of being updated.** Every scan recorded its findings again, so a file that kept matching produced one row per scan indefinitely — on one site 34 files had become 2,380 open findings across 70 scans. The number of critical issues on the dashboard is what tells you whether to worry, and at that size it tells you nothing. Scans now reconcile: a finding already open keeps its original detection date, one that has gone away is marked resolved, duplicates left by earlier scans are collapsed, and a corrected severity reaches the existing record.
* **Fixed: PHP generated by plugins under uploads was reported as critical.** The check exists because media uploads should never be executable code — but several plugins write PHP into their own working directories beneath uploads, WPML compiling Twig templates being the common case. Those are now reported at medium with an explanation, while PHP in the media directories stays critical, which is where a malicious upload actually lands.
* Findings from detections corrected in 1.7.1 clear themselves on the next scan, including the `wp-includes/version.php` core-mismatch records left over from before that file was added to the ignore list.

= 1.7.1 =
* **Fixed: an administrator could be blocked from their own site for 30 minutes.** The behavioural detector blocks any IP that requests more than 50 unique URLs in a minute. Working in wp-admin crosses that without trying — every admin-ajax call carries its own query string, so each one counts as a distinct URL — and nothing exempted a logged-in administrator. On one install this locked the site owner out six times before the alert was connected to the cause. Administrators are now exempt: someone who can already install plugins gains nothing by crawling the site, so there was no signal here to lose.
* **Fixed: the "PHP code embedded in image file" signature flagged ordinary PHP files, including WordPress core.** It was written for a polyglot — a real image carrying PHP — but ran against .php files and matched any mention of an image format within 100 characters of an opening tag. That caught `wp-admin/includes/media.php`, and every library that reads images: a GIF parser matched on its own namespace. The signature now applies only to files that claim to be images, and looks only at the header area where a polyglot hides. Images in the uploads directory are scanned for it, which is the only place the threat can arrive.
* **Fixed: the JavaScript card-skimmer detection flagged form and page-builder libraries.** It searched the whole file for a card field name, a network call and a URL, each independently — so any bundle containing all three anywhere was reported as a skimmer. In one case the card field and the network call were 1.8 MB apart, in unrelated code. The three now have to appear together, as they do in a real skimmer, which reads a field and sends it immediately.
* Scan findings from the two corrected signatures, and blocklist findings from before 1.6.3, are cleared on update. They were never real, and left in place they would keep the dashboard red and the critical count meaningless.

= 1.7.0 =
* **New: Spamhaus DQS key support (Settings → Global → Blocklist Checks).** Spamhaus refuses lookups that reach it through a public DNS resolver, which is what most shared hosting uses — so on those servers the free public mirrors cannot answer at all, and the blocklist checks could not run no matter how they were written. A Data Query Service key gives the site its own query zone and makes the checks work; Spamhaus offers a free tier for non-commercial use with low query volumes, and paid accounts otherwise. Without a key the checks still run against the public mirrors, and report as unavailable where those refuse.
* The key is excluded from settings exports, like webhook credentials. A key is an account with a query quota: restoring one bundle across many sites would point them all at a single key and exhaust it, blocking the checks everywhere at once.
* A malformed key falls back to the public mirrors rather than being pasted into a DNS name, and surrounding whitespace from copy-and-paste is tolerated.
* Changed: blocklist answers are now read per Spamhaus's documented ranges — listings occupy 127.0.0.0/16, while 127.255.255.0/24 carries error codes. Addresses are compared as numbers rather than by text prefix.
* New: an answer outside 127.0.0.0/8 is recognised as a resolver rewriting unknown names instead of returning NXDOMAIN, and reported as unavailable. Previously such an answer would have been read as a listing, flagging every site behind that resolver.
* New: a scan whose blocklist checks could not run now records that, at low severity, instead of reporting a clean result. A check that never ran is not a clean bill of health.

= 1.6.3 =
* **Fixed: the site could be reported as blocklisted when it was not listed anywhere.** Spamhaus answers a listing and a refused query the same way — with a DNS record — and only the address tells them apart. Listings come back as 127.0.1.x (DBL) or 127.0.0.x (ZEN); the 127.255.255.x range is an error code, most often "anonymous query through a public resolver". Any answer was being counted as a listing, so on a server whose DNS Spamhaus treats as a public resolver, every domain read as blocklisted permanently — a domain that did not even exist came back "listed".
* Blocklist answers are now interpreted. A check that could not run is reported as unavailable: it raises no alert, and it is not folded into "clean" either, because a reputation check that never ran is something you should be told about rather than have hidden. Note that on hosts using a public DNS resolver the Spamhaus checks will correctly report as unavailable until a Spamhaus DQS key is configured — they stop reporting false listings, but they cannot run without one.
* **Fixed: only one of the site's IP addresses was checked.** Sites behind round-robin DNS or a CDN answer with several addresses, and only the first was tested — which one varied between runs, because resolvers rotate the order. An address sitting on a blocklist could go unreported for days and then surface at random. All addresses are now checked, and one listed address flags the site.
* Fixed: alert emails carrying structured details printed the literal word "Array" instead of the values. Affected any alert with nested context — the blocklist alert showed "Array, Array, Array" where the per-check results belonged.

= 1.6.2 =
* **Fixed: a WordPress core update could be reported as a compromise, once an hour, indefinitely.** The integrity monitor compared critical core files against a baseline recorded on this site. A baseline only says a file is no longer what it was — which is equally true of a routine update, and core updates rewrite these files legitimately. Updates that do not run through WordPress's own upgrader never refreshed the baseline: background auto-updates, WP-CLI, and host control panels all fall in that gap. The stale baseline then produced a critical "file modified" email every hour, for a file that was untouched official WordPress.
* The monitor now checks the official WordPress.org manifest for the running version before raising anything. A file that is byte-for-byte the official release is adopted as the new baseline, silently. A file that differs from the official release still alerts, as does one that cannot be confirmed — `wp-config.php` is not shipped by core, and WordPress.org can be unreachable. Unknown is not treated as safe.
* **Fixed: "Admin login from a new IP" fired on almost every login from an unchanged home connection.** Residential IPv6 rotates the last half of the address every few hours, so one router emits an endless stream of distinct addresses. On a real site this meant eight "new" addresses across eleven logins, all from the same network — and an alert that cries wolf is an alert you stop reading.
* New-IP detection now compares the network rather than the exact address: the /64 prefix for IPv6, the whole address for IPv4. Widening IPv4 as well would group unrelated customers of the same provider together and weaken a signal that works. Addresses already recorded are folded into their network when read, so the change does not announce networks the account has used before.

= 1.6.1 =
* **Fixed: changing a user's password from the profile screen failed with a fatal error.** The breached-password check declared the wrong type for one of its arguments — WordPress passes a partially built object there, not a full user — and the mismatch aborted the save. Present since 1.0.3 and triggered on every password change through the profile screen.
* Fixed: creating a new user could also fail in the same check, which assumed a user ID that does not exist yet at that point. The weak-password rejection still applies on creation; only the bookkeeping is skipped.
* Fixed: two login-failure handlers required an argument that WooCommerce and custom login forms do not always send, which could produce a fatal error on the login page. They now tolerate its absence.

= 1.6.0 =
* **New: read-only integration API.** Systems that prefer to pull rather than receive can now read the audit log, traffic log, scan results and firewall status over REST, authenticated with a bearer token. This completes the integrations work started in 1.5.0.
* New: API tokens are managed in Tools → Integrations. Each integration gets its own token so one can be revoked without disturbing the others. Tokens are stored hashed — the plaintext is shown once, at creation, and cannot be recovered afterwards.
* The API is read-only by design: there is no endpoint that changes anything, so a leaked token cannot be used to alter your site's protection.
* Collections are cursor-paginated rather than offset-paginated. These logs grow between a client's calls, and with an offset the client would silently re-read or skip records every time that happened.
* Rate limited per token, deliberately below the firewall's own REST ceiling so a busy client gets a clear "rate limit exceeded" response instead of being blocked by the WAF with no explanation.
* Repeated authentication failures from one address are locked out and recorded in the audit log — probing for a valid token is something you should be able to see.
* Compatible with Apache/CGI hosting, which strips the Authorization header before PHP sees it; the rewritten variants are read as a fallback.

= 1.5.0 =
* **New: outbound webhooks (Tools → Integrations).** Push security events to Slack, Discord, PagerDuty or any SIEM as they happen. Up to 10 endpoints, each with its own severity threshold — so a chat channel can take only critical events while a SIEM takes everything. Each destination receives the payload shape it actually expects, and a "Test" button reports exactly what the endpoint answered.
* New: generic (SIEM) payloads can be signed with HMAC-SHA256, including a timestamp so a captured payload cannot be replayed later.
* Changed: webhook delivery is queued during the request and sent after the response reaches the browser, so a slow or unreachable endpoint never adds latency to your site. Failures are recorded and shown per endpoint instead of disappearing silently.
* Changed: webhook endpoints are excluded from the settings export bundle. They carry live credentials — signing secrets, PagerDuty routing keys, and for Slack and Discord the URL itself — which do not belong in a file you download and forward.
* Changed: endpoints must use HTTPS. These payloads describe attacks against your site and are not sent in the clear.
* Note: the previous webhook implementation was never reachable — the setting it depended on had no interface and was never registered, so it could not fire. This release replaces it.

= 1.4.1 =
* Fixed: the Tools screen showed "View not found" on every tab in the 1.4.0 package. A packaging bug dropped the five tab templates from the zip — the plugin code was never affected, only the built archive. The build now verifies that every view is present before producing a zip.

= 1.4.0 =
* **Now runs on PHP 7.4.** The minimum PHP version drops from 8.1 to 7.4 — the same floor WordPress itself sets — so the plugin installs on older shared hosting. Every PHP 8 construct in the codebase was rewritten, and a build-time check (`composer check-php74`) now fails the release if any creeps back in.
* **Two-factor authentication no longer depends on an external library.** TOTP (RFC 6238) is now implemented in the plugin itself, verified against the RFC's official test vectors. This removed three dependencies — including one carrying two published security advisories — and keeps 2FA fully compatible with Google Authenticator, Authy, 1Password and every other standards-compliant app. Existing 2FA setups keep working; no need to re-enrol.
* New: the GeoLite2 database row in Diagnostics now reports its version, last update status and age, and warns if it drifts past MaxMind's 30-day freshness rule instead of only saying "present".
* New: MaxMind attribution is now shown in the admin, as required now that the plugin distributes the GeoLite2 database through its own feed.
* Changed: requests with no User-Agent are classified as **Suspicious** rather than **Bot**. Every browser and every well-behaved crawler identifies itself, so an absent User-Agent is anomalous, not a crawler — it no longer hides among Googlebot traffic. Live Traffic gains a "Suspicious" filter.
* Changed: alert emails now use the same Portuguese footer as the scheduled report, instead of falling back to English when sent from cron.
* Changed: the release build now trims the unused DejaVu Serif and Mono fonts from the PDF engine, cutting about 3 MB from the download. Report rendering is byte-identical.
* Fixed: `Tested up to` now reflects WordPress 7.0, and the privacy section documents the threat-feed and GeoLite2 downloads that were previously undisclosed.

= 1.3.1 =
* Fixed: the "Check now" button (All Options → Firewall) now also downloads/updates the GeoLite2 database on demand, not just the WAF rules — so you no longer have to wait for the scheduled job to install geolocation. The result of both is shown.

= 1.3.0 =
* New: the GeoLite2 geolocation database now installs and updates itself automatically through the signed feed — no manual per-site upload. Country data (dashboard widget, activity report, country blocking) starts working on its own after the next scheduled update. The database is verified (SHA-256 + signed manifest) before use and kept fresh automatically. Includes GeoLite2 data created by MaxMind (https://www.maxmind.com).

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
