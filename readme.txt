=== DPXL Shield ===
Contributors: digitalpixelbr
Tags: security, firewall, malware scanner, login protection, two-factor authentication
Requires at least: 6.4
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 1.9.6
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

= 1.9.6 =
* **Fixed: "could not check" was being reported as "compromised".** Before raising a file-integrity alarm, the plugin asks WordPress.org whether the file on disk is the official release. That question has three answers, and two of them were landing in the same place. `false` deserves the alarm: the file was compared against the official manifest and differs. `null` is something else entirely — the comparison could not be made, because the version WordPress reports does not match the files on disk (which is the case for the minutes a core update is in progress), because the file is absent from that version's manifest, or because api.wordpress.org did not answer. None of that is evidence of anything, and calling it critical is how a reader learns to ignore the sender. On one staging install this produced between one and eight "Critical file modified" emails a day for weeks about `wp-admin/includes/plugin.php` — a file `wp core verify-checksums` reported as byte-identical to the official release. They stopped on their own the second a core update finished and the baseline was rewritten.
* **Added: a distinct event for it.** A change that could not be verified is now reported as a notice rather than a critical alert, under its own event type, and the alert states in its own body whether the comparison actually happened. The alarm for a file that genuinely differs from the official release is unchanged.

= 1.9.5 =
* **Fixed: the last nine English strings, all written in JavaScript.** The translation layer only covers strings the PHP asks it for, so anything the browser writes was out of its reach — the empty states on Integrations and the audit log, the two confirmation prompts for removing a webhook or revoking a token, and the help text under the signing-secret field. Visible only once you had something configured, or were about to delete it.

= 1.9.4 =
* **Fixed: the Integrations tab was unreachable.** Its link was in the navigation and its screen existed, but the list of allowed tabs did not know the name, so the request was silently rewritten to Live Traffic — and Live Traffic then sat on "Loading…" forever, because the script that fills it keys off the tab name in the address, which still said integrations. Nothing failed out loud; the screen holding the webhook and API-token setup simply could not be opened. Found while checking the translations that screen had just received.
* **Added: a check that the three tab lists agree.** The Tools screen keeps its tabs in three places — the allow-list, the navigation and one file per tab — and this one was in two of them.
* **Fixed: the Diagnostics section headings** were still in English above the rows translated in 1.9.3.

= 1.9.3 =
* **Changed: the rest of the plugin speaks Portuguese.** Sixty-four strings the screens asked the translation layer for were not in it, so they reached the user in English inside otherwise Portuguese pages — every paragraph explaining webhooks, API tokens, the Spamhaus key and the GeoLite2 feed, along with the filter labels, the severity thresholds and a dozen buttons. The Diagnostics tab was English end to end: thirty-two labels, values and recommendations. And the scan findings themselves — the sentence describing what was found, which is also what the weekly report and the alert email carry — were written in English at the point each detector produced them.
* **Added: a check that no English sentence can reach a screen again.** The translation layer has no way to know a string was forgotten, so a test now reads every string the views ask for, and fails naming any that looks like an English sentence and has no translation. It is the third guard of this kind, after the icon lists and the alert field labels; all three exist because the same class of regression came back.
* **Fixed: an outdated theme was reported as "Theme"** in the middle of a Portuguese sentence, because the component type came straight from WordPress.

= 1.9.2 =
* **Fixed: the Live Traffic table named its own categories in English.** Each row read "human", "bot" or "blocked" — raw slugs straight from the code — while the colour legend added in 1.9.0 named the same four categories in Portuguese right below them, and the filter above used a third wording. All three now agree. The dot's tooltip was showing the slug too.

= 1.9.1 =
* **Fixed: the Firewall screen's status line was rewritten in English by the browser.** The page renders it in Portuguese and then refreshes it over REST so the status can change without a reload — and that second copy had never been translated, so it quietly overwrote the first one on every page load. It now matches, and names the detected server, which is the one fact worth keeping from the setup step that 1.9.0 folded away.

= 1.9.0 =
* **Changed: every scan finding now offers something to do about it.** The only button on a finding was Ignore — including on a critical one, and including on an outdated plugin, which is most of what a scan turns up on a real site. A product whose single affordance is dismissing the warning is teaching people to dismiss warnings. Repairable files keep Repair; an outdated component gets Update now, straight to the WordPress updates screen; and every finding gets a "How to fix" step list written for its own kind of doubt — delete-it advice for a confirmed signature, look-before-you-act advice for a heuristic that is not sure. The file path can be copied in one click, for work done over FTP or SSH. Ignore is still there, as a quiet link rather than the main button.
* **Fixed: the finding card read back to front.** The severity chip was taking the title's place in the grid, which pushed the title to the right-hand edge and left the description sitting where the title should be. Title first, severity on the right, description under both.
* **Changed: Extended Protection stops filling the screen once it is on.** The setup flow — two completed steps, four absolute paths, a manual fallback and a paragraph explaining the procedure — stayed at the top of the Firewall screen forever. When protection is active it is now one line naming the detected server, with the technical detail behind a disclosure. When it is inactive, every bit of the flow is still there, which is when it is the point of the screen.
* **Removed: a developer note comparing the plugin to Wordfence** was showing to users on the Firewall screen. Replaced with an explanation of what Extended Protection does and why it matters.
* **Changed: Live Traffic says what it does and does not cover**, and the colour dots have a visible legend. Their meaning lived in a title attribute, invisible on touch and to anyone not hovering.
* **Changed: Diagnostics opens already run.** The one screen that answers "is this server set up correctly" used to open blank behind a button, so it showed nothing until you knew to ask.
* **Added: Login Security shows how much of the site is actually covered** — how many administrators have finished setting two-factor up, not just whether you have. That is the figure the dashboard gauge reads, and on a real install it was zero while the gauge read 100%.

= 1.8.4 =
* **Fixed: the last English labels on the dashboard and firewall screens.** Looking at 1.8.3 running on a real install turned up four more: the empty notifications panel, the writable/not-writable answer for the .htaccess file, and the 7-day and 30-day range buttons.

= 1.8.3 =
* **Changed: the dashboard gauges count what is actually on, instead of printing 100%.** `firewall_ok` was `Options::get('firewall_enabled')` and nothing else, so a site with Extended Protection off, no firewall rules loaded and not one administrator using two-factor still showed three green rings at 100%. Each ring is now the share of that module's checks that pass — five for the firewall, three for the scan, three for login — and the line underneath names the first one that does not, as a link straight to it. A module cannot reach 100% while anything it covers is switched off.
* **Added: "not verified" as a state of its own, in grey.** A check that never ran is no longer folded into either green or red. A site nobody has scanned yet reads "no scan has been completed on this site" rather than showing a healthy ring; a blocklist that refused the query reads as unanswered rather than clean. This is the same distinction the reputation checker started making in 1.7.0, finally drawn on screen. Grey never turns green on its own.
* **Changed: the protection banner has four states, and every one of them that is not green carries the next step.** It used to have two — "active" and "degraded, see the notifications below", which asked the reader to go hunting. It now says which protection is missing and puts the button to fix it in the banner itself.
* **Changed: the Scan screen's three gauges report what happened.** The malware signatures read "100% / Loaded" and the reputation check read "100% / Blacklist checks", both written by hand regardless of what had run. They now show the real signature count, the real reputation result (clean, listed, or unanswered, naming the service that did not answer) and how long ago the last scan finished.
* **Changed: counts no longer sit inside a ring.** "14 rules" and "0 blocked IPs" were drawn in the same circle used for percentages, which read as "14% of something, and all of it fine". They are plain figures now. The WAF ring covers two checks rather than one: being switched on, and loading before WordPress.
* **Fixed: three empty states and several labels were still in English** on otherwise Portuguese screens — the attack chart, the blocked-IP table and live traffic among them.

= 1.8.2 =
* **Fixed: three pieces of English left behind by 1.8.0.** The alert for a finished scan opened with "deal first with what is marked critical", but 1.8.1 widened that alert to fire on high findings too, so it could arrive pointing at a section that was not there; it now says to start with the most severe findings, whatever those turn out to be. Thirteen context fields the detectors send — the lockout duration, the breach count, the number of findings, whether the plugin being deactivated was this one — had no Portuguese label, so each arrived as a humanised English slug ("Lockout seconds", "Hibp count") inside an otherwise Portuguese email. And a true/false field still read "yes" or "no". All three are the same half-translation 1.8.0 set out to remove.
* **Added: a check that reads the detectors instead of trusting a list.** Those labels went missing because a change elsewhere added two context keys and nothing connected the two sides. A test now walks every alert payload in the source, collects the keys each one sends, and fails naming any key that has no label — the same kind of guard the icon lists got in 1.7.4.

= 1.8.1 =
* **Fixed: the dashboard's security gauge read 100% with a malware signature open, and no email ever went out about it.** The gauge, and the alert sent when a scan finishes, both asked whether anything was *critical*. The one finding open on two installs was a matched malware signature rated high — so from July onwards the panel reported perfect health over an open finding the Scan screen was listing all along, and not one alert email was sent about it. Both now treat high the same as critical, which is the line the threat count itself already drew. Medium is deliberately left out: those are the findings the scan says it is unsure about, and turning the gauge red for each of them is the same crying-wolf problem from the other side. They are still listed and still counted.

= 1.8.0 =
* **Changed: alert emails now say who, from where, and what to do.** An alert used to be one fact and a table of raw fields. One of those fields read `Endereço IP: 2804:d45:b005:1800:dcd6:a6ff:45ec:ac02` and nothing more, which is not something a reader can act on. Every alert now carries four blocks in a fixed order: what happened, who it was and where they came from, what to do about it, and the raw fields last. The origin names the country from the bundled GeoLite2 database and the provider from whatever the Whois tool has already fetched; where the provider is unknown it says so and points at the tool, instead of leaving a blank that reads as "checked, nothing there". Nothing in that block goes out to the network, so no login gets slower to decorate an email. For IPv6 the block also names the network the address belongs to — on residential connections the address itself rotates, and the network is what the plugin actually compares against.
* **Changed: every alert tells you what to do, including when the answer is nothing.** An alert that cannot be acted on and does not say so is how people learn to ignore the sender. A lockout now opens with "no action is necessary: the block is automatic and expires on its own"; a tampering alert opens with "run a full scan now". Three events that genuinely fire on normal activity — a login from a new network, a changed file, a traffic pattern — also carry one line explaining why they can appear when nothing is wrong.
* **Changed: the alert catalogue is in Portuguese.** Titles, explanations and field labels were still English while the email around them had been Portuguese since 1.4.0, so every alert arrived half-translated, subject line included. The same strings feed the webhook, Slack and Discord integrations, so those payloads are in Portuguese now too. What is still English is the one-line description each detector passes along; it has moved out of the opening sentence into the technical block, where nothing is lost.
* **Changed: the alert's button opens the screen the alert is about.** Every alert used to link to the plugin's front page, leaving the reader to hunt for what the email had just told them. A login alert opens Login Security, a scan alert opens the scan results, a blocking alert opens the Blocking tab. The subject line also gained one exception to its own rule: `critical` now says so, because an unopened malware alert costs more than the noise. Everything below critical still arrives without shouting.

= 1.7.8 =
* **Fixed: a malware signature was reporting the registration setting every plugin writes.** The signature flagged any file that turns user registration on, which is what a registration switch does when you switch it on — so a plugin whose login screen offers that switch was reported as matching a malware signature on two installs, from July onwards, and kept matching on every scan. Turning registration on is a setting; what a backdoor does, and no settings screen does, is turn it on *and* hardcode administrator as the role every new account gets. The signature now requires both halves before it reports anything. Across 30,000 files on two installs it now matches nothing, where before it matched the one file that was never a threat.

= 1.7.7 =
* **Changed: two kinds of finding no longer count as threats when the scan itself rated them medium.** The threat count is the figure you look at to decide whether something needs doing, and two findings were inflating it. PHP files inside a directory a plugin compiles into — WPML writes its page templates there as PHP, and does so by design — were already being rated medium by the scan, with the finding itself saying they are not evidence of a compromise; they were counted as threats regardless. Components merely running behind the latest release were counted the same way, although that check records a known vulnerability as high or critical and an available update as medium, so the two were indistinguishable on the badge. Both now count as threats only when the scan rated them high or critical, matching how exposed files have always been treated. On one install the count went from 40 to 1, on another from 19 to 1. Nothing was hidden: every demoted finding appears under Recommendations with its own count, and the weekly report lists components needing an update exactly as before.
* **Fixed: the Scan screen could show the previous threat count alongside the new one.** The screen takes its figure from two places — a live count of what is open, and a total recorded when the last scan finished — and writes both into the same place, so whichever answered last won. The two always agreed until the rule above changed what counts, at which point the recorded total would have gone on reporting the old figure until the next full scan. The screen now counts what is open, every time.

= 1.7.6 =
* **Fixed: the dashboard reported open threats that the Scan screen showed none of.** The dashboard counted every threat still open; the Scan screen listed only the findings the most recent scan had recorded for the first time. Since 1.7.2 a scan leaves an already-open finding on its original record — the date it was first seen is the honest one — so a problem that keeps being detected is never re-recorded, and the Scan screen stopped showing it. On one install that meant a dashboard reading 19 open threats beside a Scan screen reading none, including a malware signature open since July. Both screens now count what is open, which is what the latest scan found: a scan closes whatever it no longer sees, so the two figures are drawn from the same records and cannot disagree.
* **Fixed: "Repair all repairable" skipped files that had been reported before.** It selected only what the most recent scan had recorded, so a modified core or plugin file that kept being detected — exactly the kind that needs repairing — was never included, while the button's own count included it. It now repairs every open repairable file.
* **Fixed: an hourly scan could mark every open finding as resolved.** The hourly scan only examines files changed since the last full scan, but it closed any finding it did not come across — and it comes across almost nothing, by design. The first time it had found something, every other open finding on the site would have been silently marked resolved. It now only records what is new; closing a finding is left to the full scan, which does look everywhere.

= 1.7.5 =
* **Fixed: a filtered Live Traffic request reported a total of zero matches.** The traffic endpoint builds one set of conditions and uses it twice — once for the page of rows it returns, once to count how many rows match in total. The count ran without binding the filter values, so the placeholders for the IP and URL filters reached the database as literal text, the query failed, and the total came back as zero while the rows themselves came back correctly. The count now binds the same values as the page query. Nothing in the panel displayed this total yet, so no screen was showing a wrong number; the figure was simply waiting to be wrong for whoever used it first.

= 1.7.4 =
* **Fixed: the Live Traffic tab never loaded.** It sat on "Loading…" for as long as you left it open, made no request at all, and the "Show Advanced Filters" button did nothing. Two variables the loader needs were declared just below the line that called it, so reading one threw before the first request was built; the error escaped the loader's error handling, and the code that attaches the filter and live-update controls was never reached. Both symptoms had the same single cause, which is why the tab was inert rather than merely slow.
* **Fixed: the Firewall Summary table contradicted itself.** The four per-type rows were zeros written into the panel's JavaScript, while the Total row below them counted real blocks — so the first genuine attack produced a table reporting a total of blocks and, immediately above it, nothing in any category. The rows and the Total are now folded from one query over the same records, so they cannot disagree. Types that blocked nothing are left out, and an install with no blocks at all says why instead of showing a grid of zeros.
* **Fixed: the Location column of Live Traffic was always empty.** The firewall already geolocates every logged request, and the dashboard's blocked-countries widget was reading it, but the traffic table rendered a dash in every row regardless. It now shows the country the request came from, where it is known.
* **Fixed: four icons rendered as a generic information circle.** The panel keeps its icon set in two places — one for markup built on the server, one for rows built in the browser — and the browser copy was missing `lock`, `sliders`, `upload-cloud` and `users`. Each fell back to the info glyph without any error, so the drift was invisible. The two lists are now identical and a test fails if they ever diverge again.

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
