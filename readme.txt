=== DPXL Shield ===
Contributors: digitalpixel
Tags: security, firewall, malware scanner, two-factor authentication, brute force
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.12.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Free WordPress security: firewall, malware scanner, login protection, two-factor authentication and alerts. No paid tier, no telemetry.

== Description ==

Most hacked WordPress sites are not taken down by a sophisticated attack. They fall to a weak password, an outdated plugin, or a modified file nobody noticed. DPXL Shield closes those doors and tells you, in plain language, when something needs your attention.

It is built and maintained by [Digital Pixel](https://digitalpixel.com.br/), a WordPress agency, and given to the community for free. There is no premium version and nothing in the dashboard is locked.

= Why another security plugin? =

Because the parts small sites need most are usually the paid ones. In DPXL Shield they are all in the free plugin, with no limits and no upgrade prompts:

* **Country blocking and IP range blocking**, applied from the first request.
* **A tamper-evident audit log** (each entry is hash-chained to the previous one).
* **A PDF activity report** you can send to a client or a manager.
* **Email delivery monitoring**, so a broken mail setup does not silently swallow every other alert.
* **Signed webhooks and a read-only REST API** for Slack, Discord, PagerDuty or a SIEM.
* **No telemetry and no account.** Nothing is sent to Digital Pixel.

It was written for agencies and freelancers who look after many small sites, and its dashboard is in Brazilian Portuguese first.

= Blocks attacks before they reach your site =

* **Web application firewall** with rules for SQL injection, XSS, file inclusion, directory traversal and command injection.
* **Extended Protection (optional):** the firewall runs before WordPress loads, through `auto_prepend_file`. The plugin sets it up for you and rolls back on its own if your host does not support it.
* **IP and range blocking** (IPv4 and IPv6), **country blocking** and **rate limiting** on login, XML-RPC and the REST API.
* **Custom rules** by user agent, referrer or URL, plus an allowlist.
* **Honeypots:** invisible fields on login, registration and comment forms, and decoy URLs (`.env`, `phpinfo.php`, `.git/config`) that only bots visit.

= Finds problems on your site =

* **WordPress core integrity:** every core file is compared with the official WordPress.org checksums.
* **Malware signatures** for known backdoors, web shells and obfuscated code.
* **Outdated plugins and themes**, with optional known-vulnerability (CVE) lookups through WPScan.
* **Suspicious content** in posts and pages: iframes, external scripts and hidden links.
* **Domain reputation** with Google Safe Browsing and Spamhaus (your own key required).
* **One-click repair** of modified core files and WordPress.org plugin files, with a backup of the original.

= Protects the login =

* **Progressive lockouts** against password guessing (5 minutes, 1 hour, 24 hours).
* **Two-factor authentication (TOTP)** with Google Authenticator, Authy, 1Password and similar apps, plus recovery codes.
* **Leaked password check** (Have I Been Pwned) using k-anonymity: only the first 5 characters of the hash leave the server.
* Generic login error messages, user enumeration blocking and an option to turn off XML-RPC.

= Tells you when it matters =

* **An email on every administrator login**, and a stronger alert when the login comes from a new network.
* **Critical event alerts:** modified core file, malware found, security plugin deactivated.
* **Weekly or monthly report** by email, with a PDF.
* **Email delivery monitoring:** if the site stops being able to send email, you hear about it through another channel.
* **Integrations:** signed webhooks for Slack, Discord, PagerDuty or any SIEM, and a read-only REST API with per-integration tokens.

= Shows what is happening =

* **Live traffic**, split into people, bots, suspicious and blocked requests.
* **Audit log** of logins, users, plugins, themes and settings, hash-chained so edits stand out.
* **Diagnostics** for the server and configuration, and WHOIS/GeoIP lookups with one-click blocking.

= What it does not do =

* It does not make backups. Keep a separate backup plugin or service.
* It is not a cloud firewall. It runs on your server and cannot absorb large DDoS attacks; use a CDN such as Cloudflare for that.
* It does not clean an already hacked site by itself. Core and WordPress.org plugin files can be repaired; themes and custom files need a human.
* It does not send alerts by SMS or WhatsApp. Alerts go by email and webhooks.

= Interface language =

The admin interface is currently in Brazilian Portuguese. An English interface is planned.

= Where it keeps its data =

Settings, logs and blocklists are in your site's database. Files the plugin writes at runtime (firewall config, blocklist snapshot, rule updates, the country database and file-repair backups) go to `wp-content/uploads/dpxl-shield/`, closed to the web, never inside the plugin folder.

== External services ==

DPXL Shield sends no telemetry and nothing goes to Digital Pixel servers. It connects to the services below only for the purpose listed. Each one can be avoided by leaving the feature off.

= WordPress.org =

* `api.wordpress.org`: the official checksums of WordPress core, so the scan can tell which core files were changed. Sent: your WordPress version. When: during each scan (daily, and when you run one).
* `core.svn.wordpress.org` and `downloads.wordpress.org`: the original copy of a core file or of a WordPress.org plugin, only when you click Repair on a file. Sent: the WordPress or plugin version and the file requested.
* [Privacy policy](https://wordpress.org/about/privacy/)

= Rules and country database updates (jsDelivr and GitHub) =

The firewall rules and the IP-to-country database are updated from Digital Pixel's public rules repository on GitHub, served through jsDelivr. They are data files (JSON rules and a MaxMind DB format database), signed with Ed25519 and checked before use; nothing downloaded is ever executed.

* Sent: a plain download request (your server's IP address and a "DPXL Shield" user agent). When: once a day, and when you click "Check now". Both updates can be turned off under All Options.
* jsDelivr: [Terms](https://www.jsdelivr.com/terms) and [Privacy policy](https://www.jsdelivr.com/terms/privacy-policy-jsdelivr-net)
* GitHub: [Terms of service](https://docs.github.com/site-policy/github-terms/github-terms-of-service) and [Privacy statement](https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement)

The country database is DB-IP's "IP to Country Lite", licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/): IP geolocation by [DB-IP](https://db-ip.com).

= Have I Been Pwned (Pwned Passwords) =

Checks whether a password appears in known data breaches. Sent: only the first 5 characters of the password's SHA-1 hash (k-anonymity); the password itself never leaves your server. When: on login and when a password is changed or reset, if the option is on.

* [Privacy policy](https://haveibeenpwned.com/Privacy)

= IP lookups (ipinfo.io and regional internet registries) =

The WHOIS tool looks up an IP address you type. Sent: that IP address, to the WHOIS server of the regional internet registry that holds it (ARIN, RIPE NCC, APNIC, LACNIC or AFRINIC, on port 43) and, when WHOIS gives no answer, to ipinfo.io. When: only when you run a lookup.

* ipinfo.io: [Terms of service](https://ipinfo.io/terms-of-service) and [Privacy policy](https://ipinfo.io/privacy-policy)
* ARIN: [Terms of use](https://www.arin.net/resources/registry/whois/tou/)

= Optional services that need your own key =

None of these run until you enter your own key or token.

* Google Safe Browsing: checks whether your domain is flagged. Sent: your site's address and your API key. When: during scans. [Terms](https://developers.google.com/safe-browsing/terms) and [Privacy policy](https://policies.google.com/privacy)
* Spamhaus DQS: checks whether your domain or server IP is on a blocklist, through DNS queries. Sent: your domain, your server's IP address and your key. When: during scans. [Privacy notice](https://www.spamhaus.com/privacy-notice/)
* WPScan: known vulnerabilities in your plugins and themes. Sent: the slugs and versions of installed plugins and themes, and your token. When: during scans. [Privacy policy](https://automattic.com/privacy/)

= Webhooks you configure =

If you add a webhook (Slack, Discord, PagerDuty or any URL), security alerts are sent to that address: the event, its severity, the IP involved and your site's address. Nothing is sent until you add one.

== Installation ==

1. In your dashboard, go to **Plugins → Add New**, search for "DPXL Shield", install and activate. Or upload the release ZIP under **Plugins → Add New → Upload Plugin**.
2. Open **DPXL Shield → Dashboard** to see your site's status.
3. Turn on two-factor authentication for your account under **DPXL Shield → Login Security**.
4. Optional: enable **Extended Protection** under **DPXL Shield → Firewall**. You will be asked to download a backup of `.htaccess` first.

= Behind a proxy or CDN =

DPXL Shield only trusts forwarded IP headers (`X-Forwarded-For`, `CF-Connecting-IP`) when the connection comes from a trusted proxy, so visitors cannot pretend to be someone else. Cloudflare and proxies on the local network are recognised automatically. For any other CDN or proxy, list its addresses in `wp-config.php`:

`define( 'DPXL_SHIELD_TRUSTED_PROXIES', '192.0.2.0/24, 198.51.100.10' );`

The Diagnostics tab warns when it sees a proxy header that is being ignored.

== Frequently Asked Questions ==

= Will it slow my site down? =

The firewall is light and uses in-memory caching when the server has APCu. Traffic logging is written after the page has been sent to the visitor.

= Can I use it with another security plugin? =

Yes, but two firewalls doing the same job only add cost. If you keep both, turn one firewall off.

= I locked myself out. What now? =

Automatic lockouts expire on their own. For immediate access, rename `wp-content/plugins/dpxl-shield` over FTP. The plugin is deactivated and the Extended Protection loader becomes a harmless no-op.

= Is two-factor authentication enforced for every user? =

Not yet. Each user turns it on for their own account. Role-based enforcement is planned.

= Does 2FA work with WooCommerce or custom login pages? =

It hooks into the standard WordPress authentication flow (`wp_authenticate_user`). After the password is accepted, the user is sent to the code screen on `wp-login.php` and then back to where they were going. Login forms that bypass the standard flow need extra integration.

= Is it really free? =

Yes. No paid version, no locked features, no ads in the dashboard.

= Where do I report a security issue? =

Privately, through GitHub: [Report a vulnerability](https://github.com/Digital-Pixel-Web/dpxl-shield/security/advisories/new). Please do not open a public issue.

== Screenshots ==

1. Dashboard with protection status, attack chart and recent logins.
2. Firewall with active rules, blocked IPs and country blocking.
3. Scan with progress by stage and findings by severity.
4. Login Security with two-factor setup.
5. Live Traffic with color-coded requests and request details.
6. Audit log with a verified hash chain.

== Changelog ==

= 1.12.1 =
* Changed: files the plugin writes at runtime moved from the plugin folder to `wp-content/uploads/dpxl-shield/`. Plugin updates no longer wipe the rule updates, the country database or the firewall config.
* Changed: file repair downloads original core files from WordPress.org (`core.svn.wordpress.org`) instead of a GitHub mirror.
* Changed: the country database comes from DB-IP's IP to Country Lite (CC BY 4.0), which may be redistributed; the credit line follows the database installed.
* Changed: the signed rules feed moved to `Digital-Pixel-Web/dpxl-shield-rules` and is signed with a new Ed25519 key.
* Changed: the self-protection copies use prefixed option and file names, and are compared as JSON.
* Changed: errors go to the PHP error log only with `WP_DEBUG` on.
* Fixed: with Extended Protection on, blocks made before WordPress loads ban the IP and appear in Live Traffic.
* Fixed: without APCu, the anomaly detector counts distinct URLs, so repeated requests to one endpoint are no longer taken for a scanner. Live Traffic ignores WP-CLI.
* Changed: XML-RPC limit raised from 3 to 10 requests per minute.
* Code: fixes for what Plugin Check reports (output escaping, input sanitization, prepared queries, WordPress file functions).

= 1.12.0 =
* Security: forwarded IP headers are only trusted from known proxies (Cloudflare, local network, or `DPXL_SHIELD_TRUSTED_PROXIES`). Before, a visitor could choose their own IP to avoid lockouts or get someone else's IP blocked.
* Security: the firewall can no longer be skipped by adding an admin path to the query string, through the anonymous `admin-ajax.php` / `admin-post.php` endpoints, or with a forged login cookie. Logged-in sessions are validated.
* Fixed: Extended Protection now actually runs the firewall rules before WordPress loads, and the in-WordPress checks keep running with it.
* Fixed: manual "permanent" IP blocks expired immediately. Automatic blocks no longer shorten a permanent one. IPv6 ranges are supported.
* Security: file repair no longer leaves an executable copy of the replaced file in `wp-content`, and checks downloaded core files against the official checksum.
* Fixed: users with two-factor authentication enabled could not log in. The login form never reached the code screen and showed "incorrect password" instead.
* Security: two-factor codes are limited to 5 attempts per login, and failures count toward the brute-force lockout.
* Security: settings reads and exports no longer include API keys.
* Fixed: the threat feed and GeoIP database could not be saved on a fresh install.
* Fixed: the plugin did not load on PHP 7.4, the minimum it declares (a PHP 8 return type in the firewall rules). The compatibility check now catches it.
* Changed: XML-RPC is blocked only for `system.multicall` brute-force requests, so Jetpack, the mobile apps and pingbacks work again. Login rate limiting counts login attempts, not page loads.
* Security: a two-factor code can no longer be reused for a second login. The firewall's data folder is no longer web-readable.
* Fixed: entering a few wrong two-factor codes no longer trips the login rate limit and bans the user. Blocked XML-RPC and REST requests now return HTTP 403, and blocked requests no longer log a translation notice.
* Fixed: requests blocked by the firewall now appear in Live Traffic and the dashboard counters.
* Fixed: the Login Security screen showed first-time two-factor setup to users who already had it on, hiding the disable and regenerate options.
* Fixed: without APCu, login, XML-RPC and REST rate limits now also apply when Extended Protection is on.
* Fixed: uninstalling now removes two-factor secrets, backup codes, known login IPs and the plugin's transients.
* Security: `system.multicall` is recognised even when hidden with XML character references or CDATA.
* New: Diagnostics shows how visitor IPs are detected.
* Full history in [CHANGELOG.md](https://github.com/Digital-Pixel-Web/dpxl-shield/blob/main/CHANGELOG.md).

= 1.11.0 =
* New: email delivery monitoring, with an alert through the dashboard, audit log and webhooks when the site stops sending email.

= 1.10.1 =
* Fixed: deactivating or deleting any plugin was reported as DPXL Shield being removed.

= 1.10.0 =
* New: email on every administrator login.

== Upgrade Notice ==

= 1.12.1 =
Runtime files move to wp-content/uploads/dpxl-shield, so updates no longer reset the rule updates and the country database.

= 1.12.0 =
Important security update: fixes firewall bypasses and IP spoofing, and makes Extended Protection run its rules. Update as soon as possible.
