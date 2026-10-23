=== DPXL Shield ===
Contributors: digitalpixelbr
Tags: security, firewall, malware scanner, two-factor authentication, brute force
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.12.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Free WordPress security: firewall, malware scanner, login protection, two-factor authentication and alerts. No paid tier, no telemetry.

== Description ==

Most hacked WordPress sites are not taken down by a sophisticated attack. They fall to a weak password, an outdated plugin, or a modified file nobody noticed. DPXL Shield closes those doors and tells you, in plain language, when something needs your attention.

It is built and maintained by [Digital Pixel](https://digitalpixel.com.br/), a WordPress agency, and given to the community for free. There is no premium version and nothing in the dashboard is locked.

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

= Privacy and external services =

Data stays in your site's database. The plugin sends no telemetry and nothing goes to Digital Pixel servers. It connects to these services only for the purposes listed:

* `api.wordpress.org` — official core checksums, during scans. [Privacy policy](https://wordpress.org/about/privacy/)
* `raw.githubusercontent.com` and `downloads.wordpress.org` — original files, only when you repair a file. [GitHub privacy](https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement)
* `api.pwnedpasswords.com` — leaked password check on login and password change; only the first 5 characters of the SHA-1 hash are sent. [Privacy policy](https://haveibeenpwned.com/Privacy)
* `cdn.jsdelivr.net` — signed firewall rule updates, daily; can be turned off. [Privacy policy](https://www.jsdelivr.com/terms/privacy-policy-jsdelivr-net)
* `github.com` — GeoLite2 country database, when a newer one is published; can be turned off.
* `ip-api.com` — WHOIS/GeoIP, only when you run a lookup. [Privacy policy](https://ip-api.com/docs/legal)
* `safebrowsing.googleapis.com` — domain reputation, only with your own API key. [Terms](https://developers.google.com/safe-browsing/terms)
* Spamhaus DQS — domain reputation, only with your own key. [Privacy policy](https://www.spamhaus.com/privacy-notice/)
* `wpscan.com` — known vulnerabilities, only with your own token. [Privacy policy](https://automattic.com/privacy/)

These are plain downloads and lookups: no site data, identifiers or telemetry are sent with them beyond what each lookup needs.

This product includes GeoLite2 data created by MaxMind, available from [https://www.maxmind.com](https://www.maxmind.com).

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

= 1.12.0 =
Important security update: fixes firewall bypasses and IP spoofing, and makes Extended Protection run its rules. Update as soon as possible.
