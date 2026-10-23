<?php
declare(strict_types=1);

namespace DPXL\Shield\Bootstrap;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

use DPXL\Shield\Core\Options;
use DPXL\Shield\Core\Cron;
use DPXL\Shield\Firewall\FirewallEngine;
use DPXL\Shield\Firewall\Request;
use DPXL\Shield\Scanner\FileIntegrityMonitor;
use DPXL\Shield\LoginSecurity\LoginSecurity;
use DPXL\Shield\LoginSecurity\PasswordAudit;
use DPXL\Shield\Honeypot\HoneypotManager;
use DPXL\Shield\Hardening\WpHardening;
use DPXL\Shield\Traffic\AnomalyDetector;
use DPXL\Shield\Traffic\TrafficLogger;
use DPXL\Shield\SelfProtection\DeactivationGuard;
use DPXL\Shield\Alerts\AlertManager;
use DPXL\Shield\Admin\AdminMenu;
use DPXL\Shield\Admin\RestApi;
use DPXL\Shield\Core\Database;
use DPXL\Shield\Core\EarlyConfig;
use DPXL\Shield\Firewall\WafBypass;

/**
 * Normal plugin boot — runs on plugins_loaded after WordPress is available.
 */
class PluginInit {

    public static function boot(): void {
        // Ensure DB tables exist — handles zip-based upgrades that skip the activation hook.
        Database::maybeCreateTables();
        Database::runDataFixes();

        // The files Extended Protection reads before WordPress loads. Recreated
        // here if a plugin update wiped data/ (two stat calls otherwise).
        \DPXL\Shield\Core\EarlyConfig::ensure();

        $firewallEnabled = (bool) Options::get('firewall_enabled', true);

        // The in-WordPress layer always runs when the firewall is on. When the
        // pre-WordPress loader already evaluated the rules for this request, only
        // the database-backed checks are left for this layer; when the loader
        // deferred the request (admin screens, login, API calls with a login
        // cookie) or did not run, everything is evaluated here.
        if ($firewallEnabled) {
            self::runBasicWaf();
        }

        // Always register admin and REST hooks, even if the firewall itself is disabled.
        // REST_REQUEST is not reliably defined during plugins_loaded, so the REST API
        // must be hooked unconditionally and let rest_api_init decide whether it runs.
        self::registerHooks();
    }

    private static function runBasicWaf(): void {
        $uri = $_SERVER['REQUEST_URI'] ?? '';

        // Logged-in users on admin screens and API calls skip the rules: page
        // builders (Elementor, Gutenberg) POST raw HTML/CSS/JS that trips the
        // XSS/SQLi rules and would get the admin's own IP banned.
        //
        // The session is *validated*. This used to trust is_admin() — true for
        // the anonymous admin-ajax.php / admin-post.php endpoints too — and the
        // mere presence of a wordpress_logged_in_* cookie, which anyone can send.
        // Both turned the firewall off for exactly the requests attackers use.
        if (WafBypass::shouldBypassForUser($uri, self::hasValidSession())) {
            return;
        }

        // Hooked before evaluating: a blocked request ends in wp_die(), and the
        // shutdown log entry is the only record of the block in Live Traffic
        // and the dashboard counters. registerHooks() is idempotent.
        (new TrafficLogger())->registerHooks();

        $request = new Request();
        $engine  = new FirewallEngine(EarlyConfig::configPath(), EarlyConfig::blockedIpsPath());
        $result  = defined('DPXL_SHIELD_EARLY_EVALUATED')
            ? $engine->evaluateDatabaseChecks($request)
            : $engine->evaluate($request);

        TrafficLogger::setWafResult($result);

        if ($result->decision === 'block') {
            self::denyRequest();
        }
    }

    private static function denyRequest(): void {
        // XML-RPC and REST requests get a bare 403. wp_die() hands XML-RPC to a
        // handler that needs the XML-RPC server, which does not exist yet at
        // plugins_loaded, so the block went out as an empty HTTP 200.
        if ((defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) || (defined('REST_REQUEST') && REST_REQUEST)
            || str_contains(WafBypass::path((string) ($_SERVER['REQUEST_URI'] ?? '')), '/wp-json/')) {
            if (!headers_sent()) {
                status_header(403);
                nocache_headers();
                header('Content-Type: text/plain; charset=utf-8');
            }

            echo 'Forbidden';
            exit;
        }

        // Translations load at init; translating earlier logs a notice on
        // every blocked request (WordPress 6.7+).
        $translate = did_action('init') > 0;

        wp_die(
            esc_html($translate ? __('Your request has been blocked by DPXL Shield.', 'dpxl-shield') : 'Your request has been blocked by DPXL Shield.'),
            esc_html($translate ? __('403 Forbidden', 'dpxl-shield') : '403 Forbidden'),
            ['response' => 403]
        );
    }

    /**
     * Whether the request carries a real, unexpired login session of someone
     * who edits content. wp_validate_auth_cookie() is pluggable and loaded
     * before plugins_loaded.
     *
     * Subscribers and shop customers are not exempted: "authenticated
     * (subscriber+)" is the most common class of plugin vulnerability, and an
     * open registration form would otherwise hand anyone a WAF-free session.
     */
    private static function hasValidSession(): bool {
        if (!WafBypass::hasLoginCookie($_COOKIE) || !function_exists('wp_validate_auth_cookie')) {
            return false;
        }

        $userId = (int) wp_validate_auth_cookie('', 'logged_in');

        return $userId > 0 && user_can($userId, 'edit_posts');
    }

    private static function registerHooks(): void {
        // Alert manager — must be first so dpxl_shield_alert is wired before other modules fire.
        (new AlertManager())->registerHooks();

        // Watches whether mail can leave at all — the channel every other
        // alert depends on, and the one failure that silences itself.
        (new \DPXL\Shield\Alerts\SmtpMonitor())->registerHooks();

        // Traffic logger — starts timing at plugins_loaded, writes on shutdown.
        (new TrafficLogger())->registerHooks();

        // File integrity monitor — runs on init (priority 1) per request.
        (new FileIntegrityMonitor())->registerHooks();

        // Login security: brute force + 2FA + audit.
        (new LoginSecurity())->registerHooks();

        // Password audit: HIBP k-anonymity checks.
        (new PasswordAudit())->registerHooks();

        // Honeypots: hidden form fields + decoy endpoints.
        (new HoneypotManager())->registerHooks();

        // WordPress core hardening tweaks.
        (new WpHardening())->registerHooks();

        // Traffic anomaly detection (scanner / 404 flood / REST abuse).
        (new AnomalyDetector())->registerHooks();

        // Deactivation / deletion guard.
        (new DeactivationGuard())->registerHooks();

        // Cron schedules.
        Cron::register();

        // Keep the pre-WordPress config in step with the settings it mirrors.
        $mirrored = ['firewall_enabled', 'rate_limit_login', 'rate_limit_xmlrpc', 'rate_limit_rest', 'allowlisted_uris'];
        $refresh  = static function (string $option) use ($mirrored): void {
            if (in_array(substr($option, strlen('dpxl_shield_')), $mirrored, true) && str_starts_with($option, 'dpxl_shield_')) {
                EarlyConfig::writeConfig();
            }
        };
        add_action('added_option', $refresh);
        add_action('updated_option', $refresh);
        add_action('deleted_option', $refresh);

        // Admin UI.
        if (is_admin()) {
            (new AdminMenu())->registerHooks();
        }

        // REST API must be registered unconditionally here because REST_REQUEST is
        // defined later in the WordPress lifecycle, after plugins_loaded.
        (new RestApi())->registerHooks();

        // Read-only integration API, on its own namespace and authenticated by
        // bearer token rather than a WordPress session.
        (new \DPXL\Shield\Api\PublicApi())->registerHooks();

        do_action('dpxl_shield_loaded');
    }
}
