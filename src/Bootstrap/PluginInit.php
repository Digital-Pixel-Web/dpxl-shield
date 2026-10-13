<?php
declare(strict_types=1);

namespace DPXL\Shield\Bootstrap;

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

/**
 * Normal plugin boot — runs on plugins_loaded after WordPress is available.
 */
class PluginInit {

    public static function boot(): void {
        // Ensure DB tables exist — handles zip-based upgrades that skip the activation hook.
        Database::maybeCreateTables();
        Database::runDataFixes();

        $firewallEnabled = (bool) Options::get('firewall_enabled', true);

        // Run WAF in basic mode (inside WordPress) only when the firewall is enabled
        // and the extended auto_prepend_file loader did not run for this request.
        if ($firewallEnabled && !defined('DPXL_SHIELD_EXTENDED_ACTIVE')) {
            self::runBasicWaf();
        }

        // Always register admin and REST hooks, even if the firewall itself is disabled.
        // REST_REQUEST is not reliably defined during plugins_loaded, so the REST API
        // must be hooked unconditionally and let rest_api_init decide whether it runs.
        self::registerHooks();
    }

    private static function runBasicWaf(): void {
        $uri = $_SERVER['REQUEST_URI'] ?? '';

        // Bypass WAF for all wp-admin requests.
        // Page builders (Elementor, Gutenberg) POST HTML/CSS/JS that triggers XSS/SQLi
        // rules, causing false-positive blocks and auto-adding the admin's IP to the
        // blocklist. is_admin() is a cheap constant check (WP_ADMIN is defined early).
        if (is_admin()) {
            return;
        }

        // Bypass WAF for REST API and admin-ajax requests that carry a WordPress
        // auth cookie. We check the cookie directly rather than calling
        // is_user_logged_in() because at plugins_loaded priority -10 the user is not
        // yet fully initialized for REST requests (REST nonce auth runs at rest_api_init).
        // LOGGED_IN_COOKIE is defined by wp_cookie_constants() before plugins_loaded.
        $loggedInCookie = defined('LOGGED_IN_COOKIE') ? LOGGED_IN_COOKIE : 'wordpress_logged_in';
        $isAuthRequest  = str_contains($uri, '/wp-json/') || str_contains($uri, 'admin-ajax.php');

        if ($isAuthRequest && !empty($_COOKIE[$loggedInCookie] ?? '')) {
            return;
        }

        $configFile     = DPXL_SHIELD_PATH . 'data/early-config.php';
        $blockedIpsFile = DPXL_SHIELD_PATH . 'data/blocked-ips.php';

        $request = new Request();
        $engine  = new FirewallEngine($configFile, $blockedIpsFile);
        $result  = $engine->evaluate($request);

        TrafficLogger::setWafResult($result);

        if ($result->decision === 'block') {
            wp_die(
                esc_html__('Your request has been blocked by DPXL Shield.', 'dpxl-shield'),
                esc_html__('403 Forbidden', 'dpxl-shield'),
                ['response' => 403]
            );
        }
    }

    private static function registerHooks(): void {
        // Alert manager — must be first so dpxl_shield_alert is wired before other modules fire.
        (new AlertManager())->registerHooks();

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
