<?php
declare(strict_types=1);

namespace DPXL\Shield\Bootstrap;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

use DPXL\Shield\Firewall\FirewallEngine;
use DPXL\Shield\Firewall\Request;

/**
 * Early WAF boot — runs via auto_prepend_file before WordPress loads.
 * Must not depend on any WordPress function.
 */
class Loader {

    private static float $startTime;

    public static function handleEarlyRequest(): void {
        self::$startTime = microtime(true);

        // Skip CLI and cron — not HTTP requests.
        if (PHP_SAPI === 'cli' || PHP_SAPI === 'cli-server') {
            return;
        }

        $uri = $_SERVER['REQUEST_URI'] ?? '';

        // Admin screens, the login screen and API calls carrying a login cookie
        // are not judged here: a forged cookie looks exactly like a real one
        // before WordPress loads. They are handed to the in-WordPress layer,
        // which validates the session (see WafBypass and PluginInit).
        if (self::shouldBypassEarlyWaf($uri, $_COOKIE)) {
            self::markDeferred();
            return;
        }

        // ── WAF evaluation (unauthenticated public requests only) ──────────
        $configFile = self::locateConfig();

        if (!self::isFirewallEnabled($configFile)) {
            return;
        }

        $dataDir        = $configFile !== null ? dirname($configFile) : self::defaultDataDir();
        $blockedIpsFile = $dataDir . '/blocked-ips.php';

        $request  = new Request();
        $engine   = new FirewallEngine((string) $configFile, $blockedIpsFile);
        $result   = $engine->evaluate($request);

        if ($result->decision === 'block') {
            // No database yet: the block goes to a file the next WordPress
            // request moves into Live Traffic. Without it a false positive here
            // was invisible.
            \DPXL\Shield\Firewall\EarlyBlockLog::record($dataDir, $request, $result);

            self::sendBlockResponse($result->ruleId, $result->reason);
        }

        // The rules, rate limiter and file blocklist ran here. The in-WordPress
        // layer still runs the checks that need the database (DB blocklist,
        // country blocking, custom patterns) without evaluating the rules twice.
        if (!defined('DPXL_SHIELD_EARLY_EVALUATED')) {
            define('DPXL_SHIELD_EARLY_EVALUATED', true);
        }
    }

    /**
     * Whether a request is left for the in-WordPress layer instead of being
     * judged before WordPress loads. Kept under its historical name; the
     * decision itself lives in WafBypass.
     *
     * Nothing is skipped outright any more: a deferred request is still
     * filtered once WordPress can tell a real login from a forged cookie.
     *
     * @param array<string,mixed> $cookies  Typically $_COOKIE
     */
    public static function shouldBypassEarlyWaf(string $uri, array $cookies): bool {
        return \DPXL\Shield\Firewall\WafBypass::shouldDeferEarly($uri, $cookies);
    }

    private static function markDeferred(): void {
        if (!defined('DPXL_SHIELD_EARLY_DEFERRED')) {
            define('DPXL_SHIELD_EARLY_DEFERRED', true);
        }
    }

    /** data/ next to the plugin, where EarlyConfig writes. */
    private static function defaultDataDir(): string {
        return dirname(__DIR__, 2) . '/data';
    }

    private static function locateConfig(): ?string {
        // Walk up from the vendor autoloader to find the plugin config.
        $candidates = [
            self::defaultDataDir() . '/early-config.php',
        ];

        foreach ($candidates as $path) {
            if (file_exists($path)) {
                return realpath($path) ?: null;
            }
        }

        return null;
    }

    /**
     * The firewall is on unless the config file says otherwise.
     *
     * This used to return false when the config file was missing — and nothing
     * ever wrote that file, so Extended Protection ran no rules at all, while
     * also switching the in-WordPress WAF off. Missing config now means the
     * defaults, which have the firewall on.
     */
    private static function isFirewallEnabled(?string $configFile): bool {
        if ($configFile === null) {
            return true;
        }

        $config = @include $configFile;

        if (!is_array($config) || !array_key_exists('firewall_enabled', $config)) {
            return true;
        }

        return !empty($config['firewall_enabled']);
    }

    private static function sendBlockResponse(string $ruleId, string $reason): void {
        $ref = self::ruleReference($ruleId);

        if (!headers_sent()) {
            http_response_code(403);
            header('Content-Type: text/html; charset=utf-8');
            header('Cache-Control: no-store');
            header('X-DPXL-Shield: blocked');

            if ($ref !== '') {
                header('X-DPXL-Shield-Rule: ' . $ref);
            }
        }

        // Minimal HTML — no WordPress, no assets. The rule ID (not the reason,
        // which would teach an attacker what to change) lets whoever reports
        // the block say which rule fired.
        echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body>';
        echo '<h1>Access Denied</h1>';
        echo '<p>Your request has been blocked by DPXL Shield.</p>';

        if ($ref !== '') {
            echo '<p><small>ref: ' . htmlspecialchars($ref, ENT_QUOTES, 'UTF-8') . '</small></p>';
        }

        echo '</body></html>';

        exit;
    }

    /** A rule ID safe for a header and the page: letters, digits, dot, dash, underscore. */
    public static function ruleReference(string $ruleId): string {
        return substr((string) preg_replace('/[^A-Za-z0-9._-]/', '', $ruleId), 0, 50);
    }

    public static function getStartTime(): float {
        return self::$startTime;
    }
}
