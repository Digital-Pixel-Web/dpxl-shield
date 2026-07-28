<?php
declare(strict_types=1);

namespace DPXL\Shield\Bootstrap;

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

        // Admin, wp-login and authenticated REST/admin-ajax requests never get
        // WAF-filtered in the pre-WordPress context (see shouldBypassEarlyWaf).
        if (self::shouldBypassEarlyWaf($uri, $_COOKIE)) {
            return;
        }

        // ── WAF evaluation (unauthenticated public requests only) ──────────
        $configFile = self::locateConfig();

        if ($configFile === null || !self::isFirewallEnabled($configFile)) {
            return;
        }

        $blockedIpsFile = dirname($configFile) . '/data/blocked-ips.php';

        $request  = new Request();
        $engine   = new FirewallEngine($configFile, $blockedIpsFile);
        $result   = $engine->evaluate($request);

        if ($result->decision === 'block') {
            self::sendBlockResponse($result->ruleId, $result->reason);
        }
    }

    /**
     * Decides whether a request must skip the pre-WordPress WAF entirely.
     *
     * Pure function (no superglobals, no side effects) so the security-critical
     * bypass logic can be unit-tested directly.
     *
     * - `wp-admin/` and `wp-login.php`: WordPress handles admin auth, and page
     *   builders (Elementor, Gutenberg) POST raw HTML/CSS that trips XSS/SQLi
     *   rules. `is_admin()` is unavailable pre-WordPress, so the URI is checked.
     * - `wp-json/` and `admin-ajax.php` carrying a `wordpress_logged_in_*`
     *   cookie: a logged-in user. The cookie cannot be validated pre-WordPress,
     *   but WordPress only sets it after a successful login.
     *
     * @param array<string,mixed> $cookies  Typically $_COOKIE
     */
    public static function shouldBypassEarlyWaf(string $uri, array $cookies): bool {
        if (str_contains($uri, '/wp-admin/') || str_contains($uri, '/wp-login.php')) {
            return true;
        }

        $isAuthEndpoint = str_contains($uri, '/wp-json/') || str_contains($uri, 'admin-ajax.php');

        if ($isAuthEndpoint) {
            foreach (array_keys($cookies) as $cookieName) {
                if (str_starts_with((string) $cookieName, 'wordpress_logged_in_')) {
                    return true;
                }
            }
        }

        return false;
    }

    private static function locateConfig(): ?string {
        // Walk up from the vendor autoloader to find the plugin config.
        $candidates = [
            __DIR__ . '/../../data/early-config.php',
        ];

        foreach ($candidates as $path) {
            if (file_exists($path)) {
                return realpath($path) ?: null;
            }
        }

        return null;
    }

    private static function isFirewallEnabled(?string $configFile): bool {
        if ($configFile === null) {
            return false;
        }

        $config = @include $configFile;

        return is_array($config) && !empty($config['firewall_enabled']);
    }

    private static function sendBlockResponse(string $ruleId, string $reason): void {
        http_response_code(403);
        header('Content-Type: text/html; charset=utf-8');
        header('X-DPXL-Shield: blocked');

        // Minimal HTML — no WordPress, no assets.
        echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body>';
        echo '<h1>Access Denied</h1>';
        echo '<p>Your request has been blocked by DPXL Shield.</p>';
        echo '</body></html>';

        exit;
    }

    public static function getStartTime(): float {
        return self::$startTime;
    }
}
