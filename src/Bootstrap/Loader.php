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

        // ── Admin bypass ───────────────────────────────────────────────────
        // wp-admin and wp-login.php must never be WAF-filtered in the pre-
        // WordPress context. Page builders (Elementor, Gutenberg) POST raw
        // HTML/CSS that triggers XSS/SQLi rules; WordPress itself handles
        // admin authentication. is_admin() is unavailable here, so we check
        // the URI directly.
        if (str_contains($uri, '/wp-admin/') || str_contains($uri, '/wp-login.php')) {
            return;
        }

        // ── Authenticated REST / admin-ajax bypass ─────────────────────────
        // REST API and admin-ajax requests from logged-in users must bypass
        // the WAF. We cannot validate WP auth cookies pre-WordPress, but we
        // trust their presence: WordPress sets wordpress_logged_in_<hash>
        // cookies only after a successful login.
        $isAuthEndpoint = str_contains($uri, '/wp-json/') || str_contains($uri, 'admin-ajax.php');

        if ($isAuthEndpoint) {
            foreach (array_keys($_COOKIE) as $cookieName) {
                if (str_starts_with((string) $cookieName, 'wordpress_logged_in_')) {
                    return; // Logged-in user — skip WAF entirely.
                }
            }
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

        if ($result->decision->value === 'block') {
            self::sendBlockResponse($result->ruleId, $result->reason);
        }
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

    private static function sendBlockResponse(string $ruleId, string $reason): never {
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
