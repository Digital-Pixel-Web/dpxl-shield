<?php
declare(strict_types=1);

namespace DPXL\Shield\Api;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

use DPXL\Shield\Audit\AuditLog;

/**
 * Bearer-token authentication for the read-only integration API.
 *
 * This is the plugin's only route that grants access to site data without a
 * WordPress session, so it is deliberately narrow: read-only endpoints, one
 * credential type, no cookie fallback, and a per-token rate limit.
 */
final class ApiAuth {

    /**
     * Requests per token per minute.
     *
     * Deliberately below the WAF's own REST ceiling (RateLimiter: 60/min per IP,
     * enforced before WordPress even loads). If this were the higher of the two,
     * a busy client would be cut off by the firewall before reaching this code
     * and would see an opaque block instead of a 429 explaining the limit — and
     * the firewall counts admin-panel REST calls from the same IP too. Keeping
     * headroom means the limit that bites is the one that can explain itself.
     *
     * 30/min is ample: polling every 5 seconds with limit=200 is 12 requests.
     */
    private const RATE_LIMIT = 30;

    private const RATE_WINDOW = 60;

    /** Repeated bad credentials from one IP get locked out for this long. */
    private const FAIL_LIMIT  = 20;
    private const FAIL_WINDOW = 300;

    /** @var array<string,mixed>|null Token row for the current request. */
    private static $current = null;

    private function __construct() {}

    /**
     * permission_callback for every public API route.
     *
     * @return true|\WP_Error
     */
    public static function authorize(\WP_REST_Request $request) {
        $ip = self::clientIp();

        if (self::isLockedOut($ip)) {
            return new \WP_Error(
                'dpxl_api_locked',
                __('Too many failed authentication attempts. Try again later.', 'dpxl-shield'),
                ['status' => 429]
            );
        }

        $presented = self::bearerToken($request);

        if ($presented === null) {
            return new \WP_Error(
                'dpxl_api_no_credentials',
                __('Missing bearer token.', 'dpxl-shield'),
                ['status' => 401]
            );
        }

        $row = TokenStore::findByPlaintext($presented);

        if ($row === null) {
            self::recordFailure($ip);

            // Logged as a security event: repeated failures here are someone
            // probing for a valid credential, which the site owner should see.
            AuditLog::log(
                'fw.rule_triggered',
                'medium',
                'Rejected API request with an invalid token.',
                ['ip' => $ip]
            );

            return new \WP_Error(
                'dpxl_api_invalid_token',
                __('Invalid token.', 'dpxl-shield'),
                ['status' => 401]
            );
        }

        if (self::isRateLimited((int) $row['id'])) {
            return new \WP_Error(
                'dpxl_api_rate_limited',
                __('Rate limit exceeded.', 'dpxl-shield'),
                ['status' => 429]
            );
        }

        TokenStore::touch((int) $row['id'], (string) ($row['last_used_at'] ?? ''), $ip);

        self::$current = $row;

        return true;
    }

    /** @return array<string,mixed>|null */
    public static function currentToken(): ?array {
        return self::$current;
    }

    // ── Credential extraction ────────────────────────────────────────────────

    /**
     * Pulls the bearer token out of the request.
     *
     * The Authorization header is the documented way in, but Apache running PHP
     * as CGI/FastCGI strips it before PHP ever sees it — so the two rewritten
     * variants are checked as well. Without those fallbacks the API simply does
     * not work on a large slice of shared hosting, which is exactly the hosting
     * this plugin targets.
     */
    private static function bearerToken(\WP_REST_Request $request): ?string {
        return self::extractBearer((string) $request->get_header('authorization'), $_SERVER);
    }

    /**
     * Pure header parsing, separated so it can be tested without a request.
     *
     * @param array<string,mixed> $server
     */
    public static function extractBearer(string $header, array $server): ?string {
        if ($header === '') {
            foreach (['HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION'] as $key) {
                if (!empty($server[$key])) {
                    $header = (string) $server[$key];
                    break;
                }
            }
        }

        if ($header === '' || stripos($header, 'bearer ') !== 0) {
            return null;
        }

        $token = trim(substr($header, 7));

        return $token !== '' ? $token : null;
    }

    private static function clientIp(): string {
        // Spoof-resistant resolution lives in one place; see ClientIp.
        return \DPXL\Shield\Core\ClientIp::current();
    }

    // ── Throttling ───────────────────────────────────────────────────────────

    private static function isRateLimited(int $tokenId): bool {
        $key   = 'dpxl_api_rl_' . $tokenId;
        $count = (int) get_transient($key);

        if ($count >= self::RATE_LIMIT) {
            return true;
        }

        set_transient($key, $count + 1, self::RATE_WINDOW);

        return false;
    }

    private static function recordFailure(string $ip): void {
        $key   = 'dpxl_api_fail_' . md5($ip);
        $count = (int) get_transient($key);

        set_transient($key, $count + 1, self::FAIL_WINDOW);
    }

    private static function isLockedOut(string $ip): bool {
        return (int) get_transient('dpxl_api_fail_' . md5($ip)) >= self::FAIL_LIMIT;
    }
}
