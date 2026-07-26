<?php
declare(strict_types=1);

namespace DPXL\Shield\LoginSecurity;

use DPXL\Shield\Core\Options;
use DPXL\Shield\Firewall\IpBlocklist;

/**
 * Brute-force protection with progressive lockouts.
 *
 * Failure thresholds (configurable):
 *   ≥ 5  failures → locked out for 5 minutes
 *   ≥ 10 failures → locked out for 1 hour
 *   ≥ 20 failures → locked out for 24 hours
 *
 * Counter resets on successful login.
 * Counters are stored in transients keyed by IP (fast, no custom table needed).
 */
class BruteForceProtection {

    private const TRANSIENT_FAILURES = 'dpxl_bf_fail_';    // + md5(ip)
    private const TRANSIENT_LOCKOUT  = 'dpxl_bf_lock_';    // + md5(ip)
    private const COUNTER_TTL        = 3600;               // track failures for 1 hour

    private LoginAudit $audit;

    public function __construct(LoginAudit $audit) {
        $this->audit = $audit;
    }

    public function registerHooks(): void {
        // Check lockout status before WordPress processes the login.
        add_filter('authenticate', [$this, 'checkLockoutBeforeAuth'], 30, 3);

        // Increment failure counter after a failed login.
        add_action('wp_login_failed', [$this, 'onLoginFailed'], 10, 2);

        // Reset counter on successful login.
        add_action('wp_login', [$this, 'onLoginSuccess'], 10, 2);
    }

    // ── Hooks ──────────────────────────────────────────────────────────────

    /**
     * Runs on `authenticate` filter (priority 30 — after WP validates credentials).
     * Returns WP_Error to abort login if IP is locked out.
     */
    public function checkLockoutBeforeAuth(mixed $user, string $username, string $password): mixed {
        if (empty($username)) {
            return $user;
        }

        $ip = $this->currentIp();

        if ($this->isLockedOut($ip)) {
            $remaining = $this->lockoutSecondsRemaining($ip);
            $minutes   = (int) ceil($remaining / 60);

            $this->audit->recordBlocked($username, $ip);

            return new \WP_Error(
                'dpxl_locked_out',
                sprintf(
                    /* translators: %d = minutes remaining */
                    __('Too many failed login attempts. Please try again in %d minute(s).', 'dpxl-shield'),
                    $minutes
                )
            );
        }

        // Block immediately if username is "admin" and option is explicitly enabled.
        // Default is false to avoid locking out sites that legitimately use "admin".
        if (Options::get('brute_force_block_admin_username', false) && strtolower($username) === 'admin') {
            $this->incrementFailures($ip);
            $this->audit->recordBlocked($username, $ip);

            return new \WP_Error(
                'dpxl_invalid_username',
                __('That username is not allowed.', 'dpxl-shield')
            );
        }

        return $user;
    }

    public function onLoginFailed(string $username, \WP_Error $error): void {
        $ip = $this->currentIp();

        $failures = $this->incrementFailures($ip);
        $this->applyLockoutIfNeeded($ip, $failures, $username);
    }

    public function onLoginSuccess(string $userLogin, \WP_User $user): void {
        $ip = $this->currentIp();
        $this->clearCounters($ip);
    }

    // ── Lockout Logic ──────────────────────────────────────────────────────

    public function isLockedOut(string $ip): bool {
        return (bool) get_transient(self::TRANSIENT_LOCKOUT . md5($ip));
    }

    private function lockoutSecondsRemaining(string $ip): int {
        // Transient TTL is not directly queryable; we store the expiry timestamp.
        $expiry = get_transient(self::TRANSIENT_LOCKOUT . md5($ip) . '_expiry');
        return max(0, (int) $expiry - time());
    }

    private function incrementFailures(string $ip): int {
        $key     = self::TRANSIENT_FAILURES . md5($ip);
        $current = (int) get_transient($key);
        $next    = $current + 1;

        set_transient($key, $next, self::COUNTER_TTL);

        return $next;
    }

    /**
     * Progressive lockout duration (seconds) for a failure count, given the
     * base threshold. 0 means "not locked out yet". Pure function so the
     * security-critical escalation curve is unit-tested.
     *
     *   ≥ base×4 → 24h · ≥ base×2 → 1h · ≥ base → 5min · below → 0
     */
    public static function lockoutDuration(int $failures, int $baseThreshold): int {
        return match (true) {
            $failures >= $baseThreshold * 4 => DAY_IN_SECONDS,
            $failures >= $baseThreshold * 2 => HOUR_IN_SECONDS,
            $failures >= $baseThreshold     => 5 * MINUTE_IN_SECONDS,
            default                         => 0,
        };
    }

    private function applyLockoutIfNeeded(string $ip, int $failures, string $username): void {
        $lockoutSeconds = self::lockoutDuration($failures, (int) Options::get('brute_force_threshold', 5));

        if ($lockoutSeconds === 0) {
            return;
        }

        $lockKey = self::TRANSIENT_LOCKOUT . md5($ip);
        set_transient($lockKey, true, $lockoutSeconds);
        set_transient($lockKey . '_expiry', time() + $lockoutSeconds, $lockoutSeconds + 60);

        // Also add to the IP blocklist for WAF-level enforcement.
        IpBlocklist::blockIp($ip, "Brute force: {$failures} failed login attempts", 'auto_brute', $lockoutSeconds);

        do_action('dpxl_shield_alert', [
            'level'       => 'high',
            'event_type'  => 'brute_force_lockout',
            'description' => "IP {$ip} locked out after {$failures} failed login attempts for '{$username}'.",
            'context'     => [
                'ip'              => $ip,
                'failures'        => $failures,
                'username'        => $username,
                'lockout_seconds' => $lockoutSeconds,
            ],
        ]);
    }

    private function clearCounters(string $ip): void {
        delete_transient(self::TRANSIENT_FAILURES . md5($ip));
        delete_transient(self::TRANSIENT_LOCKOUT . md5($ip));
        delete_transient(self::TRANSIENT_LOCKOUT . md5($ip) . '_expiry');
    }

    // ── Manual Management ──────────────────────────────────────────────────

    public static function unlockIp(string $ip): void {
        delete_transient(self::TRANSIENT_FAILURES . md5($ip));
        delete_transient(self::TRANSIENT_LOCKOUT . md5($ip));
        delete_transient(self::TRANSIENT_LOCKOUT . md5($ip) . '_expiry');
        IpBlocklist::unblockIp($ip);
    }

    public static function getFailureCount(string $ip): int {
        return (int) get_transient(self::TRANSIENT_FAILURES . md5($ip));
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private function currentIp(): string {
        $headers = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'];

        foreach ($headers as $h) {
            $value = $_SERVER[$h] ?? '';
            $ip    = trim(explode(',', $value)[0]);

            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }

        return '0.0.0.0';
    }
}
