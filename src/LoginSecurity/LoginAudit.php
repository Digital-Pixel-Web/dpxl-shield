<?php
declare(strict_types=1);

namespace DPXL\Shield\LoginSecurity;

use DPXL\Shield\Core\Options;

/**
 * Records login events to dpxl_shield_login_events and fires alerts
 * when an admin logs in from a previously unseen IP.
 */
class LoginAudit {

    private const KNOWN_IPS_META = 'dpxl_shield_known_ips';

    public function registerHooks(): void {
        add_action('wp_login', [$this, 'onLoginSuccess'], 10, 2);
        add_action('wp_login_failed', [$this, 'onLoginFailure'], 10, 2);
        add_action('wp_logout', [$this, 'onLogout']);
    }

    // ── Hook Handlers ──────────────────────────────────────────────────────

    public function onLoginSuccess(string $userLogin, \WP_User $user): void {
        $ip = $this->currentIp();

        $this->record($userLogin, $ip, 'success');

        // Alert on first-seen IP for admin accounts.
        if (user_can($user, 'manage_options') && $this->isNewIp($user->ID, $ip)) {
            $this->markIpKnown($user->ID, $ip);

            do_action('dpxl_shield_alert', [
                // Notice, not critical: an admin signing in from a new network
                // is routine (mobile, travel, dynamic IP). Reserve `critical`
                // for confirmed compromise so it keeps its weight.
                'level'       => 'medium',
                'event_type'  => 'new_admin_ip_login',
                'description' => "Admin '{$userLogin}' logged in from a new IP: {$ip}",
                'context'     => [
                    'username' => $userLogin,
                    'ip'       => $ip,
                    'user_id'  => $user->ID,
                ],
            ]);
        }
    }

    public function onLoginFailure(string $username, \WP_Error $error): void {
        $this->record($username, $this->currentIp(), 'failure');
    }

    public function onLogout(): void {
        $user = wp_get_current_user();

        if ($user->exists()) {
            $this->record($user->user_login, $this->currentIp(), 'success');
        }
    }

    // ── Public for BruteForceProtection ───────────────────────────────────

    public function recordBlocked(string $username, string $ip): void {
        $this->record($username, $ip, 'blocked');
    }

    public function record2faRequired(string $username, string $ip): void {
        $this->record($username, $ip, '2fa_required');
    }

    public function record2faFailed(string $username, string $ip): void {
        $this->record($username, $ip, '2fa_failed');
    }

    // ── Internal ───────────────────────────────────────────────────────────

    private function record(string $userLogin, string $ip, string $result): void {
        global $wpdb;

        $wpdb->insert(
            $wpdb->prefix . 'dpxl_shield_login_events',
            [
                'timestamp'  => current_time('mysql', true),
                'user_login' => $userLogin,
                'ip'         => $ip,
                'user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500),
                'result'     => $result,
            ],
            ['%s', '%s', '%s', '%s', '%s']
        );
    }

    private function isNewIp(int $userId, string $ip): bool {
        $knownIps = get_user_meta($userId, self::KNOWN_IPS_META, true);
        return !is_array($knownIps) || !in_array($ip, $knownIps, true);
    }

    private function markIpKnown(int $userId, string $ip): void {
        $knownIps   = get_user_meta($userId, self::KNOWN_IPS_META, true);
        $knownIps   = is_array($knownIps) ? $knownIps : [];
        $knownIps[] = $ip;

        // Keep only the last 50 known IPs.
        if (count($knownIps) > 50) {
            $knownIps = array_slice($knownIps, -50);
        }

        update_user_meta($userId, self::KNOWN_IPS_META, $knownIps);
    }

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
