<?php
declare(strict_types=1);

namespace DPXL\Shield\LoginSecurity;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

use DPXL\Shield\Core\Options;

/**
 * Records login events to dpxl_shield_login_events and alerts on
 * administrator sign-ins — every one of them, or only those from a network
 * not seen before, depending on `alert_admin_login_enabled`.
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

        if (!user_can($user, 'manage_options')) {
            return;
        }

        $context = [
            'username' => $userLogin,
            'ip'       => $ip,
            'user_id'  => $user->ID,
        ];

        // A first-seen network is the stronger signal, and its alert already
        // says so — sending the routine notice as well would mean two emails
        // for one login. One event per sign-in, the more specific one winning.
        if ($this->isNewIp($user->ID, $ip)) {
            $this->markIpKnown($user->ID, $ip);

            do_action('dpxl_shield_alert', [
                // Notice, not critical: an admin signing in from a new network
                // is routine (mobile, travel, dynamic IP). Reserve `critical`
                // for confirmed compromise so it keeps its weight.
                'level'       => 'medium',
                'event_type'  => 'new_admin_ip_login',
                'description' => "Admin '{$userLogin}' logged in from a new IP: {$ip}",
                'context'     => $context,
            ]);

            return;
        }

        // Every other administrator sign-in, when the setting is on.
        //
        // This is the one alert whose whole point is to be routine: it is only
        // useful because it arrives every time, so the one you did not perform
        // stands out against the ones you did. That is also why it is a notice
        // and carries a line saying it can be switched off — an alert the
        // reader cannot silence is one they learn to filter instead.
        if (!Options::get('alert_admin_login_enabled', true)) {
            return;
        }

        do_action('dpxl_shield_alert', [
            'level'       => 'medium',
            'event_type'  => 'admin_login',
            'description' => "Admin '{$userLogin}' signed in from {$ip}",
            'context'     => $context,
        ]);
    }

    /**
     * `wp_login_failed`. $error is optional and untyped — see the matching note
     * in BruteForceProtection::onLoginFailed(): third-party login forms fire this
     * action with the username alone, and a required typed parameter would turn
     * that into a fatal instead of a missed log entry.
     *
     * @param mixed $error WP_Error when the caller supplies one.
     */
    public function onLoginFailure(string $username, $error = null): void {
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
        return !in_array(self::networkId($ip), $this->knownNetworks($userId), true);
    }

    private function markIpKnown(int $userId, string $ip): void {
        $known   = $this->knownNetworks($userId);
        $known[] = self::networkId($ip);

        // Keep only the last 50 known networks.
        if (count($known) > 50) {
            $known = array_slice($known, -50);
        }

        update_user_meta($userId, self::KNOWN_IPS_META, $known);
    }

    /**
     * Known networks for a user, normalised.
     *
     * Entries stored before the comparison moved to network level are full
     * addresses; normalising on read folds them into their prefix, so the
     * change does not re-alert for networks the account already used.
     *
     * @return list<string>
     */
    private function knownNetworks(int $userId): array {
        $stored = get_user_meta($userId, self::KNOWN_IPS_META, true);

        if (!is_array($stored)) {
            return [];
        }

        $networks = array_map([self::class, 'networkId'], array_filter($stored, 'is_string'));

        return array_values(array_unique($networks));
    }

    /**
     * The stable network identity of an address, used for "have we seen this
     * place before?".
     *
     * Residential IPv6 (SLAAC with RFC 4941 privacy extensions) rotates the
     * 64-bit interface identifier every few hours, so one unchanged router
     * emits an endless stream of distinct addresses. Comparing whole IPv6
     * addresses therefore reports "a new IP" on nearly every login from home —
     * which is noise, and noise is what makes a real alert get ignored. The /64
     * prefix is the part the ISP assigns and the part that actually means
     * "somewhere else".
     *
     * IPv4 is compared whole: it does not rotate per session this way, and
     * widening it to /24 would merge unrelated customers of the same ISP and
     * blunt a signal that currently works.
     */
    public static function networkId(string $ip): string {
        $packed = @inet_pton($ip);

        // Not IPv6 (or unparseable) — compare as-is.
        if ($packed === false || strlen($packed) !== 16) {
            return $ip;
        }

        // IPv4-mapped (::ffff:192.0.2.1) is IPv4 wearing a v6 hat. Truncating it
        // to /64 would collapse every such address into a single bucket.
        if (strncmp($packed, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff", 12) === 0) {
            return $ip;
        }

        $prefix = inet_ntop(substr($packed, 0, 8) . str_repeat("\x00", 8));

        return $prefix === false ? $ip : $prefix . '/64';
    }

    private function currentIp(): string {
        // Spoof-resistant resolution lives in one place; see ClientIp.
        return \DPXL\Shield\Core\ClientIp::current();
    }
}
