<?php
declare(strict_types=1);

namespace DPXL\Shield\LoginSecurity;

use DPXL\Shield\Core\Logger;

/**
 * Checks passwords against the HaveIBeenPwned Pwned Passwords API
 * using k-anonymity (only the first 5 chars of the SHA-1 hash are sent).
 *
 * Hooks:
 *   wp_login                    — checks on successful login; stores warning in user meta
 *   user_profile_update_errors  — blocks profile save when a pwned password is chosen
 *   validate_password_reset     — blocks password reset to a known-compromised password
 *
 * HIBP API: https://api.pwnedpasswords.com/range/{prefix}
 *   Returns  SUFFIX:count\r\n  lines for all hashes sharing that prefix.
 */
class PasswordAudit {

    private const META_KEY    = '_dpxl_shield_pwned_password';
    private const CACHE_TTL   = 3600; // 1 hour per prefix
    private const API_TIMEOUT = 5;    // seconds

    public function registerHooks(): void {
        add_action('wp_login',                   [$this, 'onLogin'], 10, 2);
        add_filter('user_profile_update_errors', [$this, 'onProfileUpdate'], 10, 3);
        add_action('validate_password_reset',    [$this, 'onPasswordReset'], 10, 2);
    }

    // ── Hook handlers ──────────────────────────────────────────────────────

    /** @param \WP_User $user */
    public function onLogin(string $username, $user): void {
        if (!$user instanceof \WP_User) {
            return;
        }

        // We can't check the plain-text password at this point — WordPress
        // doesn't pass it to wp_login.  Store a flag if a prior check (profile
        // update or reset) detected a compromise.  The actionable warning was
        // already recorded then; here we just refresh the meta-based reminder.
        $this->flagIfPreviouslyPwned($user->ID);
    }

    public function onProfileUpdate(\WP_Error $errors, bool $update, \WP_User $user): \WP_Error {
        $password = $_POST['pass1'] ?? '';

        if ($password === '' || $password !== ($_POST['pass2'] ?? '')) {
            return $errors;
        }

        $count = $this->pwnedCount($password);

        if ($count > 0) {
            Logger::error("PasswordAudit: user {$user->user_login} chose a password seen {$count}× in HIBP.");

            update_user_meta($user->ID, self::META_KEY, [
                'detected_at' => time(),
                'count'       => $count,
            ]);

            $errors->add(
                'dpxl_pwned_password',
                sprintf(
                    /* translators: %d: number of times password appeared in data breaches */
                    __('This password has appeared in %d known data breaches. Please choose a different password.', 'dpxl-shield'),
                    $count
                )
            );
        } else {
            delete_user_meta($user->ID, self::META_KEY);
        }

        return $errors;
    }

    /** @param \WP_User|\WP_Error $user */
    public function onPasswordReset(\WP_Error $errors, $user): void {
        if (!$user instanceof \WP_User) {
            return;
        }

        $password = $_POST['pass1'] ?? '';

        if ($password === '' || $password !== ($_POST['pass2'] ?? '')) {
            return;
        }

        $count = $this->pwnedCount($password);

        if ($count > 0) {
            Logger::error("PasswordAudit: password reset for user {$user->user_login} — HIBP hit ({$count}).");

            update_user_meta($user->ID, self::META_KEY, [
                'detected_at' => time(),
                'count'       => $count,
            ]);

            $errors->add(
                'dpxl_pwned_password',
                sprintf(
                    __('This password has appeared in %d known data breaches. Please choose a different password.', 'dpxl-shield'),
                    $count
                )
            );

            do_action('dpxl_shield_alert', [
                'level'       => 'medium',
                'event_type'  => 'pwned_password_reset',
                'description' => "User {$user->user_login} attempted to reset to a compromised password (HIBP count: {$count}).",
                'context'     => ['user_id' => $user->ID, 'hibp_count' => $count],
            ]);
        } else {
            delete_user_meta($user->ID, self::META_KEY);
        }
    }

    // ── HIBP lookup ────────────────────────────────────────────────────────

    /** Returns the number of times the password appears in HIBP (0 = safe). */
    public function pwnedCount(string $password): int {
        $sha1   = strtoupper(sha1($password));
        $prefix = substr($sha1, 0, 5);
        $suffix = substr($sha1, 5);

        $lines = $this->fetchRange($prefix);

        if ($lines === null) {
            // API unreachable — fail open (do not block the user).
            return 0;
        }

        foreach ($lines as $line) {
            [$lineSuffix, $count] = explode(':', trim($line), 2) + ['', '0'];

            if (hash_equals($suffix, strtoupper($lineSuffix))) {
                return (int) $count;
            }
        }

        return 0;
    }

    /**
     * Fetches the hash range from HIBP, with transient caching per prefix.
     *
     * @return string[]|null  Lines from the API, or null on network failure.
     */
    private function fetchRange(string $prefix): ?array {
        $cacheKey = 'dpxl_hibp_' . strtolower($prefix);
        $cached   = get_transient($cacheKey);

        if (is_string($cached)) {
            return explode("\n", $cached);
        }

        $response = wp_remote_get(
            'https://api.pwnedpasswords.com/range/' . $prefix,
            [
                'timeout'    => self::API_TIMEOUT,
                'user-agent' => 'DPXL-Shield/' . (defined('DPXL_SHIELD_VERSION') ? DPXL_SHIELD_VERSION : '1.0'),
                'headers'    => ['Add-Padding' => 'true'],
            ]
        );

        if (is_wp_error($response)) {
            Logger::error('PasswordAudit: HIBP API error — ' . $response->get_error_message());
            return null;
        }

        $code = wp_remote_retrieve_response_code($response);

        if ($code !== 200) {
            Logger::error("PasswordAudit: HIBP API returned HTTP {$code}.");
            return null;
        }

        $body = wp_remote_retrieve_body($response);
        set_transient($cacheKey, $body, self::CACHE_TTL);

        return explode("\n", $body);
    }

    // ── Internal ───────────────────────────────────────────────────────────

    private function flagIfPreviouslyPwned(int $userId): void {
        $meta = get_user_meta($userId, self::META_KEY, true);

        if (!is_array($meta)) {
            return;
        }

        do_action('dpxl_shield_alert', [
            'level'       => 'medium',
            'event_type'  => 'pwned_password_login',
            'description' => sprintf(
                'User ID %d logged in with a previously-flagged compromised password (HIBP count: %d).',
                $userId,
                (int) ($meta['count'] ?? 0)
            ),
            'context'     => ['user_id' => $userId, 'hibp_count' => $meta['count'] ?? 0],
        ]);
    }
}
