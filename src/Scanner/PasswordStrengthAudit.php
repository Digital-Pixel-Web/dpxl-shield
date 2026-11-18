<?php
declare(strict_types=1);

namespace DPXL\Shield\Scanner;

use DPXL\Shield\LoginSecurity\PasswordAudit;

/**
 * Audits all WordPress user accounts for compromised or weak passwords.
 *
 * This is a scan-time check (not per-request).  It:
 *   - Iterates over all users with elevated roles (administrator, editor)
 *   - Checks whether their passwords are flagged in user meta by PasswordAudit
 *   - Reports users whose passwords need to be changed
 *
 * Note: We cannot check actual stored password hashes (bcrypt — irreversible).
 * We rely on the flag set by PasswordAudit::onProfileUpdate / onPasswordReset.
 *
 * Results are fed into ScanOrchestrator::persistResults().
 */
class PasswordStrengthAudit {

    private const META_KEY    = '_dpxl_shield_pwned_password';
    private const AUDIT_ROLES = ['administrator', 'editor', 'author'];

    /**
     * @return array<int,array{file_path:string,issue_type:string,severity:string,details:string}>
     */
    public function run(): array {
        $results = [];

        $users = get_users([
            'role__in' => self::AUDIT_ROLES,
            'fields'   => ['ID', 'user_login', 'user_email'],
            'number'   => 500,
        ]);

        foreach ($users as $user) {
            $userId = (int) $user->ID;
            $login  = (string) $user->user_login;

            // Check for HIBP flag.
            $pwnedMeta = get_user_meta($userId, self::META_KEY, true);

            if (is_array($pwnedMeta) && isset($pwnedMeta['count'])) {
                $count   = (int) $pwnedMeta['count'];
                $results[] = [
                    'file_path'  => "user:{$userId}:{$login}",
                    'issue_type' => 'unknown',
                    'severity'   => $count > 100 ? 'critical' : 'high',
                    'details'    => "User '{$login}' has a password that appears {$count}× in known data breaches. Password must be changed.",
                ];
                continue;
            }

            // Check for no password set (reset token still active).
            $caps  = get_user_meta($userId, $GLOBALS['wpdb']->prefix . 'capabilities', true);

            if (empty($caps)) {
                continue;
            }

            // Check for default/empty password indicator (WP sets this on some import scenarios).
            $hash = $GLOBALS['wpdb']->get_var(
                $GLOBALS['wpdb']->prepare(
                    "SELECT user_pass FROM {$GLOBALS['wpdb']->users} WHERE ID = %d",
                    $userId
                )
            );

            if ($hash === '' || $hash === '*') {
                $results[] = [
                    'file_path'  => "user:{$userId}:{$login}",
                    'issue_type' => 'unknown',
                    'severity'   => 'high',
                    'details'    => "User '{$login}' has no password set. Account may be compromised.",
                ];
            }
        }

        return $results;
    }
}
