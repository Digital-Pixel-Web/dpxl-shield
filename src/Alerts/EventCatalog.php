<?php
declare(strict_types=1);

namespace DPXL\Shield\Alerts;

/**
 * Human-readable names for alert events and context fields.
 *
 * Event types are machine slugs (`new_admin_ip_login`, `fw.reputation_hit`).
 * They are fine in the audit log and in webhooks, but they must never reach
 * an email subject line or heading. This catalog maps each slug to a short
 * title and a one-sentence explanation of what actually happened.
 *
 * Unknown slugs fall back to a humanised form of the slug itself, so a new
 * event type still produces a readable email before it is catalogued here.
 */
class EventCatalog {

    /**
     * Short title — used in the subject line and as the email heading.
     */
    public static function label(string $eventType): string {
        $labels = [
            // Authentication
            'new_admin_ip_login'       => __('Admin login from a new IP', 'dpxl-shield'),
            'brute_force_lockout'      => __('IP locked out after failed logins', 'dpxl-shield'),
            'auth.lockout'             => __('IP locked out after failed logins', 'dpxl-shield'),
            '2fa_activated'            => __('Two-factor authentication enabled', 'dpxl-shield'),
            '2fa_deactivated'          => __('Two-factor authentication disabled', 'dpxl-shield'),
            'pwned_password_login'     => __('Login with a breached password', 'dpxl-shield'),
            'pwned_password_reset'     => __('Password reset after breach match', 'dpxl-shield'),

            // Users
            'user.created'             => __('New user account created', 'dpxl-shield'),
            'user.deleted'             => __('User account deleted', 'dpxl-shield'),
            'user.role_changed'        => __('User promoted to administrator', 'dpxl-shield'),

            // Firewall / traffic
            'fw.ip_blocked'            => __('IP address blocked', 'dpxl-shield'),
            'fw.rule_triggered'        => __('Firewall rule triggered', 'dpxl-shield'),
            'fw.reputation_hit'        => __('Site listed on a security blocklist', 'dpxl-shield'),
            'anomaly_detected'         => __('Suspicious traffic pattern detected', 'dpxl-shield'),
            'honeypot_triggered'       => __('Honeypot field filled by a bot', 'dpxl-shield'),
            'decoy_accessed'           => __('Decoy endpoint accessed', 'dpxl-shield'),

            // Integrity / self-protection
            'file_modified'            => __('Critical WordPress file changed', 'dpxl-shield'),
            'plugin_tampered'          => __('DPXL Shield files were modified', 'dpxl-shield'),
            'plugin_deactivated'       => __('DPXL Shield was deactivated', 'dpxl-shield'),
            'plugin_deleted'           => __('DPXL Shield was deleted', 'dpxl-shield'),
            'integrity_store_conflict' => __('Integrity records disagree', 'dpxl-shield'),

            // Scanner
            'scan_found_criticals'     => __('Security scan found critical issues', 'dpxl-shield'),
        ];

        return $labels[$eventType] ?? self::humanise($eventType);
    }

    /**
     * One sentence explaining why the alert exists — shown under the heading
     * when the caller's own description is not self-explanatory.
     */
    public static function summary(string $eventType): string {
        $summaries = [
            'new_admin_ip_login'       => __('An administrator signed in from an IP address that had never been used for this account before. If this was you, no action is needed.', 'dpxl-shield'),
            'brute_force_lockout'      => __('Repeated failed login attempts came from the same address, so it was locked out automatically.', 'dpxl-shield'),
            '2fa_activated'            => __('Two-factor authentication was turned on for an account.', 'dpxl-shield'),
            '2fa_deactivated'          => __('Two-factor authentication was turned off for an account. Confirm this was intentional.', 'dpxl-shield'),
            'pwned_password_login'     => __('This account signed in with a password that appears in a known public data breach. It should be changed.', 'dpxl-shield'),
            'pwned_password_reset'     => __('The password was found in a known public data breach and has been reset.', 'dpxl-shield'),
            'user.created'             => __('A new account was added to this site.', 'dpxl-shield'),
            'user.role_changed'        => __('An account was granted administrator access. Administrators can install plugins and modify any content.', 'dpxl-shield'),
            'fw.reputation_hit'        => __('An external blocklist is flagging this site. Search engines and email providers may start warning visitors.', 'dpxl-shield'),
            'anomaly_detected'         => __('The behavioural engine saw a request pattern typical of automated scanning.', 'dpxl-shield'),
            'honeypot_triggered'       => __('A hidden form field, invisible to humans, was filled in — a reliable sign of an automated bot.', 'dpxl-shield'),
            'decoy_accessed'           => __('A decoy URL that no legitimate visitor should ever request was accessed.', 'dpxl-shield'),
            'file_modified'            => __('A file WordPress relies on changed outside of a normal update. This can indicate a compromise.', 'dpxl-shield'),
            'plugin_tampered'          => __('DPXL Shield\'s own files no longer match their signed checksums. Malware often disables security plugins first.', 'dpxl-shield'),
            'plugin_deactivated'       => __('Site protection is currently off. If you did not do this, treat it as an intrusion.', 'dpxl-shield'),
            'plugin_deleted'           => __('Site protection has been removed. If you did not do this, treat it as an intrusion.', 'dpxl-shield'),
            'integrity_store_conflict' => __('The three independent copies of the integrity baseline no longer agree with each other.', 'dpxl-shield'),
            'scan_found_criticals'     => __('The latest scan finished with issues that need review.', 'dpxl-shield'),
        ];

        return $summaries[$eventType] ?? '';
    }

    /**
     * Human label for a context field key (`user_id` → `User ID`).
     */
    public static function fieldLabel(string $key): string {
        $labels = [
            'username'    => __('Username', 'dpxl-shield'),
            'user_login'  => __('Username', 'dpxl-shield'),
            'user_id'     => __('User ID', 'dpxl-shield'),
            'ip'          => __('IP address', 'dpxl-shield'),
            'hostname'    => __('Hostname', 'dpxl-shield'),
            'country'     => __('Country', 'dpxl-shield'),
            'uri'         => __('URL', 'dpxl-shield'),
            'url'         => __('URL', 'dpxl-shield'),
            'user_agent'  => __('User agent', 'dpxl-shield'),
            'referer'     => __('Referrer', 'dpxl-shield'),
            'rule_id'     => __('Rule', 'dpxl-shield'),
            'reason'      => __('Reason', 'dpxl-shield'),
            'file'        => __('File', 'dpxl-shield'),
            'file_path'   => __('File', 'dpxl-shield'),
            'plugin'      => __('Plugin', 'dpxl-shield'),
            'scan_id'     => __('Scan ID', 'dpxl-shield'),
            'attempts'    => __('Attempts', 'dpxl-shield'),
            'new_role'    => __('New role', 'dpxl-shield'),
            'old_roles'   => __('Previous roles', 'dpxl-shield'),
        ];

        return $labels[$key] ?? self::humanise($key);
    }

    /**
     * `fw.rule_triggered` → `Rule triggered`. Last-resort readable form.
     */
    private static function humanise(string $slug): string {
        $slug = (string) preg_replace('/^[a-z]+\./', '', $slug);
        $slug = str_replace(['_', '-'], ' ', $slug);

        return ucfirst(trim($slug));
    }
}
