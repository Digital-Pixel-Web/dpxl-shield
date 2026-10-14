<?php
declare(strict_types=1);

namespace DPXL\Shield\SelfProtection;

use DPXL\Shield\Core\Logger;

/**
 * Logs plugin deactivation and deletion events.
 *
 * These events can be signs of an attacker trying to disable protection
 * before launching an attack.  Each event is logged to the audit log
 * and a CRITICAL alert is fired.  Deletion also sends a direct wp_mail
 * because the hook infrastructure may be torn down before the event fires.
 */
class DeactivationGuard {

    private const OUR_BASENAME = 'dpxl-shield/dpxl-shield.php';

    public function registerHooks(): void {
        add_action('deactivated_plugin', [$this, 'onDeactivated'], 10, 2);
        add_action('deleted_plugin',     [$this, 'onDeleted'], 10, 2);
    }

    // ── Handlers ───────────────────────────────────────────────────────────

    public function onDeactivated(string $pluginBasename, bool $networkDeactivating): void {
        $actor = $this->currentActor();

        Logger::error(sprintf(
            'DeactivationGuard: plugin deactivated — plugin=%s actor=%s ip=%s network=%s',
            $pluginBasename,
            $actor['user'],
            $actor['ip'],
            $networkDeactivating ? 'yes' : 'no'
        ));

        $ours = ($pluginBasename === self::OUR_BASENAME);

        // The event type decides the email's title and summary, so one type
        // cannot serve both cases: `plugin_deactivated` says "DPXL Shield was
        // switched off", which is false — and alarming — when the plugin that
        // was switched off belongs to someone else. Routine plugin management
        // is recorded in the audit log and sent to the integrations, without an
        // email; only our own plugin going quiet is worth interrupting someone.
        do_action('dpxl_shield_alert', [
            'level'       => $ours ? 'critical' : 'low',
            'event_type'  => $ours ? 'plugin_deactivated' : 'other_plugin_deactivated',
            'description' => sprintf(
                'Plugin deactivated: %s by %s from %s%s',
                $pluginBasename,
                $actor['user'],
                $actor['ip'],
                $networkDeactivating ? ' (network-wide)' : ''
            ),
            'context'     => array_merge($actor, [
                'plugin'              => $pluginBasename,
                'network_deactivating' => $networkDeactivating,
                'our_plugin'          => $ours,
            ]),
        ]);
    }

    public function onDeleted(string $pluginFile, bool $deleted): void {
        if (!$deleted) {
            return;
        }

        $actor = $this->currentActor();

        Logger::error(sprintf(
            'DeactivationGuard: plugin deleted — plugin=%s actor=%s ip=%s',
            $pluginFile,
            $actor['user'],
            $actor['ip']
        ));

        $ours = str_contains($pluginFile, 'dpxl-shield');

        do_action('dpxl_shield_alert', [
            'level'       => $ours ? 'critical' : 'low',
            'event_type'  => $ours ? 'plugin_deleted' : 'other_plugin_deleted',
            'description' => sprintf('Plugin deleted: %s by %s from %s', $pluginFile, $actor['user'], $actor['ip']),
            'context'     => array_merge($actor, [
                'plugin'     => $pluginFile,
                'our_plugin' => $ours,
            ]),
        ]);

        // If our own plugin was deleted, send a direct email since hooks may not fire later.
        if ($ours) {
            $this->sendDeletionEmail($actor);
        }
    }

    // ── Internal ───────────────────────────────────────────────────────────

    /** @return array{user: string, ip: string, user_id: int} */
    private function currentActor(): array {
        $userId = get_current_user_id();
        $user   = $userId ? (get_userdata($userId)->user_login ?? "user#{$userId}") : 'cli/cron';
        $ip     = $this->resolveIp();

        return ['user' => $user, 'ip' => $ip, 'user_id' => $userId];
    }

    private function resolveIp(): string {
        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $header) {
            $ip = trim(explode(',', $_SERVER[$header] ?? '')[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }

        return 'cli';
    }

    /** @param array{user: string, ip: string, user_id: int} $actor */
    private function sendDeletionEmail(array $actor): void {
        $adminEmail = get_option('admin_email');

        if (!$adminEmail) {
            return;
        }

        $siteName = get_option('blogname', get_option('siteurl'));
        $subject  = "[{$siteName}] CRITICAL — DPXL Shield was deleted";
        $message  = sprintf(
            "DPXL Shield has been deleted from your site.\n\n" .
            "Site:    %s\n" .
            "By:      %s\n" .
            "From IP: %s\n" .
            "Time:    %s UTC\n\n" .
            "If you did not authorise this, investigate immediately.\n",
            get_option('siteurl'),
            $actor['user'],
            $actor['ip'],
            gmdate('Y-m-d H:i:s')
        );

        wp_mail($adminEmail, $subject, $message);
    }
}
