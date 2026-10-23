<?php
declare(strict_types=1);

namespace DPXL\Shield\Alerts;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

use DPXL\Shield\Audit\AuditLog;
use DPXL\Shield\Audit\AuditEvents;
use DPXL\Shield\Core\Options;
use DPXL\Shield\Integrations\WebhookDispatcher;

/**
 * Central alert dispatcher.
 *
 * Listens to the `dpxl_shield_alert` action fired throughout the plugin,
 * writes to the audit log, and routes to notification channels.
 *
 * Expected action payload:
 * [
 *   'level'       => 'critical|high|medium|low|info',
 *   'event_type'  => 'fw.ip_blocked' (AuditEvents::* constant),
 *   'description' => 'Human-readable summary',
 *   'context'     => [],   // optional extra data
 * ]
 */
class AlertManager {

    /** @var EmailChannel */
    private $email;

    /** @var WebhookDispatcher */
    private $webhooks;

    public function __construct() {
        $this->email    = new EmailChannel();
        $this->webhooks = new WebhookDispatcher();
    }

    public function registerHooks(): void {
        add_action('dpxl_shield_alert', [$this, 'handle'], 10, 1);

        // WordPress lifecycle events → audit log.
        add_action('wp_login',          [$this, 'onLoginSuccess'], 10, 2);
        add_action('wp_logout',         [$this, 'onLogout']);
        add_action('user_register',     [$this, 'onUserCreated']);
        add_action('delete_user',       [$this, 'onUserDeleted']);
        add_action('set_user_role',     [$this, 'onRoleChanged'], 10, 3);
        add_action('activated_plugin',  [$this, 'onPluginActivated']);
        add_action('upgrader_process_complete', [$this, 'onUpdateComplete'], 10, 2);
        add_action('switch_theme',      [$this, 'onThemeSwitched']);
        add_action('updated_option',    [$this, 'onOptionUpdated'], 10, 3);
    }

    // ── Primary handler ────────────────────────────────────────────────────

    /** @param array{level: string, event_type: string, description: string, context?: array<string,mixed>} $alert */
    public function handle(array $alert): void {
        $level       = (string) ($alert['level']       ?? 'info');
        $eventType   = (string) ($alert['event_type']  ?? 'fw.rule_triggered');
        $description = (string) ($alert['description'] ?? '');
        $context     = (array)  ($alert['context']     ?? []);

        // Always write to audit log.
        AuditLog::log($eventType, $level, $description, $context);

        // Email for medium+ severity.
        if (in_array($level, ['critical', 'high', 'medium'], true)) {
            $this->email->send($level, $eventType, $description, $context);
        }

        // Outbound integrations. Queued here and delivered on shutdown, so a
        // slow Slack or PagerDuty never shows up as page latency. Each endpoint
        // applies its own severity threshold, so this hands over everything.
        $this->webhooks->enqueue($level, $eventType, $description, $context);
    }

    // ── WordPress lifecycle → audit log ────────────────────────────────────

    /** @param \WP_User $user */
    public function onLoginSuccess(string $username, $user): void {
        AuditLog::log(
            AuditEvents::AUTH_LOGIN_SUCCESS,
            'info',
            "Login successful: {$username}",
            ['username' => $username]
        );
    }

    public function onLogout(): void {
        $user = wp_get_current_user();
        AuditLog::log(AuditEvents::AUTH_LOGOUT, 'info', "User logged out: {$user->user_login}");
    }

    public function onUserCreated(int $userId): void {
        $user = get_userdata($userId);
        $login = $user ? $user->user_login : "ID:{$userId}";

        AuditLog::log(AuditEvents::USER_CREATED, 'medium', "New user created: {$login}", ['user_id' => $userId]);
    }

    public function onUserDeleted(int $userId): void {
        $user  = get_userdata($userId);
        $login = $user ? $user->user_login : "ID:{$userId}";

        AuditLog::log(AuditEvents::USER_DELETED, 'medium', "User deleted: {$login}", ['user_id' => $userId]);
    }

    /** @param string[] $oldRoles */
    public function onRoleChanged(int $userId, string $role, array $oldRoles): void {
        $user     = get_userdata($userId);
        $login    = $user ? $user->user_login : "ID:{$userId}";
        $severity = ($role === 'administrator') ? 'high' : 'medium';

        AuditLog::log(
            AuditEvents::USER_ROLE_CHANGED,
            $severity,
            "Role changed for {$login}: " . implode(',', $oldRoles) . " → {$role}",
            ['user_id' => $userId, 'new_role' => $role, 'old_roles' => $oldRoles]
        );

        if ($role === 'administrator') {
            $this->email->send('high', AuditEvents::USER_ROLE_CHANGED, "User {$login} was promoted to administrator.", []);
        }
    }

    public function onPluginActivated(string $plugin): void {
        AuditLog::log(AuditEvents::PLUGIN_ACTIVATED, 'info', "Plugin activated: {$plugin}", ['plugin' => $plugin]);
    }

    /** @param array<string,mixed> $hookExtra */
    public function onUpdateComplete(\WP_Upgrader $upgrader, array $hookExtra): void {
        $type   = $hookExtra['type']   ?? 'unknown';
        $action = $hookExtra['action'] ?? 'unknown';

        AuditLog::log(AuditEvents::PLUGIN_UPDATED, 'info', "Update completed: {$type} {$action}", $hookExtra);
    }

    public function onThemeSwitched(string $newName): void {
        AuditLog::log(AuditEvents::THEME_SWITCHED, 'info', "Theme switched to: {$newName}");
    }

    /** @param mixed $oldValue @param mixed $newValue */
    public function onOptionUpdated(string $option, $oldValue, $newValue): void {
        // Only log WordPress core options and DPXL Shield options, not transients etc.
        $trackedPrefixes = ['dpxl_shield_', 'blogname', 'siteurl', 'admin_email', 'default_role', 'permalink_structure'];

        $track = false;
        foreach ($trackedPrefixes as $prefix) {
            if (str_starts_with($option, $prefix)) {
                $track = true;
                break;
            }
        }

        if (!$track) {
            return;
        }

        AuditLog::log(
            AuditEvents::SETTINGS_UPDATED,
            'info',
            "Option updated: {$option}",
            ['option' => $option]
        );
    }
}
