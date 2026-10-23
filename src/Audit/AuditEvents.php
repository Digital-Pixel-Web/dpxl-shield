<?php
declare(strict_types=1);

namespace DPXL\Shield\Audit;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

/**
 * Constants for all audit log event types and categories.
 *
 * Category → colour map (for the admin UI):
 *   authentication  → yellow
 *   user_permissions→ purple
 *   plugin_themes   → blue
 *   firewall        → red
 *   site_settings   → green
 *   content         → gray
 */
class AuditEvents {

    // ── Categories ─────────────────────────────────────────────────────────
    const CATEGORY_AUTH     = 'authentication';
    const CATEGORY_USER     = 'user_permissions';
    const CATEGORY_PLUGIN   = 'plugin_themes';
    const CATEGORY_FIREWALL = 'firewall';
    const CATEGORY_SETTINGS = 'site_settings';
    const CATEGORY_CONTENT  = 'content';

    // ── Authentication ──────────────────────────────────────────────────────
    const AUTH_LOGIN_SUCCESS   = 'auth.login_success';
    const AUTH_LOGIN_FAILURE   = 'auth.login_failure';
    const AUTH_LOGOUT          = 'auth.logout';
    const AUTH_2FA_ENABLED     = 'auth.2fa_enabled';
    const AUTH_2FA_DISABLED    = 'auth.2fa_disabled';
    const AUTH_2FA_FAILED      = 'auth.2fa_failed';
    const AUTH_LOCKOUT         = 'auth.lockout';
    const AUTH_HONEYPOT        = 'auth.honeypot_triggered';
    const AUTH_PASSWORD_RESET  = 'auth.password_reset';

    // ── User / Permissions ──────────────────────────────────────────────────
    const USER_CREATED         = 'user.created';
    const USER_DELETED         = 'user.deleted';
    const USER_ROLE_CHANGED    = 'user.role_changed';
    const USER_PROFILE_UPDATED = 'user.profile_updated';

    // ── Plugin / Themes / Updates ───────────────────────────────────────────
    const PLUGIN_ACTIVATED     = 'plugin.activated';
    const PLUGIN_DEACTIVATED   = 'plugin.deactivated';
    const PLUGIN_DELETED       = 'plugin.deleted';
    const PLUGIN_INSTALLED     = 'plugin.installed';
    const PLUGIN_UPDATED       = 'plugin.updated';
    const THEME_SWITCHED       = 'theme.switched';
    const WP_CORE_UPDATED      = 'wp.core_updated';

    // ── Firewall ────────────────────────────────────────────────────────────
    const FW_IP_BLOCKED        = 'fw.ip_blocked';
    const FW_IP_UNBLOCKED      = 'fw.ip_unblocked';
    const FW_RULE_TRIGGERED    = 'fw.rule_triggered';
    const FW_DECOY_ACCESSED    = 'fw.decoy_accessed';
    const FW_TAMPER_DETECTED   = 'fw.tamper_detected';
    const FW_ANOMALY_DETECTED  = 'fw.anomaly_detected';
    const FW_REPUTATION_HIT    = 'fw.reputation_hit';

    // ── Site Settings ───────────────────────────────────────────────────────
    const SETTINGS_UPDATED     = 'settings.updated';
    const SETTINGS_EXPORTED    = 'settings.exported';
    const SETTINGS_IMPORTED    = 'settings.imported';

    // ── Content ─────────────────────────────────────────────────────────────
    const CONTENT_POST_CREATED = 'content.post_created';
    const CONTENT_POST_UPDATED = 'content.post_updated';
    const CONTENT_POST_DELETED = 'content.post_deleted';

    // ── Category map (event_type prefix → category) ────────────────────────

    /** @return string  One of the CATEGORY_* constants */
    public static function category(string $eventType): string {
        $prefix = explode('.', $eventType)[0] ?? '';

        $categories = [
            'auth'     => self::CATEGORY_AUTH,
            'user'     => self::CATEGORY_USER,
            'plugin'   => self::CATEGORY_PLUGIN,
            'theme'    => self::CATEGORY_PLUGIN,
            'wp'       => self::CATEGORY_PLUGIN,
            'fw'       => self::CATEGORY_FIREWALL,
            'settings' => self::CATEGORY_SETTINGS,
            'content'  => self::CATEGORY_CONTENT,
        ];

        return $categories[$prefix] ?? self::CATEGORY_SETTINGS;
    }

    /**
     * Events considered "significant" — logged in SIGNIFICANT_EVENTS mode.
     * Content events are excluded from this set.
     */
    public static function isSignificant(string $eventType): bool {
        return !str_starts_with($eventType, 'content.');
    }
}
