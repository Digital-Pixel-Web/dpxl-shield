<?php
declare(strict_types=1);

namespace DPXL\Shield\Core;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

class Logger {

    public static function debug(string $message, array $context = []): void {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log('[DPXL Shield] ' . $message . (!empty($context) ? ' ' . wp_json_encode($context) : ''));
        }
    }

    public static function error(string $message, array $context = []): void {
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
        error_log('[DPXL Shield ERROR] ' . $message . (!empty($context) ? ' ' . wp_json_encode($context) : ''));
    }
}
