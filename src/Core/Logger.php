<?php
declare(strict_types=1);

namespace DPXL\Shield\Core;

/** Writes to the PHP error log only when WP_DEBUG is on. */
class Logger {

    public static function debug(string $message, array $context = []): void {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log('[DPXL Shield] ' . $message . (!empty($context) ? ' ' . wp_json_encode($context) : ''));
        }
    }

    public static function error(string $message, array $context = []): void {
        if (!defined('WP_DEBUG') || !WP_DEBUG) {
            return;
        }

        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
        error_log('[DPXL Shield ERROR] ' . $message . (!empty($context) ? ' ' . wp_json_encode($context) : ''));
    }
}
