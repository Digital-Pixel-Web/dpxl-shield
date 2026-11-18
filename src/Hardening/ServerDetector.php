<?php
declare(strict_types=1);

namespace DPXL\Shield\Hardening;

/**
 * Identifies the web server type from runtime environment.
 * Used by PhpExecutionBlocker and AutoPrepend to generate the correct directives.
 */
class ServerDetector {

    public const APACHE    = 'apache';
    public const NGINX     = 'nginx';
    public const LITESPEED = 'litespeed';
    public const UNKNOWN   = 'unknown';

    public static function detect(): string {
        $software = strtolower(isset($_SERVER['SERVER_SOFTWARE']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE'])) : '');

        // LiteSpeed must be checked before Apache because some LiteSpeed
        // builds also include "Apache" in the SERVER_SOFTWARE string.
        if (str_contains($software, 'litespeed') || str_contains($software, 'openlitespeed')) {
            return self::LITESPEED;
        }

        if (str_contains($software, 'nginx')) {
            return self::NGINX;
        }

        if (str_contains($software, 'apache')) {
            return self::APACHE;
        }

        // Fallback: if apache_get_modules() exists or an .htaccess is present,
        // the server honours .htaccess directives.
        if (function_exists('apache_get_modules')) {
            return self::APACHE;
        }

        if (file_exists(ABSPATH . '.htaccess')) {
            return self::APACHE;
        }

        return self::UNKNOWN;
    }

    public static function supportsHtaccess(): bool {
        return in_array(self::detect(), [self::APACHE, self::LITESPEED], true);
    }

    /** Returns a human-readable server name for the admin UI. */
    public static function label(): string {
        $labels = [
            self::APACHE    => 'Apache',
            self::NGINX     => 'Nginx',
            self::LITESPEED => 'LiteSpeed',
        ];

        return $labels[self::detect()] ?? 'Unknown';
    }
}
