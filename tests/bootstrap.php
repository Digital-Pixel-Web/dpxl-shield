<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Brain\Monkey;

// WordPress constants needed by the plugin.
defined('ABSPATH')           || define('ABSPATH', '/tmp/wordpress/');
defined('WP_CONTENT_DIR')    || define('WP_CONTENT_DIR', '/tmp/wordpress/wp-content');
defined('WP_PLUGIN_DIR')     || define('WP_PLUGIN_DIR', '/tmp/wordpress/wp-content/plugins');
defined('WPINC')             || define('WPINC', 'wp-includes');
defined('DAY_IN_SECONDS')    || define('DAY_IN_SECONDS', 86400);
defined('HOUR_IN_SECONDS')   || define('HOUR_IN_SECONDS', 3600);
defined('MINUTE_IN_SECONDS') || define('MINUTE_IN_SECONDS', 60);
defined('WEEK_IN_SECONDS')   || define('WEEK_IN_SECONDS', 604800);
defined('DPXL_SHIELD_PATH')  || define('DPXL_SHIELD_PATH', dirname(__DIR__) . '/');
defined('DPXL_SHIELD_VERSION') || define('DPXL_SHIELD_VERSION', '1.0.0');

/**
 * Minimal WP_Error stand-in.
 *
 * Brain\Monkey stubs functions, not classes, but several hook callbacks are
 * type-hinted against WP_Error because that is genuinely what WordPress passes.
 * Only the surface the plugin touches is implemented.
 */
if (!class_exists('WP_Error')) {
    class WP_Error {

        /** @var array<string,string[]> */
        public $errors = [];

        public function __construct(string $code = '', string $message = '') {
            if ($code !== '') {
                $this->add($code, $message);
            }
        }

        public function add($code, $message = '', $data = ''): void {
            $this->errors[(string) $code][] = (string) $message;
        }

        public function get_error_message($code = ''): string {
            if ($code === '') {
                $first = reset($this->errors);
                return is_array($first) && $first !== [] ? (string) $first[0] : '';
            }

            return isset($this->errors[$code][0]) ? (string) $this->errors[$code][0] : '';
        }

        /** @return string[] */
        public function get_error_codes(): array {
            return array_keys($this->errors);
        }

        public function has_errors(): bool {
            return $this->errors !== [];
        }
    }
}

// Bootstrap Brain\Monkey before each test and tear down after.
\PHPUnit\Framework\TestCase::class; // autoload check

// Global setup/teardown via PHPUnit event system handled per-test via trait or setUp/tearDown.
