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

// Bootstrap Brain\Monkey before each test and tear down after.
\PHPUnit\Framework\TestCase::class; // autoload check

// Global setup/teardown via PHPUnit event system handled per-test via trait or setUp/tearDown.
