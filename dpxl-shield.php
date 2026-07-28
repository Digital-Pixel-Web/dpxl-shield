<?php
/**
 * Plugin Name:       DPXL Shield
 * Plugin URI:        https://digitalpixel.com.br/dpxl-shield
 * Description:       Security that runs before WordPress does.
 * Version:           1.6.0
 * Author:            Digital Pixel
 * Author URI:        https://digitalpixel.com.br/
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       dpxl-shield
 * Domain Path:       /languages
 * Requires at least: 6.4
 * Requires PHP:      7.4
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

// PHP 8 string helpers, polyfilled for the 7.4 floor. Required before anything
// else — the code below uses str_contains() and does not wait for the autoloader.
require_once __DIR__ . '/src/Compat/php-polyfill.php';

define('DPXL_SHIELD_VERSION', '1.6.0');
define('DPXL_SHIELD_PATH', plugin_dir_path(__FILE__));
define('DPXL_SHIELD_URL', plugin_dir_url(__FILE__));
define('DPXL_SHIELD_FILE', __FILE__);
define('DPXL_SHIELD_BASENAME', plugin_basename(__FILE__));

// Ed25519 public key (base64) that the threat feed's signed manifest is verified
// against. The matching private key never leaves the maintainer's build/signing
// environment and is never committed. See docs-internal/dpxl-shield-threatfeed-design.md.
define('DPXL_SHIELD_FEED_PUBKEY', '2TfF5ZV81IHzcRUfTiDH9enjACNvDdb6q2otfuymVTw=');

if (file_exists(DPXL_SHIELD_PATH . 'vendor/autoload.php')) {
    require_once DPXL_SHIELD_PATH . 'vendor/autoload.php';
}

// Fatal error catcher — logs to the server's PHP error log (always writable on shared hosting)
// AND stores in a WP option so the admin panel can display it.
// Check the log via hPanel → Advanced → Error Logs, or look for ~/logs/error_log.
register_shutdown_function(static function (): void {
    $error = error_get_last();

    if ($error === null) {
        return;
    }

    $fatal = [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR];

    if (!in_array($error['type'], $fatal, true)) {
        return;
    }

    $msg = sprintf(
        '[DPXL Shield Fatal] type=%d message="%s" file=%s line=%d',
        $error['type'],
        $error['message'],
        $error['file'],
        $error['line']
    );

    // Always goes to server PHP error log — visible in hPanel → Error Logs.
    error_log($msg);

    // Store in WP option so the plugin dashboard can surface it (best-effort).
    if (function_exists('update_option')) {
        update_option('dpxl_shield_last_fatal', [
            'message' => $error['message'],
            'file'    => $error['file'],
            'line'    => $error['line'],
            'time'    => gmdate('Y-m-d H:i:s'),
        ], false);
    }
});

// Start output buffering early for REST API requests so any PHP notices/warnings
// generated during plugins_loaded (e.g. from WP_DEBUG_DISPLAY = true) are captured
// in a buffer rather than being sent directly to the response stream, where they
// would corrupt the JSON body. The buffer is cleaned in RestApi::cleanRestOutputBuffer().
if (!defined('DPXL_SHIELD_EXTENDED_ACTIVE')) {
    $dpxlRequestUri = $_SERVER['REQUEST_URI'] ?? '';
    if (str_contains($dpxlRequestUri, '/wp-json/') || str_contains($dpxlRequestUri, '?rest_route=')) {
        ob_start();
    }
    unset($dpxlRequestUri);
}

register_activation_hook(__FILE__, [\DPXL\Shield\Core\Plugin::class, 'activate']);
register_deactivation_hook(__FILE__, [\DPXL\Shield\Core\Plugin::class, 'deactivate']);

// Self-protection: verify plugin file integrity before anything else runs.
add_action('plugins_loaded', [\DPXL\Shield\SelfProtection\TamperDetector::class, 'verifyIntegrity'], -20);

add_action('plugins_loaded', [\DPXL\Shield\Bootstrap\PluginInit::class, 'boot'], -10);
