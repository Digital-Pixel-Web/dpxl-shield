<?php
/**
 * Plugin Name:       DPXL Shield
 * Plugin URI:        https://digitalpixel.com.br/shieldwp/
 * Description:       Firewall, malware scanner, login protection and two-factor authentication for WordPress. Free and open source.
 * Version:           1.12.1
 * Author:            Digital Pixel
 * Author URI:        https://digitalpixel.com.br/
 * License:           GPLv2 or later
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

// str_contains() and the other PHP 8 string helpers come from WordPress itself
// here (wp-includes/compat.php). Before WordPress loads, Extended Protection
// gets them from symfony/polyfill-php80 through the autoloader.

define('DPXL_SHIELD_VERSION', '1.12.1');
define('DPXL_SHIELD_PATH', plugin_dir_path(__FILE__));
define('DPXL_SHIELD_URL', plugin_dir_url(__FILE__));
define('DPXL_SHIELD_FILE', __FILE__);
define('DPXL_SHIELD_BASENAME', plugin_basename(__FILE__));

// Ed25519 public key (base64) that the threat feed's signed manifest is verified
// against. The matching private key never leaves the maintainer's build/signing
// environment and is never committed. See docs-internal/dpxl-shield-threatfeed-design.md.
define('DPXL_SHIELD_FEED_PUBKEY', '2TfF5ZV81IHzcRUfTiDH9enjACNvDdb6q2otfuymVTw=');

if (!file_exists(DPXL_SHIELD_PATH . 'vendor/autoload.php')) {
    // Installed from GitHub's "Download ZIP" (source code, no dependencies)
    // instead of a release package. Say so instead of fataling on activation.
    add_action('admin_notices', static function (): void {
        if (!current_user_can('activate_plugins')) {
            return;
        }

        echo '<div class="notice notice-error"><p>'
            . esc_html__('DPXL Shield is missing its dependencies. Install the release package (dpxl-shield.zip) from the Releases page on GitHub or from WordPress.org, not the source-code ZIP.', 'dpxl-shield')
            . ' <a href="https://github.com/Digital-Pixel-Web/dpxl-shield/releases/latest">'
            . esc_html__('Download the release', 'dpxl-shield')
            . '</a></p></div>';
    });

    return;
}

require_once DPXL_SHIELD_PATH . 'vendor/autoload.php';

// Fatal error catcher — PHP logs the error itself; a copy goes to a WP option so
// the admin panel can display it.
register_shutdown_function(static function (): void {
    $error = error_get_last();

    if ($error === null) {
        return;
    }

    $fatal = [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR];

    if (!in_array($error['type'], $fatal, true)) {
        return;
    }

    // PHP already writes the fatal error to the server log; this keeps a copy
    // the plugin dashboard can show.
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
    $dpxlRequestUri = isset($_SERVER['REQUEST_URI']) ? esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'])) : '';
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
