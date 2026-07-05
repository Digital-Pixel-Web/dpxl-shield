<?php
/**
 * Plugin Name:       DPXL Shield
 * Plugin URI:        https://digitalpixel.com.br/dpxl-shield
 * Description:       Security that runs before WordPress does.
 * Version:           1.0.13
 * Author:            Digital Pixel
 * Author URI:        https://digitalpixel.com.br/
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       dpxl-shield
 * Domain Path:       /languages
 * Requires at least: 6.4
 * Requires PHP:      8.1
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

define('DPXL_SHIELD_VERSION', '1.0.13');
define('DPXL_SHIELD_PATH', plugin_dir_path(__FILE__));
define('DPXL_SHIELD_URL', plugin_dir_url(__FILE__));
define('DPXL_SHIELD_FILE', __FILE__);
define('DPXL_SHIELD_BASENAME', plugin_basename(__FILE__));

if (file_exists(DPXL_SHIELD_PATH . 'vendor/autoload.php')) {
    require_once DPXL_SHIELD_PATH . 'vendor/autoload.php';
}

register_activation_hook(__FILE__, [\DPXL\Shield\Core\Plugin::class, 'activate']);
register_deactivation_hook(__FILE__, [\DPXL\Shield\Core\Plugin::class, 'deactivate']);

// Self-protection: verify plugin file integrity before anything else runs.
add_action('plugins_loaded', [\DPXL\Shield\SelfProtection\TamperDetector::class, 'verifyIntegrity'], -20);

add_action('plugins_loaded', [\DPXL\Shield\Bootstrap\PluginInit::class, 'boot'], -10);
