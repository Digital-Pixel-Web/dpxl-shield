<?php
declare(strict_types=1);

namespace DPXL\Shield\Hardening;

use DPXL\Shield\Core\Options;

/**
 * General WordPress hardening measures applied via hooks.
 */
class WpHardening {

    public function registerHooks(): void {
        // Remove WordPress version from HTML head and RSS feeds.
        remove_action('wp_head', 'wp_generator');
        add_filter('the_generator', '__return_empty_string');

        // Remove RSD and Windows Live Writer manifest links.
        remove_action('wp_head', 'rsd_link');
        remove_action('wp_head', 'wlwmanifest_link');

        // Remove shortlink from head (information leakage).
        remove_action('wp_head', 'wp_shortlink_wp_head');

        // Restrict REST API user listing to authenticated users only.
        add_filter('rest_endpoints', [$this, 'restrictUserEndpoints']);

        // Disable pingbacks if not needed.
        add_filter('xmlrpc_methods', [$this, 'disablePingbacks']);

        // Prevent author query var from leaking usernames.
        add_action('template_redirect', [$this, 'blockAuthorScan']);

        if (Options::get('xmlrpc_disabled', false)) {
            add_filter('xmlrpc_enabled', '__return_false');
        }
    }

    /**
     * Removes /wp/v2/users endpoints for unauthenticated requests.
     */
    public function restrictUserEndpoints(array $endpoints): array {
        if (is_user_logged_in()) {
            return $endpoints;
        }

        unset($endpoints['/wp/v2/users'], $endpoints['/wp/v2/users/(?P<id>[\d]+)']);

        return $endpoints;
    }

    /**
     * Removes pingback.ping from XML-RPC method list.
     */
    public function disablePingbacks(array $methods): array {
        unset($methods['pingback.ping'], $methods['pingback.extensions.getPingbacks']);
        return $methods;
    }

    /**
     * Blocks direct ?author=N requests that enumerate WordPress usernames.
     * The WAF rule (wp-002) handles pre-WordPress blocking; this handles
     * any that slip through in basic mode.
     */
    public function blockAuthorScan(): void {
        if (!is_author()) {
            return;
        }

        // Allow if the request came from a logged-in admin (preview).
        if (current_user_can('manage_options')) {
            return;
        }

        wp_die(
            esc_html__('Author archives are disabled.', 'dpxl-shield'),
            esc_html__('403 Forbidden', 'dpxl-shield'),
            ['response' => 403]
        );
    }
}
