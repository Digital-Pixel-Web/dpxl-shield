<?php
declare(strict_types=1);

namespace DPXL\Shield\Honeypot;

use DPXL\Shield\Firewall\IpBlocklist;

/**
 * Registers fake "decoy" URLs that no legitimate user or search engine
 * should ever access. Any access is treated as a hostile probe.
 *
 * Decoy requests → IP blocked for 24 hours + CRITICAL alert.
 *
 * Implementation: WordPress rewrite rules redirect these URIs to
 * index.php?dpxl_decoy=1, which we intercept on template_redirect.
 * This avoids shipping real sensitive files.
 */
class DecoyEndpoints {

    private const QUERY_VAR = 'dpxl_decoy';

    /** Paths that should never be accessed on a healthy WordPress site. */
    private const DECOYS = [
        '\.env$',
        '\.env\.local$',
        'phpinfo\.php$',
        'adminer\.php$',
        'php-adminer\.php$',
        'phpmyadmin/index\.php$',
        'wp-config\.php\.bak$',
        '\.git/config$',
        'server-status$',
        'wp-content/debug\.log$',
    ];

    public function registerHooks(): void {
        add_action('init', [$this, 'addRewriteRules']);
        add_filter('query_vars', [$this, 'registerQueryVar']);
        add_action('template_redirect', [$this, 'handleDecoyHit'], 1);
    }

    public function addRewriteRules(): void {
        foreach (self::DECOYS as $pattern) {
            add_rewrite_rule(
                '^' . $pattern,
                'index.php?' . self::QUERY_VAR . '=1',
                'top'
            );
        }
    }

    public function registerQueryVar(array $vars): array {
        $vars[] = self::QUERY_VAR;
        return $vars;
    }

    public function handleDecoyHit(): void {
        if (!get_query_var(self::QUERY_VAR)) {
            return;
        }

        $ip  = $this->resolveIp();
        $uri = isset($_SERVER['REQUEST_URI']) ? esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'])) : '';

        // Block for 24 hours — decoy access is always intentional or automated.
        IpBlocklist::blockIp(
            $ip,
            "Decoy endpoint accessed: {$uri}",
            'auto_honeypot',
            DAY_IN_SECONDS
        );

        do_action('dpxl_shield_alert', [
            'level'       => 'critical',
            'event_type'  => 'decoy_accessed',
            'description' => "Decoy endpoint accessed by {$ip}: {$uri}",
            'context'     => ['ip' => $ip, 'uri' => $uri, 'method' => isset($_SERVER['REQUEST_METHOD']) ? sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'get'],
        ]);

        status_header(403);
        nocache_headers();
        header('Content-Type: text/plain');
        exit('Forbidden');
    }

    private function resolveIp(): string {
        // Spoof-resistant resolution lives in one place; see ClientIp.
        return \DPXL\Shield\Core\ClientIp::current();
    }
}
