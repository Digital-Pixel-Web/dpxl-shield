<?php
declare(strict_types=1);

namespace DPXL\Shield\Hardening;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

use DPXL\Shield\Core\Logger;

/**
 * Blocks PHP execution inside the WordPress uploads directory.
 *
 * Apache / LiteSpeed → writes rules to /wp-content/uploads/.htaccess
 * Nginx              → generates a config snippet for the admin to paste
 *
 * The .htaccess approach is fully automatic. Nginx requires manual action
 * (the snippet is displayed in the Diagnostics page).
 */
class PhpExecutionBlocker {

    private const MARKER_BEGIN = '# BEGIN DPXL Shield PHP Execution Block';
    private const MARKER_END   = '# END DPXL Shield PHP Execution Block';

    private const HTACCESS_RULES = <<<'HTACCESS'

<FilesMatch "\.(php[0-9]?|phtml|phar|php-s|shtml)$">
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
    <IfModule !mod_authz_core.c>
        Order Deny,Allow
        Deny from all
    </IfModule>
</FilesMatch>

HTACCESS;

    /**
     * Installs the PHP execution block.
     *
     * @return bool|string  true on success, Nginx snippet string if manual action needed, false on failure
     */
    public function install() {
        $server = ServerDetector::detect();

        if ($server === ServerDetector::APACHE || $server === ServerDetector::LITESPEED) {
            return $this->writeHtaccess();
        }

        if ($server === ServerDetector::NGINX) {
            return $this->nginxSnippet();
        }

        return false;
    }

    /**
     * Removes the block (called on plugin deactivation).
     */
    public function remove(): bool {
        $path = $this->htaccessPath();

        if (!file_exists($path)) {
            return true;
        }

        $content = @file_get_contents($path);

        if ($content === false) {
            return false;
        }

        $pattern    = '/' . preg_quote(self::MARKER_BEGIN, '/') . '.*?' . preg_quote(self::MARKER_END, '/') . '\s*/s';
        $newContent = preg_replace($pattern, '', $content);

        // If the file is now empty, delete it entirely.
        if (trim((string) $newContent) === '') {
            return @unlink($path);
        }

        return @file_put_contents($path, $newContent) !== false;
    }

    public function isInstalled(): bool {
        $path = $this->htaccessPath();

        if (!file_exists($path)) {
            return false;
        }

        $content = @file_get_contents($path);

        return $content !== false && str_contains($content, self::MARKER_BEGIN);
    }

    public function nginxSnippet(): string {
        return <<<'NGINX'
# Add this block to your Nginx server {} configuration:
location ~* /wp-content/uploads/.*\.(php[0-9]?|phtml|phar|php-s|shtml)$ {
    deny all;
    return 403;
}
NGINX;
    }

    // ── Internal ───────────────────────────────────────────────────────────

    private function writeHtaccess(): bool {
        $path  = $this->htaccessPath();
        $block = self::MARKER_BEGIN . self::HTACCESS_RULES . self::MARKER_END . "\n";

        if (!is_writable(dirname($path))) {
            Logger::error('PhpExecutionBlocker: uploads directory is not writable.');
            return false;
        }

        if (file_exists($path)) {
            $existing = @file_get_contents($path);

            if ($existing !== false && str_contains($existing, self::MARKER_BEGIN)) {
                return true; // Already installed.
            }

            $block = $block . "\n" . (string) $existing;
        }

        return @file_put_contents($path, $block) !== false;
    }

    private function htaccessPath(): string {
        $uploadDir = wp_upload_dir();
        return trailingslashit($uploadDir['basedir']) . '.htaccess';
    }
}
