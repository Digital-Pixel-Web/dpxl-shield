<?php
declare(strict_types=1);

namespace DPXL\Shield\Bootstrap;

use DPXL\Shield\Hardening\ServerDetector;

/**
 * Extended Protection installer.
 *
 * Wordfence-style flow:
 *   1. Admin downloads the current .htaccess as a backup.
 *   2. DPXL Shield creates a safe prepend loader outside the plugin folder.
 *   3. DPXL Shield writes a managed auto_prepend_file block to .htaccess.
 *   4. A loopback request verifies that the loader really ran before PHP output.
 *   5. If verification fails, the original .htaccess is restored automatically.
 *
 * Safety note:
 * The auto_prepend_file directive points to a root-level wrapper file, not
 * directly to wp-content/plugins/dpxl-shield/dpxl-shield-waf.php. If the plugin
 * is deleted manually or cleanup cannot remove the server directive, the wrapper
 * can no-op instead of taking the site down because a plugin file is missing.
 */
class AutoPrepend {

    private const MARKER_BEGIN  = '# BEGIN DPXL Shield Extended Protection';
    private const MARKER_END    = '# END DPXL Shield Extended Protection';

    private const USER_INI_MARKER_BEGIN = '; BEGIN DPXL Shield Extended Protection';
    private const USER_INI_MARKER_END   = '; END DPXL Shield Extended Protection';

    private const STATUS_OPTION = 'dpxl_shield_extended_mode_method';
    private const BACKUP_OPTION = 'dpxl_shield_htaccess_backup_downloaded_at';
    private const ERROR_OPTION  = 'dpxl_shield_extended_last_error';

    private const SAFE_PREPEND_FILENAME = 'dpxl-shield-prepend.php';

    public function enable(): array {
        return $this->enableHtaccessAfterBackup(true);
    }

    /**
     * Enables Extended Protection by writing the managed .htaccess block.
     */
    public function enableHtaccessAfterBackup(bool $requireBackup = true): array {
        $wafFile      = $this->getWafFile();
        $prependFile  = $this->getPrependFile();
        $htaccessPath = $this->getHtaccessPath();
        $userIniPath  = $this->getUserIniPath();

        if ($requireBackup && !$this->hasDownloadedHtaccessBackup()) {
            return $this->fail(
                'backup_required',
                __('Please download a backup of your current .htaccess file before enabling Extended Protection.', 'dpxl-shield'),
                ['snippet' => $this->manualSnippet($prependFile, $wafFile)]
            );
        }

        if (!file_exists($wafFile)) {
            return $this->fail(
                'waf_file_missing',
                __('The WAF loader file dpxl-shield-waf.php was not found.', 'dpxl-shield'),
                ['snippet' => $this->manualSnippet($prependFile, $wafFile)]
            );
        }

        if (!$this->ensureActivePrependLoader($prependFile, $wafFile)) {
            return $this->fail(
                'prepend_loader_not_writable',
                sprintf(
                    /* translators: %s: safe prepend loader path */
                    __('DPXL Shield could not create the safe prepend loader: %s', 'dpxl-shield'),
                    $prependFile
                ),
                ['snippet' => $this->manualSnippet($prependFile, $wafFile)]
            );
        }

        $serverBackup = null;
        $htaccessAttempted = false;
        $htaccessError = null;

        // First try the Wordfence-like .htaccess flow. On many LiteSpeed hosts
        // this works; on PHP-FPM/CGI it may be written correctly but ignored.
        if (ServerDetector::supportsHtaccess()) {
            $target = file_exists($htaccessPath) ? $htaccessPath : dirname($htaccessPath);

            if (is_writable($target)) {
                $htaccessAttempted = true;
                $original = file_exists($htaccessPath) ? (string) @file_get_contents($htaccessPath) : '';
                $block    = $this->buildHtaccessBlock($prependFile);
                $updated  = $this->injectManagedBlock($original, $block);
                $serverBackup = $this->createServerSideBackup($original);

                if ($this->writeFileAtomic($htaccessPath, $updated)) {
                    clearstatcache(true, $htaccessPath);
                    $verification = $this->verifyExtendedMode(3);

                    if (!empty($verification['active'])) {
                        update_option(self::STATUS_OPTION, 'htaccess');
                        delete_option(self::ERROR_OPTION);

                        return [
                            'success'             => true,
                            'active'              => true,
                            'method'              => 'htaccess',
                            'message'             => __('Extended Protection is active. The WAF is now loading before WordPress.', 'dpxl-shield'),
                            'server_backup'       => $serverBackup,
                            'prepend_loader_file' => $prependFile,
                            'htaccess_written'    => true,
                        ];
                    }

                    // The file was writable and the block was inserted, but the
                    // PHP handler ignored php_value. Restore the original file
                    // and continue with .user.ini automatically.
                    $htaccessError = $verification;
                    $this->writeFileAtomic($htaccessPath, $original);
                } else {
                    $htaccessError = [
                        'message' => __('DPXL Shield could not write the managed block to .htaccess. Trying .user.ini fallback.', 'dpxl-shield'),
                    ];
                }
            } else {
                $htaccessError = [
                    'message' => __('The .htaccess file is not writable. Trying .user.ini fallback.', 'dpxl-shield'),
                ];
            }
        }

        // Automatic fallback for LiteSpeed/PHP-FPM/CGI hosts such as Hostinger.
        // This writes auto_prepend_file to .user.ini at the WordPress root.
        $userIniResult = $this->enableUserIniFallback($prependFile, $wafFile, 6);

        if (!empty($userIniResult['success'])) {
            $message = !empty($userIniResult['active'])
                ? __('Extended Protection is active through .user.ini. The WAF is now loading before WordPress.', 'dpxl-shield')
                : __('The .user.ini fallback was written. Some hosts cache .user.ini for a few minutes; refresh this page shortly to confirm Extended Protection.', 'dpxl-shield');

            return [
                'success'             => true,
                'active'              => !empty($userIniResult['active']),
                'method'              => !empty($userIniResult['active']) ? 'user_ini' : 'user_ini_pending',
                'message'             => $message,
                'server_backup'       => $serverBackup,
                'prepend_loader_file' => $prependFile,
                'htaccess_attempted'  => $htaccessAttempted,
                'htaccess_error'      => $htaccessError,
                'user_ini_path'       => $userIniPath,
                'user_ini_written'    => true,
                'verification'        => $userIniResult['verification'] ?? null,
            ];
        }

        return $this->fail(
            'verification_failed',
            __('The .htaccess rule was ignored by the server and DPXL Shield could not enable the .user.ini fallback automatically. Use the manual configuration snippet.', 'dpxl-shield'),
            [
                'rolled_back'     => $htaccessAttempted,
                'server_backup'   => $serverBackup,
                'snippet'         => $this->manualSnippet($prependFile, $wafFile),
                'htaccess_error'  => $htaccessError,
                'user_ini_error'  => $userIniResult,
            ]
        );
    }

    /**
     * Disables Extended Protection and leaves a safe no-op wrapper behind.
     *
     * Leaving the no-op wrapper is intentional. If a host-level PHP config still
     * points to it, the site stays online and the WAF does not run after plugin
     * deactivation/uninstall.
     */
    public function disable(): array {
        $htaccessRemoved = $this->removeFromHtaccess();
        $phpIniRemoved   = $this->removeDirectiveFromFile(ABSPATH . 'php.ini');
        $userIniRemoved  = $this->removeDirectiveFromFile(ABSPATH . '.user.ini');
        $noopWritten     = $this->writeNoopPrependLoader($this->getPrependFile());

        delete_option(self::STATUS_OPTION);
        delete_option(self::ERROR_OPTION);

        return [
            'success'             => true,
            'active'              => false,
            'message'             => __('Extended Protection has been disabled. Managed server rules were removed where possible.', 'dpxl-shield'),
            'htaccess_removed'    => $htaccessRemoved,
            'php_ini_removed'     => $phpIniRemoved,
            'user_ini_removed'    => $userIniRemoved,
            'noop_loader_written' => $noopWritten,
            'prepend_loader_file' => $this->getPrependFile(),
        ];
    }

    /**
     * Used by deactivation/uninstall hooks. It must never break plugin removal.
     */
    public function cleanupForPluginRemoval(): array {
        try {
            return $this->disable();
        } catch (\Throwable $e) {
            update_option(self::ERROR_OPTION, [
                'success' => false,
                'active'  => false,
                'code'    => 'cleanup_failed',
                'message' => $e->getMessage(),
                'snippet' => $this->manualSnippet($this->getPrependFile(), $this->getWafFile()),
            ]);

            return [
                'success' => false,
                'active'  => false,
                'message' => $e->getMessage(),
            ];
        }
    }

    /**
     * True only when the current request proves that auto_prepend_file ran.
     */
    public function isActive(): bool {
        return defined('DPXL_SHIELD_EXTENDED_ACTIVE') || defined('DPXL_SHIELD_PREPEND_LOADED');
    }

    public function getMethod(): string {
        if ($this->isActive()) {
            return (string) get_option(self::STATUS_OPTION, 'auto_prepend_file');
        }

        return (string) get_option(self::STATUS_OPTION, 'inactive');
    }

    public function getStatus(): array {
        $backupInfo  = $this->getHtaccessBackupInfo();
        $prependFile = $this->getPrependFile();

        return [
            'active'                        => $this->isActive(),
            'configured_method'             => (string) get_option(self::STATUS_OPTION, ''),
            'method'                        => $this->getMethod(),
            'server'                        => ServerDetector::label(),
            'supports_htaccess'             => ServerDetector::supportsHtaccess(),
            'waf_file'                      => $this->getWafFile(),
            'prepend_loader_file'           => $prependFile,
            'prepend_loader_exists'         => file_exists($prependFile),
            'htaccess_path'                 => $this->getHtaccessPath(),
            'htaccess_exists'               => $backupInfo['exists'],
            'htaccess_writable'             => $backupInfo['writable'],
            'htaccess_backup_downloaded'    => $backupInfo['downloaded'],
            'htaccess_backup_downloaded_at' => $backupInfo['downloaded_at'],
            'user_ini_path'                  => $this->getUserIniPath(),
            'user_ini_exists'                => file_exists($this->getUserIniPath()),
            'user_ini_writable'              => is_writable(file_exists($this->getUserIniPath()) ? $this->getUserIniPath() : dirname($this->getUserIniPath())),
            'last_error'                    => get_option(self::ERROR_OPTION, null),
            'manual_snippet'                => $this->manualSnippet($prependFile, $this->getWafFile()),
        ];
    }

    public function getWafFile(): string {
        return wp_normalize_path(DPXL_SHIELD_PATH . 'dpxl-shield-waf.php');
    }

    public function getPrependFile(): string {
        return wp_normalize_path(ABSPATH . self::SAFE_PREPEND_FILENAME);
    }

    public function getHtaccessPath(): string {
        return wp_normalize_path(ABSPATH . '.htaccess');
    }

    public function getUserIniPath(): string {
        return wp_normalize_path(ABSPATH . '.user.ini');
    }

    public function hasDownloadedHtaccessBackup(): bool {
        return (string) get_option(self::BACKUP_OPTION, '') !== '';
    }

    public function markHtaccessBackupDownloaded(): void {
        update_option(self::BACKUP_OPTION, current_time('mysql', true));
    }

    public function getHtaccessBackupInfo(): array {
        $path   = $this->getHtaccessPath();
        $exists = file_exists($path);
        $target = $exists ? $path : dirname($path);

        return [
            'path'          => $path,
            'exists'        => $exists,
            'size'          => $exists ? (int) @filesize($path) : 0,
            'writable'      => is_writable($target),
            'downloaded'    => $this->hasDownloadedHtaccessBackup(),
            'downloaded_at' => get_option(self::BACKUP_OPTION, ''),
        ];
    }

    public function getDownloadFilename(): string {
        $host = wp_parse_url(home_url(), PHP_URL_HOST) ?: 'site';
        $host = sanitize_file_name((string) $host);

        return sprintf('%s-htaccess-backup-%s.txt', $host, gmdate('Ymd-His'));
    }

    public function getHtaccessDownloadContent(): string {
        $path = $this->getHtaccessPath();

        if (file_exists($path)) {
            return (string) @file_get_contents($path);
        }

        return "# No .htaccess file existed at the WordPress root when this backup was downloaded.\n"
            . "# DPXL Shield will create one if Extended Protection is enabled.\n";
    }

    // ── Prepend loader handling ────────────────────────────────────────────

    private function ensureActivePrependLoader(string $prependFile, string $wafFile): bool {
        return $this->writeFileAtomic($prependFile, $this->buildActivePrependLoader($wafFile));
    }

    private function writeNoopPrependLoader(string $prependFile): bool {
        return $this->writeFileAtomic($prependFile, $this->buildNoopPrependLoader());
    }

    private function buildActivePrependLoader(string $wafFile): string {
        $exportedWafFile = var_export($wafFile, true);

        return <<<PHP
<?php
/**
 * DPXL Shield safe prepend loader.
 *
 * This file is intentionally stored outside the plugin folder. The server's
 * auto_prepend_file directive points here instead of pointing directly to the
 * plugin directory. If DPXL Shield is deleted or unavailable, this loader no-ops
 * so the site does not break.
 */
if (!defined('DPXL_SHIELD_PREPEND_LOADED')) {
    define('DPXL_SHIELD_PREPEND_LOADED', true);
}

// The installer validates this header against a temporary PHP file, not the
// homepage, to avoid false negatives caused by page cache/CDN cache.
if (!headers_sent()) {
    header('X-DPXL-Shield-Prepend: active');
}

\$dpxlShieldWafFile = {$exportedWafFile};

if (is_string(\$dpxlShieldWafFile) && file_exists(\$dpxlShieldWafFile) && is_readable(\$dpxlShieldWafFile)) {
    require_once \$dpxlShieldWafFile;
}

return;
PHP;
    }

    private function buildNoopPrependLoader(): string {
        return <<<PHP
<?php
/**
 * DPXL Shield safe prepend loader disabled.
 *
 * This no-op file is kept intentionally. If an auto_prepend_file directive still
 * points here after deactivation or uninstall, the site remains online.
 */
return;
PHP;
    }

    // ── .htaccess handling ────────────────────────────────────────────────

    private function buildHtaccessBlock(string $prependFile): string {
        $line = '    php_value auto_prepend_file "' . $prependFile . '"' . "\n";

        return self::MARKER_BEGIN . "\n"
            // LiteSpeed commonly exposes <IfModule LiteSpeed>. The previous
            // version only checked lsapi_module, which can make the directive
            // silently skip on many LiteSpeed hosts.
            . '<IfModule LiteSpeed>' . "\n"
            . $line
            . '</IfModule>' . "\n"
            . '<IfModule lsapi_module>' . "\n"
            . $line
            . '</IfModule>' . "\n"
            . '<IfModule mod_php.c>' . "\n"
            . $line
            . '</IfModule>' . "\n"
            . '<IfModule mod_php5.c>' . "\n"
            . $line
            . '</IfModule>' . "\n"
            . '<IfModule mod_php7.c>' . "\n"
            . $line
            . '</IfModule>' . "\n"
            . '<IfModule mod_php8.c>' . "\n"
            . $line
            . '</IfModule>' . "\n"
            . self::MARKER_END . "\n";
    }

    private function injectManagedBlock(string $existing, string $block): string {
        $pattern = '/' . preg_quote(self::MARKER_BEGIN, '/') . '.*?' . preg_quote(self::MARKER_END, '/') . '\s*/s';

        if (preg_match($pattern, $existing)) {
            return (string) preg_replace($pattern, $block . "\n", $existing);
        }

        return $block . "\n" . ltrim($existing);
    }

    private function createServerSideBackup(string $content): ?string {
        $dir = wp_normalize_path(WP_CONTENT_DIR . '/dpxl-shield-backups');

        if (!wp_mkdir_p($dir)) {
            return null;
        }

        $file = $dir . '/htaccess-before-extended-' . gmdate('Ymd-His') . '.txt';

        if (!$this->writeFileAtomic($file, $content)) {
            return null;
        }

        return $file;
    }

    /**
     * Writes sensitive server config files as safely as possible.
     * This mirrors the WordPress/Wordfence expectation: if WordPress can update
     * permalinks, DPXL Shield should usually be able to update .htaccess too.
     */
    private function writeFileAtomic(string $path, string $content): bool {
        $dir = dirname($path);

        if (!is_dir($dir) || !is_writable(file_exists($path) ? $path : $dir)) {
            return false;
        }

        $temp = $path . '.dpxl-tmp-' . wp_generate_password(8, false, false);

        if (@file_put_contents($temp, $content, LOCK_EX) === false) {
            return false;
        }

        @chmod($temp, file_exists($path) ? (fileperms($path) & 0777) : 0644);

        if (@rename($temp, $path)) {
            clearstatcache(true, $path);
            return true;
        }

        @unlink($temp);

        if (@file_put_contents($path, $content, LOCK_EX) !== false) {
            clearstatcache(true, $path);
            return true;
        }

        return false;
    }

    private function verifyExtendedMode(int $attempts = 1): array {
        if ($this->isActive()) {
            return ['active' => true, 'message' => '', 'http_code' => 200];
        }

        if (!function_exists('wp_remote_get')) {
            return [
                'active'    => false,
                'message'   => __('WordPress HTTP API is unavailable, so DPXL Shield could not verify Extended Protection.', 'dpxl-shield'),
                'http_code' => null,
            ];
        }

        $attempts = max(1, min(8, $attempts));
        $lastResult = null;

        for ($i = 1; $i <= $attempts; $i++) {
            $testFile = $this->createLoopbackTestFile();
            if ($testFile === null) {
                return [
                    'active'    => false,
                    'message'   => __('DPXL Shield could not create a temporary PHP verification file in the WordPress root. Check file permissions.', 'dpxl-shield'),
                    'http_code' => null,
                ];
            }

            $url = add_query_arg(
                [
                    'dpxl_shield_waf_test' => '1',
                    'attempt'              => $i,
                    'nocache'              => wp_generate_password(12, false, false),
                ],
                home_url('/' . basename($testFile))
            );

            $response = wp_remote_get($url, [
                'timeout'     => 12,
                'redirection' => 0,
                'sslverify'   => false,
                'headers'     => [
                    'Cache-Control' => 'no-cache, no-store, max-age=0',
                    'Pragma'        => 'no-cache',
                ],
            ]);

            @unlink($testFile);

            if (is_wp_error($response)) {
                $lastResult = [
                    'active'    => false,
                    'message'   => $response->get_error_message(),
                    'http_code' => null,
                    'url'       => $url,
                    'attempt'   => $i,
                ];
            } else {
                $extendedHeader = strtolower((string) wp_remote_retrieve_header($response, 'x-dpxl-shield-extended'));
                $prependHeader  = strtolower((string) wp_remote_retrieve_header($response, 'x-dpxl-shield-prepend'));
                $httpCode       = (int) wp_remote_retrieve_response_code($response);
                $body           = (string) wp_remote_retrieve_body($response);

                $bodyProvesPrepend = str_contains($body, 'DPXL_SHIELD_PREPEND=active')
                    || str_contains($body, 'DPXL_SHIELD_EXTENDED=active');

                if ($extendedHeader === 'active' || $prependHeader === 'active' || $bodyProvesPrepend) {
                    return ['active' => true, 'message' => '', 'http_code' => $httpCode, 'url' => $url, 'attempt' => $i];
                }

                $lastResult = [
                    'active'    => false,
                    'message'   => sprintf(
                        /* translators: %d: HTTP status code */
                        __('Loopback test completed with HTTP %d, but the DPXL Shield prepend marker was not detected. On LiteSpeed this usually means the <IfModule LiteSpeed> / php_value directive was ignored by the PHP handler or server cache served the response without PHP.', 'dpxl-shield'),
                        $httpCode
                    ),
                    'http_code' => $httpCode,
                    'url'       => $url,
                    'body'      => substr($body, 0, 500),
                    'attempt'   => $i,
                    'headers'   => [
                        'x-dpxl-shield-extended' => $extendedHeader,
                        'x-dpxl-shield-prepend'  => $prependHeader,
                    ],
                ];
            }

            if ($i < $attempts) {
                sleep(1);
            }
        }

        return $lastResult ?: [
            'active'    => false,
            'message'   => __('DPXL Shield could not verify Extended Protection.', 'dpxl-shield'),
            'http_code' => null,
        ];
    }

    private function createLoopbackTestFile(): ?string {
        $file = wp_normalize_path(ABSPATH . 'dpxl-shield-prepend-test-' . wp_generate_password(12, false, false) . '.php');

        $content = <<<'PHP'
<?php
header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-cache, no-store, max-age=0');
echo "DPXL_SHIELD_PREPEND=" . (defined('DPXL_SHIELD_PREPEND_LOADED') ? 'active' : 'inactive') . "\n";
echo "DPXL_SHIELD_EXTENDED=" . (defined('DPXL_SHIELD_EXTENDED_ACTIVE') ? 'active' : 'inactive') . "\n";
PHP;

        if (!$this->writeFileAtomic($file, $content)) {
            return null;
        }

        return $file;
    }

    private function removeFromHtaccess(): bool {
        $path = $this->getHtaccessPath();

        if (!file_exists($path)) {
            return true;
        }

        if (!is_writable($path)) {
            return false;
        }

        $content = (string) @file_get_contents($path);
        $pattern = '/' . preg_quote(self::MARKER_BEGIN, '/') . '.*?' . preg_quote(self::MARKER_END, '/') . '\s*/s';
        $new     = (string) preg_replace($pattern, '', $content);

        if ($new === $content) {
            return true;
        }

        return $this->writeFileAtomic($path, $new);
    }

    private function removeDirectiveFromFile(string $path): bool {
        if (!file_exists($path)) {
            return true;
        }

        if (!is_writable($path)) {
            return false;
        }

        $content = (string) @file_get_contents($path);
        $pattern = '/' . preg_quote(self::USER_INI_MARKER_BEGIN, '/') . '.*?' . preg_quote(self::USER_INI_MARKER_END, '/') . '\s*/s';
        $new = (string) preg_replace($pattern, '', $content);
        $new = (string) preg_replace('/^\s*auto_prepend_file\s*=\s*["\']?.*dpxl-shield-prepend\.php["\']?\s*\n?/mi', '', $new);

        if ($new === $content) {
            return true;
        }

        return $this->writeFileAtomic($path, ltrim($new));
    }

    private function enableUserIniFallback(string $prependFile, string $wafFile, int $verifyAttempts = 5): array {
        $path   = $this->getUserIniPath();
        $target = file_exists($path) ? $path : dirname($path);

        if (!is_writable($target)) {
            return [
                'success' => false,
                'active'  => false,
                'code'    => 'user_ini_not_writable',
                'message' => sprintf(
                    /* translators: %s: .user.ini path */
                    __('The .user.ini file is not writable or cannot be created: %s', 'dpxl-shield'),
                    $path
                ),
            ];
        }

        // Make sure the safe loader still points to the real WAF before writing
        // a server-level directive.
        if (!$this->ensureActivePrependLoader($prependFile, $wafFile)) {
            return [
                'success' => false,
                'active'  => false,
                'code'    => 'prepend_loader_not_writable',
                'message' => __('DPXL Shield could not create the safe prepend loader for the .user.ini fallback.', 'dpxl-shield'),
            ];
        }

        $original = file_exists($path) ? (string) @file_get_contents($path) : '';
        $updated  = $this->injectUserIniBlock($original, $prependFile);

        if (!$this->writeFileAtomic($path, $updated)) {
            return [
                'success' => false,
                'active'  => false,
                'code'    => 'user_ini_write_failed',
                'message' => __('DPXL Shield could not write the .user.ini fallback.', 'dpxl-shield'),
            ];
        }

        clearstatcache(true, $path);
        update_option(self::STATUS_OPTION, 'user_ini_pending');

        $verification = $this->verifyExtendedMode($verifyAttempts);

        if (!empty($verification['active'])) {
            update_option(self::STATUS_OPTION, 'user_ini');
            delete_option(self::ERROR_OPTION);

            return [
                'success'      => true,
                'active'       => true,
                'method'       => 'user_ini',
                'path'         => $path,
                'verification' => $verification,
            ];
        }

        // Do not roll back .user.ini on verification failure. Many hosts cache
        // .user.ini for a few minutes. Keeping it is safer and lets the next
        // request become active when the cache expires.
        update_option(self::ERROR_OPTION, [
            'success' => true,
            'active'  => false,
            'code'    => 'user_ini_pending',
            'message' => __('The .user.ini fallback was written, but the server has not applied it yet. Some hosts cache .user.ini for a few minutes.', 'dpxl-shield'),
            'path'    => $path,
        ]);

        return [
            'success'      => true,
            'active'       => false,
            'method'       => 'user_ini_pending',
            'path'         => $path,
            'verification' => $verification,
        ];
    }

    private function injectUserIniBlock(string $existing, string $prependFile): string {
        $block = self::USER_INI_MARKER_BEGIN . "\n"
            . 'auto_prepend_file = "' . $prependFile . '"' . "\n"
            . self::USER_INI_MARKER_END . "\n";

        $pattern = '/' . preg_quote(self::USER_INI_MARKER_BEGIN, '/') . '.*?' . preg_quote(self::USER_INI_MARKER_END, '/') . '\s*/s';

        if (preg_match($pattern, $existing)) {
            return (string) preg_replace($pattern, $block, $existing);
        }

        // Remove old unmanaged DPXL lines if any previous build added them.
        $existing = (string) preg_replace('/^\s*auto_prepend_file\s*=\s*["\']?.*dpxl-shield-prepend\.php["\']?\s*\n?/mi', '', $existing);

        return rtrim($existing) . "\n\n" . $block;
    }

    private function manualSnippet(string $prependFile, string $wafFile): string {
        $server = ServerDetector::detect();
        $activeLoader = $this->buildActivePrependLoader($wafFile);
        $userIniPath = $this->getUserIniPath();

        if ($server === ServerDetector::NGINX) {
            return <<<NGINX
# DPXL Shield manual fallback for Nginx / PHP-FPM
#
# 1) Create this file first:
# {$prependFile}

{$activeLoader}

# 2) Add this inside the PHP location block / fastcgi configuration:
fastcgi_param PHP_VALUE "auto_prepend_file={$prependFile}";

# Safety note:
# If DPXL Shield is removed, keep {$prependFile} as a no-op file or remove the
# fastcgi_param line before deleting the file.
NGINX;
        }

        return <<<HTACCESS
# DPXL Shield manual fallback
#
# 1) Create this file first:
# {$prependFile}

{$activeLoader}

# 2) Add this to the WordPress root .htaccess file:
# BEGIN DPXL Shield Extended Protection
<IfModule LiteSpeed>
    php_value auto_prepend_file "{$prependFile}"
</IfModule>
<IfModule lsapi_module>
    php_value auto_prepend_file "{$prependFile}"
</IfModule>
<IfModule mod_php.c>
    php_value auto_prepend_file "{$prependFile}"
</IfModule>
<IfModule mod_php5.c>
    php_value auto_prepend_file "{$prependFile}"
</IfModule>
<IfModule mod_php7.c>
    php_value auto_prepend_file "{$prependFile}"
</IfModule>
<IfModule mod_php8.c>
    php_value auto_prepend_file "{$prependFile}"
</IfModule>
# END DPXL Shield Extended Protection

# If your host uses PHP-FPM/CGI and .htaccess php_value is ignored,
# create or edit {$userIniPath} and add this instead.
# It may take a few minutes because PHP can cache .user.ini values:
; BEGIN DPXL Shield Extended Protection
auto_prepend_file = "{$prependFile}"
; END DPXL Shield Extended Protection

# Safety note:
# Do not point auto_prepend_file directly to the plugin folder.
# Use the safe loader above so the site does not go down if the plugin is deleted.
HTACCESS;
    }

    private function fail(string $code, string $message, array $extra = []): array {
        $result = array_merge([
            'success' => false,
            'active'  => false,
            'code'    => $code,
            'message' => $message,
        ], $extra);

        update_option(self::ERROR_OPTION, $result);

        return $result;
    }
}
