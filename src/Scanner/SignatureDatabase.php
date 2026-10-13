<?php
declare(strict_types=1);

namespace DPXL\Shield\Scanner;

/**
 * Malware signature database.
 *
 * Phase 2 ships with an inline MVP set. Phase 5 will pull an updated
 * binary-compressed set from the DPXL Shield API via cron.
 */
class SignatureDatabase {

    private array $signatures = [];
    private bool  $loaded     = false;

    public function __construct() {
        $this->load();
    }

    /**
     * Scan file content against all loaded signatures.
     *
     * @return array{id:string,name:string,severity:string}|null  matched signature or null
     */
    /**
     * @param string $extension Lowercase extension of the file being scanned.
     *                          Signatures carrying `applies_to` only run against
     *                          the file types they were written for.
     */
    public function match(string $content, string $extension = ''): ?array {
        if ($content === '') {
            return null;
        }

        // Truncate to 2 MB before regex to prevent ReDoS on huge files.
        $content = substr($content, 0, 2_097_152);

        foreach ($this->signatures as $sig) {
            if (!self::appliesTo($sig, $extension)) {
                continue;
            }

            if ($this->matchesSig($content, $sig)) {
                return [
                    'id'       => $sig['id'],
                    'name'     => $sig['name'],
                    'severity' => $sig['severity'],
                ];
            }
        }

        return null;
    }

    public function count(): int {
        return count($this->signatures);
    }

    /**
     * Whether a signature is meant for this file type.
     *
     * Most signatures describe code and run everywhere. A few describe a file
     * *format* being abused, and running those outside that format is not a
     * weaker check — it is a different, wrong one. `sig-php-in-img` is the case
     * that proved it: written for a polyglot image, applied to .php files, it
     * matched any PHP file mentioning "gif" or "png" near an opening tag, which
     * includes WordPress core and every library that reads images.
     *
     * @param array<string,mixed> $sig
     */
    private static function appliesTo(array $sig, string $extension): bool {
        $scope = $sig['applies_to'] ?? null;

        if (!is_array($scope) || $scope === []) {
            return true;
        }

        // No extension supplied: the caller is not file-scoped, so a
        // format-specific signature cannot be judged. Skip it rather than guess.
        return $extension !== '' && in_array($extension, $scope, true);
    }

    /**
     * A `regex_all` signature carries `patterns` instead of `pattern` and matches
     * only when every one of them is found, in any order. It exists for the case
     * where each half is ordinary code and only the combination is evidence:
     * matching a single half flags the plugins that do that half for a living.
     */
    private function matchesSig(string $content, array $sig): bool {
        $type = (string) ($sig['type'] ?? '');

        if ($type === 'regex_all') {
            $patterns = $sig['patterns'] ?? [];

            if (!is_array($patterns) || $patterns === []) {
                return false;
            }

            foreach ($patterns as $pattern) {
                if (@preg_match((string) $pattern, $content) !== 1) {
                    return false;
                }
            }

            return true;
        }

        $pattern = (string) ($sig['pattern'] ?? '');

        if ($pattern === '') {
            return false;
        }

        if ($type === 'regex') {
            return @preg_match($pattern, $content) === 1;
        }

        return str_contains($content, $pattern);
    }

    private function load(): void {
        if ($this->loaded) {
            return;
        }

        $this->signatures = $this->mvpSignatures();
        $this->loaded     = true;
    }

    /** @return list<array{id:string,name:string,type:string,pattern?:string,patterns?:list<string>,severity:string}> */
    private function mvpSignatures(): array {
        return [
            // ── Well-known webshells ──────────────────────────────────────
            [
                'id'       => 'sig-wso',
                'name'     => 'WSO Webshell',
                'type'     => 'string',
                'pattern'  => 'wso_ver',
                'severity' => 'critical',
            ],
            [
                'id'       => 'sig-c99',
                'name'     => 'C99 Webshell',
                'type'     => 'string',
                'pattern'  => 'c99_buff_prepare',
                'severity' => 'critical',
            ],
            [
                'id'       => 'sig-r57',
                'name'     => 'R57 Shell',
                'type'     => 'string',
                'pattern'  => 'r57shell',
                'severity' => 'critical',
            ],
            [
                'id'       => 'sig-b374k',
                'name'     => 'b374k Shell',
                'type'     => 'string',
                'pattern'  => 'b374k',
                'severity' => 'critical',
            ],

            // ── Backdoors via user input ──────────────────────────────────
            [
                'id'       => 'sig-shell-get',
                'name'     => 'Shell exec via user input ($_GET/$_POST)',
                'type'     => 'regex',
                'pattern'  => '/(?:passthru|shell_exec|system|exec)\s*\(\s*(?:base64_decode\s*\(|\$_(?:GET|POST|REQUEST|COOKIE))/i',
                'severity' => 'critical',
            ],

            // ── Obfuscated eval payloads ──────────────────────────────────
            [
                'id'       => 'sig-eval-b64',
                'name'     => 'eval(base64_decode) with long payload',
                'type'     => 'regex',
                'pattern'  => '/eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(\s*[\'"][A-Za-z0-9+\/=]{100,}[\'"]\s*\)\s*\)/i',
                'severity' => 'critical',
            ],
            [
                'id'       => 'sig-preg-e',
                'name'     => 'preg_replace /e modifier (code execution)',
                'type'     => 'regex',
                'pattern'  => '/preg_replace\s*\(\s*["\'][^"\']*\/e["\'\s,]/i',
                'severity' => 'critical',
            ],
            [
                'id'       => 'sig-assert-b64',
                'name'     => 'assert(base64_decode) backdoor',
                'type'     => 'regex',
                'pattern'  => '/assert\s*\(\s*(?:base64_decode|gzinflate|str_rot13)\s*\(/i',
                'severity' => 'critical',
            ],

            // ── WordPress-specific injectors ──────────────────────────────
            [
                'id'       => 'sig-wp-spam-inject',
                'name'     => 'WordPress spam wp_head injector',
                'type'     => 'regex',
                'pattern'  => '/add_action\s*\(\s*[\'"]wp_head[\'"]\s*,\s*(?:create_function|\$[a-z_]+)\s*\(/i',
                'severity' => 'high',
            ],
            // Opening registration is a setting, not an attack: every plugin
            // with a "disable registration" switch writes this option, and a
            // login-page customizer flipping it back to 1 was reported as a
            // malware signature on two installs for months. What a backdoor
            // does, and a settings screen never does, is open registration
            // *and* hardcode administrator as the role new accounts get. Both
            // halves are required, in either order.
            [
                'id'       => 'sig-wp-open-registration-admin-role',
                'name'     => 'Registration opened with administrator as the default role',
                'type'     => 'regex_all',
                'patterns' => [
                    '/(?:update|add)_option\s*\(\s*[\'"]users_can_register[\'"]\s*,\s*(?:1|true|[\'"]1[\'"])\s*\)/i',
                    '/(?:update|add)_option\s*\(\s*[\'"]default_role[\'"]\s*,\s*[\'"]administrator[\'"]\s*\)/i',
                ],
                'severity' => 'high',
            ],
            [
                'id'       => 'sig-wp-admin-create',
                'name'     => 'Remote admin creation script',
                'type'     => 'regex',
                'pattern'  => '/wp_create_user.*wp_new_user_notification.*add_user_to_blog/is',
                'severity' => 'critical',
            ],

            // ── Skimmers ──────────────────────────────────────────────────
            [
                'id'       => 'sig-skimmer-js',
                'name'     => 'JavaScript card skimmer pattern',
                'type'     => 'regex',
                'pattern'  => '/document\.forms.*\.(?:cardnumber|cc_number|credit_card|card-number).*(?:XMLHttpRequest|fetch)\s*\(/is',
                'severity' => 'critical',
            ],

            // ── Hex / encoding evasion ────────────────────────────────────
            [
                'id'       => 'sig-hex-payload',
                'name'     => 'Encoded payload near execution function',
                'type'     => 'regex',
                'pattern'  => '/(?:eval|assert|base64_decode|gzinflate|str_rot13).{0,250}(?:\\\\x[0-9a-f]{2}){40,}/is',
                'severity' => 'medium',
            ],

            // ── PHP in image headers ──────────────────────────────────────
            [
                'id'         => 'sig-php-in-img',
                'name'       => 'PHP code embedded in image file',
                'type'       => 'regex',
                // Anchored near the start: a polyglot hides PHP in the header
                // area of a real image. Unanchored, this matched any mention of
                // an image format anywhere in a file.
                'pattern'    => '/\A.{0,2048}?<\?php/s',
                'severity'   => 'critical',
                // Only meaningful inside something claiming to BE an image.
                'applies_to' => ['gif', 'jpg', 'jpeg', 'jpe', 'png', 'webp', 'bmp', 'ico', 'tif', 'tiff'],
            ],

            // ── Dynamic function dispatch ─────────────────────────────────
            [
                'id'       => 'sig-globals-dispatch',
                'name'     => 'Dynamic function call via $GLOBALS with user input',
                'type'     => 'regex',
                'pattern'  => '/\$GLOBALS\s*\[\s*["\'][^"\']+["\']\s*\]\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i',
                'severity' => 'critical',
            ],
        ];
    }
}
