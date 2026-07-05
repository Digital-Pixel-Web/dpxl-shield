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
    public function match(string $content): ?array {
        if ($content === '') {
            return null;
        }

        // Truncate to 2 MB before regex to prevent ReDoS on huge files.
        $content = substr($content, 0, 2_097_152);

        foreach ($this->signatures as $sig) {
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

    private function matchesSig(string $content, array $sig): bool {
        $pattern = $sig['pattern'] ?? '';

        if ($pattern === '') {
            return false;
        }

        if ($sig['type'] === 'regex') {
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

    /** @return list<array{id:string,name:string,type:string,pattern:string,severity:string}> */
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
            [
                'id'       => 'sig-wp-option-inject',
                'name'     => 'WordPress option manipulation (users_can_register)',
                'type'     => 'regex',
                'pattern'  => '/update_option\s*\(\s*[\'"]users_can_register[\'"]\s*,\s*1\s*\)/i',
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
                'id'       => 'sig-php-in-img',
                'name'     => 'PHP code embedded in image file header',
                'type'     => 'regex',
                'pattern'  => '/<\?php.{0,100}(?:GIF|JFIF|PNG|IHDR)/is',
                'severity' => 'critical',
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
