<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall\Rules;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

use DPXL\Shield\Firewall\Request;
use DPXL\Shield\Firewall\RuleResult;

class WordPressRule extends AbstractRule {

    public function getId(): string {
        return 'wp-001';
    }

    public function getPriority(): int {
        return 20;
    }

    public function evaluate(Request $request): RuleResult {
        // wp-001: Direct POST to xmlrpc.php (brute-force vector)
        if ($this->isXmlRpcAbuse($request)) {
            return $this->block('Direct XML-RPC abuse blocked', 'high');
        }

        // wp-002: User enumeration via ?author=N
        if ($this->isUserEnumeration($request)) {
            return $this->block('WordPress user enumeration blocked', 'medium');
        }

        // wp-003: PHP file upload attempt disguised as another type
        if ($this->isPhpUpload($request)) {
            return $this->block('PHP file upload attempt blocked', 'critical');
        }

        // wp-004: Direct access to sensitive WordPress files
        if ($this->isSensitiveFileAccess($request)) {
            return $this->block('Access to sensitive file blocked', 'high');
        }

        return RuleResult::pass();
    }

    private function isXmlRpcAbuse(Request $request): bool {
        return str_contains($request->uri, 'xmlrpc.php')
            && $request->method === 'POST';
    }

    private function isUserEnumeration(Request $request): bool {
        if ($request->method !== 'GET') {
            return false;
        }

        // Matches /?author=1 or /index.php?author=2 etc.
        return isset($request->get['author'])
            && is_numeric($request->get['author']);
    }

    private function isPhpUpload(Request $request): bool {
        if ($request->method !== 'POST' || empty($_FILES)) {
            return false;
        }

        foreach ($_FILES as $file) {
            $name = is_array($file['name']) ? $file['name'] : [$file['name']];

            foreach ($name as $filename) {
                if (preg_match('/\.(php[0-9]?|phtml|phar|php-s|shtml)$/i', (string) $filename)) {
                    return true;
                }
            }

            // Also check MIME type mismatch.
            $type = is_array($file['type']) ? $file['type'] : [$file['type']];

            foreach ($type as $mime) {
                if (str_contains((string) $mime, 'php')) {
                    return true;
                }
            }
        }

        return false;
    }

    private function isSensitiveFileAccess(Request $request): bool {
        $patterns = [
            '/wp-config\.php/i',
            '/wp-config-sample\.php/i',
            '/\.env$/i',
            '/\.htpasswd/i',
            '/\/\.git\//i',
            '/\/\.svn\//i',
            '/phpinfo\.php/i',
            '/readme\.html/i',
            '/license\.txt/i',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $request->uri)) {
                return true;
            }
        }

        return false;
    }
}
