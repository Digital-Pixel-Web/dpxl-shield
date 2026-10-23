<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall\Rules;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

use DPXL\Shield\Firewall\Request;
use DPXL\Shield\Firewall\WafBypass;
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

    /**
     * system.multicall packs hundreds of password guesses into one request,
     * which is what makes XML-RPC a brute-force vector. Every other XML-RPC
     * call is left to the rate limiter and the login lockout: blocking all of
     * them (and banning the IP for an hour) broke Jetpack, the WordPress mobile
     * apps and pingbacks while the settings said XML-RPC was on.
     */
    private function isXmlRpcAbuse(Request $request): bool {
        if (!str_ends_with(WafBypass::path($request->uri), '/xmlrpc.php') || $request->method !== 'POST') {
            return false;
        }

        $body = $request->rawBody;

        if (stripos($body, 'system.multicall') !== false) {
            return true;
        }

        // No XML-RPC client sends a DOCTYPE; it is only useful for entity tricks.
        if (stripos($body, '<!DOCTYPE') !== false) {
            return true;
        }

        // The XML parser decodes character references and CDATA before the
        // method is dispatched, so "&#115;ystem.multicall" or a CDATA section
        // slips past a plain text search. Compare the parsed method name.
        return self::xmlRpcMethodName($body) === 'system.multicall';
    }

    private static function xmlRpcMethodName(string $body): ?string {
        if (stripos($body, 'methodName') === false || !function_exists('simplexml_load_string')) {
            return null;
        }

        $previous = libxml_use_internal_errors(true);
        $xml      = simplexml_load_string($body, 'SimpleXMLElement', LIBXML_NONET);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        if ($xml === false) {
            return null;
        }

        // Like WordPress's IXR parser: any methodName element, the last one wins.
        $names = $xml->xpath('//methodName');

        if (!is_array($names) || $names === []) {
            return null;
        }

        return trim((string) end($names));
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
