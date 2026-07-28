<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall;

/**
 * Value object representing the current HTTP request.
 * Safe to instantiate before WordPress loads.
 *
 * Populated once in the constructor and never written to afterwards. The
 * properties are not marked `readonly` because that is PHP 8.1 and the plugin's
 * floor is 7.4 — treat them as read-only by convention.
 */
class Request {

    /** @var string */
    public $ip;

    /** @var string */
    public $method;

    /** @var string */
    public $uri;

    /** @var string */
    public $queryString;

    /** @var string */
    public $userAgent;

    /** @var string */
    public $referer;

    /** @var string */
    public $host;

    /** @var array */
    public $get;

    /** @var array */
    public $post;

    /** @var array */
    public $cookies;

    /** @var string */
    public $rawBody;

    public function __construct() {
        $this->ip          = $this->resolveIp();
        $this->method      = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
        $this->uri         = $_SERVER['REQUEST_URI'] ?? '/';
        $this->queryString = $_SERVER['QUERY_STRING'] ?? '';
        $this->userAgent   = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $this->referer     = $_SERVER['HTTP_REFERER'] ?? '';
        $this->host        = $_SERVER['HTTP_HOST'] ?? '';
        $this->get         = $_GET ?? [];
        $this->post        = $_POST ?? [];
        $this->cookies     = $_COOKIE ?? [];
        $this->rawBody     = (string) @file_get_contents('php://input');
    }

    /** Respects Cloudflare, load-balancer, and proxy headers in order of trust. */
    private function resolveIp(): string {
        $headers = [
            'HTTP_CF_CONNECTING_IP',  // Cloudflare
            'HTTP_X_REAL_IP',         // Nginx proxy
            'HTTP_X_FORWARDED_FOR',   // Generic proxy (first hop)
            'REMOTE_ADDR',
        ];

        foreach ($headers as $header) {
            $value = $_SERVER[$header] ?? '';

            if ($value === '') {
                continue;
            }

            // X-Forwarded-For may be a comma-separated list; take the first.
            $ip = trim(explode(',', $value)[0]);

            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $ip;
            }
        }

        // Fallback: accept any valid IP including private ranges.
        return filter_var($_SERVER['REMOTE_ADDR'] ?? '', FILTER_VALIDATE_IP) ?: '0.0.0.0';
    }

    /** Returns all GET + POST values as a flat merged array for rule evaluation. */
    public function getAllParams(): array {
        return array_merge($this->get, $this->post);
    }
}
