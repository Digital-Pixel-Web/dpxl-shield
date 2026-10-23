<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

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

    /**
     * Forwarding headers are believed only from a trusted proxy — see ClientIp.
     * Taking the first X-Forwarded-For entry at face value let any client pick
     * its own IP, and with it dodge lockouts or get someone else banned.
     */
    private function resolveIp(): string {
        return \DPXL\Shield\Core\ClientIp::current();
    }

    /** Returns all GET + POST values as a flat merged array for rule evaluation. */
    public function getAllParams(): array {
        return array_merge($this->get, $this->post);
    }
}
