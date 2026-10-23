<?php
declare(strict_types=1);

namespace DPXL\Shield\Core;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

/**
 * The one place that decides which IP address a request came from.
 *
 * Every security decision the plugin makes per IP — brute-force lockouts, the
 * rate limiter, the blocklist, honeypot bans, anomaly bans, API lockouts — is
 * only as good as this answer. Headers such as X-Forwarded-For and
 * CF-Connecting-IP are written by the client unless a proxy in front of the site
 * overwrites them, so trusting them blindly lets anyone:
 *
 *   - pick a fresh IP on every request and never hit a lockout or rate limit;
 *   - name someone else's IP (the site owner's) and get *that* address banned.
 *
 * So a forwarding header is believed only when the connection itself
 * (REMOTE_ADDR) comes from a proxy we have a reason to trust:
 *
 *   - CF-Connecting-IP, when REMOTE_ADDR is inside Cloudflare's published ranges;
 *   - X-Forwarded-For / X-Real-IP, when REMOTE_ADDR is a loopback or private
 *     address (a reverse proxy on the same host or network — nginx in front of
 *     Apache, a Docker ingress, a load balancer on a private network), or is in
 *     the site's own trusted-proxy list.
 *
 * Anything else falls back to REMOTE_ADDR, which the client cannot forge.
 *
 * Extra proxies (a CDN other than Cloudflare, a host's edge network) are added
 * with the DPXL_SHIELD_TRUSTED_PROXIES constant in wp-config.php — a comma-
 * separated list of IPs or CIDR ranges — or the `dpxl_shield_trusted_proxies`
 * filter.
 *
 * Pure and dependency-free so it can run before WordPress loads (Extended
 * Protection) and be unit-tested with plain arrays.
 */
final class ClientIp {

    /**
     * Cloudflare's published edge ranges (https://www.cloudflare.com/ips/).
     * They change rarely; a stale entry only means that edge's visitors are
     * seen as the edge IP, never that a forged header is believed.
     */
    private const CLOUDFLARE_RANGES = [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
        '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
    ];

    private function __construct() {}

    /** The client IP of the current request. */
    public static function current(): string {
        return self::resolve($_SERVER, self::configuredProxies());
    }

    /**
     * @param array<string,mixed> $server          Typically $_SERVER.
     * @param string[]            $trustedProxies  Extra proxy IPs / CIDR ranges.
     */
    public static function resolve(array $server, array $trustedProxies = []): string {
        $remote = trim((string) ($server['REMOTE_ADDR'] ?? ''));

        if (filter_var($remote, FILTER_VALIDATE_IP) === false) {
            return '0.0.0.0';
        }

        // Cloudflare overwrites CF-Connecting-IP on every request it proxies, so
        // the header is trustworthy exactly when the connection is from Cloudflare.
        if (self::inAnyRange($remote, self::CLOUDFLARE_RANGES)) {
            $cf = trim((string) ($server['HTTP_CF_CONNECTING_IP'] ?? ''));

            if (filter_var($cf, FILTER_VALIDATE_IP) !== false) {
                return $cf;
            }
        }

        if (!self::isTrustedProxy($remote, $trustedProxies)) {
            return $remote;
        }

        // X-Forwarded-For is appended to by each proxy: "client, proxy1, proxy2".
        // Only the right-hand entries were written by proxies we trust; the
        // left-most one is whatever the client sent. Walk from the right and
        // return the first address that is not itself a trusted proxy.
        $forwarded = (string) ($server['HTTP_X_FORWARDED_FOR'] ?? '');

        if ($forwarded !== '') {
            $hops = array_reverse(array_map('trim', explode(',', $forwarded)));

            foreach ($hops as $hop) {
                if (filter_var($hop, FILTER_VALIDATE_IP) === false) {
                    break;
                }

                if (!self::isTrustedProxy($hop, $trustedProxies)) {
                    return $hop;
                }
            }
        }

        $real = trim((string) ($server['HTTP_X_REAL_IP'] ?? ''));

        if (filter_var($real, FILTER_VALIDATE_IP) !== false) {
            return $real;
        }

        return $remote;
    }

    /**
     * @param string[] $ranges IPs or CIDR ranges, IPv4 or IPv6.
     */
    public static function inAnyRange(string $ip, array $ranges): bool {
        foreach ($ranges as $range) {
            if (self::inRange($ip, (string) $range)) {
                return true;
            }
        }

        return false;
    }

    /** IPv4 and IPv6 CIDR match. A range without a prefix is an exact IP. */
    public static function inRange(string $ip, string $range): bool {
        $range = trim($range);

        if ($range === '') {
            return false;
        }

        if (strpos($range, '/') === false) {
            $a = @inet_pton($ip);
            $b = @inet_pton($range);

            return $a !== false && $b !== false && $a === $b;
        }

        [$subnet, $bits] = explode('/', $range, 2);

        $ipBin     = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);

        if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
            return false;
        }

        if (!ctype_digit($bits)) {
            return false;
        }

        $bits     = (int) $bits;
        $maxBits  = strlen($ipBin) * 8;

        if ($bits < 0 || $bits > $maxBits) {
            return false;
        }

        $fullBytes = intdiv($bits, 8);
        $remainder = $bits % 8;

        if (strncmp($ipBin, $subnetBin, $fullBytes) !== 0) {
            return false;
        }

        if ($remainder === 0) {
            return true;
        }

        $mask = (0xFF << (8 - $remainder)) & 0xFF;

        return (ord($ipBin[$fullBytes]) & $mask) === (ord($subnetBin[$fullBytes]) & $mask);
    }

    /** @param string[] $trustedProxies */
    private static function isTrustedProxy(string $ip, array $trustedProxies): bool {
        // Loopback and private-network peers: a proxy on the same machine or LAN.
        // FILTER_FLAG_NO_PRIV_RANGE / NO_RES_RANGE reject exactly those.
        $isPublic = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;

        if (!$isPublic) {
            return true;
        }

        return self::inAnyRange($ip, $trustedProxies);
    }

    /** @return string[] */
    private static function configuredProxies(): array {
        $list = [];

        if (defined('DPXL_SHIELD_TRUSTED_PROXIES')) {
            $list = array_filter(array_map('trim', explode(',', (string) DPXL_SHIELD_TRUSTED_PROXIES)));
        }

        if (function_exists('apply_filters')) {
            $list = (array) apply_filters('dpxl_shield_trusted_proxies', $list);
        }

        return array_values(array_map('strval', $list));
    }
}
