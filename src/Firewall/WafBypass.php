<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

/**
 * Which requests may skip the WAF rules, decided from the request *path*.
 *
 * Two holes this replaces:
 *
 *  1. The checks used str_contains() on REQUEST_URI, which includes the query
 *     string. `/?s=<payload>&x=/wp-admin/` therefore "was" an admin request and
 *     skipped every rule and the blocklist. Only the path is looked at now.
 *
 *  2. /wp-admin/admin-ajax.php and /wp-admin/admin-post.php were bypassed as
 *     "admin", but both serve anonymous visitors (the `nopriv` actions) and are
 *     where most plugin vulnerabilities are exploited. They are filtered unless
 *     the visitor is really logged in.
 *
 * "Really logged in" cannot be known before WordPress loads: a cookie named
 * `wordpress_logged_in_*` is trivially forged. So the pre-WordPress layer only
 * *defers* such requests, and the in-WordPress layer validates the cookie with
 * wp_validate_auth_cookie() before letting them through.
 *
 * Pure functions, no WordPress dependency.
 */
final class WafBypass {

    private function __construct() {}

    /** Path component of a REQUEST_URI, lower-cased, without query or fragment. */
    public static function path(string $uri): string {
        // Absolute-form request targets ("http://host/path") are rare but legal.
        if (preg_match('#^[a-z][a-z0-9+.-]*://#i', $uri) === 1) {
            $uri = (string) parse_url($uri, PHP_URL_PATH);
        }

        // Cut by hand rather than parse_url(): it reads "//wp-admin/x" as a
        // host named wp-admin and gives up on some malformed URIs entirely.
        $path = explode('#', explode('?', $uri, 2)[0], 2)[0];

        $path = rawurldecode($path);

        // Collapse duplicate slashes so "//wp-admin//admin-ajax.php" is seen for what it is.
        $path = (string) preg_replace('#/{2,}#', '/', $path);

        return strtolower($path);
    }

    /**
     * wp-admin screens other than the two endpoints that also serve anonymous
     * visitors. Page builders POST raw HTML/CSS/JS from these screens, which
     * trips the XSS/SQLi rules — the reason the bypass exists at all.
     */
    public static function isAdminScreen(string $uri): bool {
        $path = self::path($uri);

        if (!str_contains($path, '/wp-admin/')) {
            return false;
        }

        return !self::isPublicAdminEndpoint($uri);
    }

    /** admin-ajax.php / admin-post.php: reachable without logging in. */
    public static function isPublicAdminEndpoint(string $uri): bool {
        $path = self::path($uri);

        return str_ends_with($path, '/wp-admin/admin-ajax.php')
            || str_ends_with($path, '/wp-admin/admin-post.php');
    }

    public static function isLoginScreen(string $uri): bool {
        return str_ends_with(self::path($uri), '/wp-login.php');
    }

    /** REST API (pretty or ?rest_route=) and admin-ajax / admin-post. */
    public static function isAuthenticatedApi(string $uri): bool {
        if (self::isPublicAdminEndpoint($uri)) {
            return true;
        }

        if (str_contains(self::path($uri), '/wp-json/')) {
            return true;
        }

        $query = explode('?', $uri, 2)[1] ?? '';
        parse_str(explode('#', $query, 2)[0], $params);

        return isset($params['rest_route']);
    }

    /** @param array<string,mixed> $cookies */
    public static function hasLoginCookie(array $cookies): bool {
        foreach ($cookies as $name => $value) {
            if (str_starts_with((string) $name, 'wordpress_logged_in_') && is_string($value) && $value !== '') {
                return true;
            }
        }

        return false;
    }

    /**
     * Pre-WordPress layer: requests that must not be judged here and are left
     * to the in-WordPress layer, which can tell a real session from a forged
     * cookie. Nothing is ever *skipped* on the strength of a cookie alone.
     *
     * @param array<string,mixed> $cookies
     */
    public static function shouldDeferEarly(string $uri, array $cookies): bool {
        if (self::isAdminScreen($uri) || self::isLoginScreen($uri)) {
            return true;
        }

        return self::isAuthenticatedApi($uri) && self::hasLoginCookie($cookies);
    }

    /**
     * In-WordPress layer: whether the rules are skipped, given whether the
     * visitor holds a *validated* login session.
     */
    public static function shouldBypassForUser(string $uri, bool $validatedUser): bool {
        if (!$validatedUser) {
            return false;
        }

        return self::isAdminScreen($uri) || self::isAuthenticatedApi($uri);
    }
}
