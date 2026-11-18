<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall\Rules;

use DPXL\Shield\Firewall\Request;
use DPXL\Shield\Firewall\RuleResult;

/**
 * rfi-001: remote file inclusion.
 *
 * An RFI payload is a parameter whose whole value is a remote URL that the
 * vulnerable code hands to include(): `?page=http://evil.com/shell.txt?`.
 *
 * The rule used to match any URL with an `=` anywhere in it, in any field. Every
 * Elementor form posts the page address as `referrer`, so a visitor who arrived
 * from an ad (`/?utm_source=ig`) could not submit a form: the 403 swallowed the
 * lead and nothing showed in the logs. Now:
 *
 *  - the value must *start* with the URL (include() needs the scheme first), so
 *    a link inside a message is not a payload;
 *  - URLs on the site's own domain are never RFI;
 *  - fields that carry a URL by design (referrer, redirect_to, url…) are only
 *    blocked for an IP-literal host;
 *  - elsewhere the URL must look like remote code: a code/text file, a `.php`
 *    with no query, or the trailing `?` / null-byte tricks that neutralise a
 *    suffix the application appends.
 *
 * Stream wrappers (php://, data://, expect://…) are LfiRule's job.
 */
class RfiRule extends AbstractRule {

    /** Markers that are suspicious wherever they appear. */
    private const MARKERS = [
        '/%68%74%74%70/i',  // "http" still percent-encoded after decoding: double encoding
        '/RemoteFileInclusion/i',
        '/rfidemo/i',
    ];

    /**
     * Parameters that legitimately carry a full URL. Compared lower-case.
     * Form plugins, WordPress core and tracking scripts send these on ordinary
     * submissions; for them only an IP-literal host is treated as an attack.
     */
    private const URL_FIELDS = [
        'referrer', 'referer', 'http_referer', '_wp_http_referer', 'utm_referrer',
        'redirect', 'redirect_to', 'redirect_url', 'redirect_uri',
        'return', 'return_to', 'return_url', 'returnurl', 'ref', 'ref_url',
        'url', 'link', 'href', 'permalink', 'website', 'site', 'site_url', 'homepage',
        'page_url', 'pageurl', 'current_url', 'source_url', 'landing_page', 'landing_url',
        'page_location', 'document_location', 'document_referrer',
    ];

    /** Path endings that are code or text, never a page someone links to. */
    private const CODE_EXTENSION = '/\.(?:txt|inc|phtml|phar|sh|pl|py|cgi)$/i';

    /** A bare .php script — remote code when it carries no query. */
    private const PHP_EXTENSION = '/\.php\d?$/i';

    /**
     * The site's own hosts, normalised (lower-case, no port, no "www.").
     * Set by FirewallEngine from the early config / home_url().
     *
     * @var string[]
     */
    private static array $siteHosts = [];

    /** @param string[] $hosts Host names or URLs of the site itself. */
    public static function setSiteHosts(array $hosts): void {
        $normalised = [];

        foreach ($hosts as $host) {
            $host = (string) $host;

            if (str_contains($host, '://')) {
                $host = (string) parse_url($host, PHP_URL_HOST); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- runs before WordPress loads.
            }

            $host = self::normaliseHost($host);

            if ($host !== '') {
                $normalised[$host] = true;
            }
        }

        self::$siteHosts = array_keys($normalised);
    }

    /** @return string[] */
    public static function getSiteHosts(): array {
        return self::$siteHosts;
    }

    public function getId(): string {
        return 'rfi-001';
    }

    public function getPriority(): int {
        return 11;
    }

    public function evaluate(Request $request): RuleResult {
        $pairs = array_merge(
            $this->flattenNamedValues($request->get),
            $this->flattenNamedValues($request->post),
        );

        $siteHosts = self::$siteHosts;

        // Without a configured host list (config written by an older version),
        // the Host header is the best guess at the site's own domain.
        if ($siteHosts === [] && $request->host !== '') {
            $siteHosts = [self::normaliseHost($request->host)];
        }

        foreach ($pairs as [$name, $value]) {
            if ($this->matchesAny(self::MARKERS, $value)) {
                return $this->block('Remote File Inclusion attempt', 'high', $name);
            }

            $reason = $this->inspectUrl(trim($value), strtolower($name), $siteHosts);

            if ($reason !== null) {
                return $this->block($reason, 'high', $name);
            }
        }

        return RuleResult::pass();
    }

    /**
     * @param string[] $siteHosts
     * @return string|null Block reason, or null when the value is not an RFI payload.
     */
    private function inspectUrl(string $value, string $name, array $siteHosts): ?string {
        if (!preg_match('~^(?:https?|ftps?)://~i', $value)) {
            return null;
        }

        $value = substr($value, 0, 8192);
        $host  = self::hostOf($value);

        if ($host !== '' && self::isSiteHost($host, $siteHosts)) {
            return null;
        }

        // A URL pointing at a bare IP address dodges every hostname check and is
        // the usual shape of a payload served from a compromised box.
        if (filter_var(trim($host, '[]'), FILTER_VALIDATE_IP) !== false) {
            return 'Remote File Inclusion attempt (IP-literal URL)';
        }

        if (in_array($name, self::URL_FIELDS, true)) {
            return null;
        }

        // A URL whose host cannot even be parsed is not a link anyone shares.
        if ($host === '') {
            return 'Remote File Inclusion attempt (malformed URL)';
        }

        if (preg_match('~^ftps?://~i', $value)) {
            return 'Remote File Inclusion attempt (FTP URL)';
        }

        // Null byte or a trailing "?" cut off a suffix the application appends
        // (include($_GET['page'] . '.php')).
        if (str_contains($value, "\0") || stripos($value, '%00') !== false || str_ends_with($value, '?')) {
            return 'Remote File Inclusion attempt (suffix truncation)';
        }

        $path  = (string) parse_url($value, PHP_URL_PATH); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- runs before WordPress loads.
        $query = (string) parse_url($value, PHP_URL_QUERY); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- runs before WordPress loads.

        if ($this->matchesPattern(self::CODE_EXTENSION, $path)) {
            return 'Remote File Inclusion attempt (remote code file)';
        }

        if ($query === '' && $this->matchesPattern(self::PHP_EXTENSION, $path)) {
            return 'Remote File Inclusion attempt (remote PHP script)';
        }

        return null;
    }

    /** Host part of a URL, honouring user-info ("http://a.com@evil.com/"). '' when unparseable. */
    private static function hostOf(string $url): string {
        $host = @parse_url($url, PHP_URL_HOST); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- runs before WordPress loads.

        if (is_string($host) && $host !== '') {
            return self::normaliseHost($host);
        }

        if (preg_match('~^[a-z][a-z0-9+.-]*://(?:[^@/?#]*@)?(\[[^\]]*\]|[^:/?#]+)~i', $url, $m)) {
            return self::normaliseHost($m[1]);
        }

        return '';
    }

    /** @param string[] $siteHosts */
    private static function isSiteHost(string $host, array $siteHosts): bool {
        foreach ($siteHosts as $site) {
            if ($site === '') {
                continue;
            }

            // Subdomains of the site (lp.example.com) are the site too.
            if ($host === $site || str_ends_with($host, '.' . $site)) {
                return true;
            }
        }

        return false;
    }

    private static function normaliseHost(string $host): string {
        $host = strtolower(trim($host));

        // Strip a port, but not the colons of a bracketed IPv6 literal.
        if ($host !== '' && $host[0] !== '[' && substr_count($host, ':') === 1) {
            $host = (string) strstr($host, ':', true);
        }

        $host = rtrim($host, '.');

        return str_starts_with($host, 'www.') ? substr($host, 4) : $host;
    }
}
