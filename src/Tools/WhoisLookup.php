<?php
declare(strict_types=1);

namespace DPXL\Shield\Tools;

/**
 * Performs WHOIS lookups for any IP address or hostname.
 *
 * Strategy:
 *   1. If input is a hostname, resolve it to an IP first.
 *   2. Direct TCP socket to the appropriate WHOIS server (no API key needed).
 *   3. Fallback: ipinfo.io JSON endpoint (free tier, HTTPS, no key required).
 *
 * Results are cached for 1 hour per IP in transients to avoid hammering WHOIS servers.
 *
 * @return array{
 *   ip: string,
 *   input: string,
 *   org: string,
 *   asn: string,
 *   country: string,
 *   country_code: string,
 *   range: string,
 *   abuse: string,
 *   raw: string,
 *   source: string,
 *   error?: string,
 * }
 */
class WhoisLookup {

    private const CACHE_TTL    = 3600;
    private const SOCK_TIMEOUT = 4; // Reduced: port 43 is blocked on most shared hosts; fail fast.

    // WHOIS server by IP range (simplified — ARIN covers the rest).
    private const WHOIS_SERVERS = [
        'apnic'   => 'whois.apnic.net',
        'ripe'    => 'whois.ripe.net',
        'arin'    => 'whois.arin.net',
        'lacnic'  => 'whois.lacnic.net',
        'afrinic' => 'whois.afrinic.net',
    ];

    /**
     * @return array<string,string>
     */
    public function lookup(string $input): array {
        $input = trim($input);

        // Resolve hostname to IP if needed.
        if (filter_var($input, FILTER_VALIDATE_IP)) {
            $ip = $input;
        } else {
            // Strip scheme/path in case user pastes a URL.
            $host = (string) parse_url(
                str_contains($input, '://') ? $input : 'http://' . $input,
                PHP_URL_HOST
            );
            $host = $host ?: $input;

            // gethostbyname returns the original string unchanged on failure.
            $resolved = gethostbyname($host);

            if ($resolved === $host || !filter_var($resolved, FILTER_VALIDATE_IP)) {
                return $this->error($input, $input, 'invalid_ip', "Cannot resolve \"{$input}\" to an IP address.");
            }

            $ip = $resolved;
        }

        $cacheKey = 'dpxl_whois_' . md5($ip);
        $cached   = get_transient($cacheKey);

        if (is_array($cached)) {
            // Preserve the original input even on cache hit.
            $cached['input'] = $input;
            return $cached;
        }

        // Try direct WHOIS socket first.
        $result = $this->socketLookup($ip);

        if ($result === null) {
            // Fallback to ipinfo.io (free, HTTPS).
            $result = $this->ipinfoLookup($ip);
        }

        if ($result === null) {
            $result = $this->error($ip, $input, 'lookup_failed', 'Both WHOIS socket and ipinfo.io lookup failed. Check outbound connectivity.');
        }

        $result['input'] = $input;
        set_transient($cacheKey, $result, self::CACHE_TTL);

        return $result;
    }

    // ── Socket WHOIS ───────────────────────────────────────────────────────

    /** @return array<string,string>|null */
    private function socketLookup(string $ip): ?array {
        $server = $this->whoisServer($ip);
        $raw    = $this->rawWhois($ip, $server);

        if ($raw === null) {
            return null;
        }

        return [
            'ip'           => $ip,
            'org'          => $this->extractField($raw, ['OrgName', 'org', 'owner', 'descr']),
            'asn'          => $this->extractField($raw, ['OriginAS', 'origin', 'aut-num']),
            'country'      => $this->extractField($raw, ['Country', 'country']),
            'country_code' => strtoupper($this->extractField($raw, ['Country', 'country'])),
            'range'        => $this->extractField($raw, ['NetRange', 'inetnum', 'inet6num']),
            'abuse'        => $this->extractField($raw, ['OrgAbuseEmail', 'abuse-mailbox']),
            'raw'          => substr($raw, 0, 4000),
            'source'       => 'whois',
        ];
    }

    private function whoisServer(string $ip): string {
        // Very simplified region detection by first octet.
        $firstOctet = (int) explode('.', $ip)[0];

        // APNIC: 1-126 (partial), 175, 202-203, 210-211, 218-223
        if (in_array($firstOctet, range(202, 223), true) || in_array($firstOctet, [1, 27, 36, 42, 49, 58, 61, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 175, 180, 182, 183], true)) {
            return self::WHOIS_SERVERS['apnic'];
        }

        // RIPE: most of Europe/Middle East ranges 2, 5, 31, 37, 41, 46, 77-95, 176-195
        if ($firstOctet >= 77 && $firstOctet <= 95) {
            return self::WHOIS_SERVERS['ripe'];
        }

        // LACNIC: 177, 179, 181, 186-191, 200-201
        if (in_array($firstOctet, [177, 179, 181, 186, 187, 189, 190, 191, 200, 201], true)) {
            return self::WHOIS_SERVERS['lacnic'];
        }

        // Default to ARIN.
        return self::WHOIS_SERVERS['arin'];
    }

    private function rawWhois(string $ip, string $server): ?string {
        $socket = @fsockopen($server, 43, $errno, $errstr, self::SOCK_TIMEOUT);

        if (!$socket) {
            return null;
        }

        stream_set_timeout($socket, self::SOCK_TIMEOUT);
        fwrite($socket, "{$ip}\r\n");

        $response = '';
        while (!feof($socket)) {
            $chunk = fgets($socket, 4096);
            if ($chunk === false) {
                break;
            }
            $response .= $chunk;
        }

        fclose($socket);

        return $response !== '' ? $response : null;
    }

    // ── ipinfo.io fallback (free tier, HTTPS, no API key required) ────────

    /** @return array<string,string>|null */
    private function ipinfoLookup(string $ip): ?array {
        $response = wp_remote_get(
            "https://ipinfo.io/{$ip}/json",
            ['timeout' => 6, 'user-agent' => 'DPXL-Shield/1.0 (WordPress security plugin)']
        );

        if (is_wp_error($response)) {
            return null;
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);

        if (!is_array($body) || isset($body['error'])) {
            return null;
        }

        // ipinfo.io returns: ip, hostname, city, region, country, loc, org, postal, timezone
        $org = (string) ($body['org'] ?? '');
        // org field is like "AS13335 Cloudflare, Inc." — split ASN and name
        $asn = '';
        if (preg_match('/^(AS\d+)\s+(.+)$/', $org, $m)) {
            $asn = $m[1];
            $org = $m[2];
        }

        return [
            'ip'           => $ip,
            'org'          => $org,
            'asn'          => $asn,
            'country'      => (string) ($body['country'] ?? ''),
            'country_code' => strtoupper((string) ($body['country'] ?? '')),
            'range'        => '',
            'abuse'        => '',
            'raw'          => '',
            'source'       => 'ipinfo.io',
        ];
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    /** @param string[] $fields */
    private function extractField(string $raw, array $fields): string {
        foreach ($fields as $field) {
            if (preg_match('/^' . preg_quote($field, '/') . '\s*:\s*(.+)$/im', $raw, $m)) {
                return trim($m[1]);
            }
        }

        return '';
    }

    /** @return array<string,string> */
    private function error(string $ip, string $input, string $reason, string $message): array {
        return [
            'ip'           => $ip,
            'input'        => $input,
            'org'          => '',
            'asn'          => '',
            'country'      => '',
            'country_code' => '',
            'range'        => '',
            'abuse'        => '',
            'raw'          => '',
            'source'       => $reason,
            'error'        => $message,
        ];
    }
}
