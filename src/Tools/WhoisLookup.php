<?php
declare(strict_types=1);

namespace DPXL\Shield\Tools;

/**
 * Performs WHOIS lookups for any IP address.
 *
 * Strategy:
 *   1. Direct TCP socket to the appropriate WHOIS server (no API key needed).
 *   2. Fallback: ip-api.com JSON endpoint (free, no key, 45 req/min limit).
 *
 * Results are cached for 1 hour per IP in transients to avoid hammering WHOIS servers.
 *
 * @return array{
 *   ip: string,
 *   org: string,
 *   asn: string,
 *   country: string,
 *   country_code: string,
 *   range: string,
 *   abuse: string,
 *   raw: string,
 *   source: string,
 * }
 */
class WhoisLookup {

    private const CACHE_TTL   = 3600;
    private const SOCK_TIMEOUT = 8;

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
    public function lookup(string $ip): array {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return $this->empty($ip, 'invalid_ip');
        }

        $cacheKey = 'dpxl_whois_' . md5($ip);
        $cached   = get_transient($cacheKey);

        if (is_array($cached)) {
            return $cached;
        }

        // Try direct WHOIS first.
        $result = $this->socketLookup($ip);

        if ($result === null) {
            // Fallback to ip-api.com.
            $result = $this->ipApiLookup($ip);
        }

        if ($result === null) {
            $result = $this->empty($ip, 'lookup_failed');
        }

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

    // ── ip-api.com fallback ────────────────────────────────────────────────

    /** @return array<string,string>|null */
    private function ipApiLookup(string $ip): ?array {
        $response = wp_remote_get(
            "http://ip-api.com/json/{$ip}?fields=status,message,country,countryCode,org,as,query",
            ['timeout' => 6]
        );

        if (is_wp_error($response)) {
            return null;
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);

        if (!is_array($body) || ($body['status'] ?? '') !== 'success') {
            return null;
        }

        return [
            'ip'           => $ip,
            'org'          => (string) ($body['org']         ?? ''),
            'asn'          => (string) ($body['as']          ?? ''),
            'country'      => (string) ($body['country']     ?? ''),
            'country_code' => strtoupper((string) ($body['countryCode'] ?? '')),
            'range'        => '',
            'abuse'        => '',
            'raw'          => '',
            'source'       => 'ip-api',
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
    private function empty(string $ip, string $reason): array {
        return [
            'ip'           => $ip,
            'org'          => '',
            'asn'          => '',
            'country'      => '',
            'country_code' => '',
            'range'        => '',
            'abuse'        => '',
            'raw'          => '',
            'source'       => $reason,
        ];
    }
}
