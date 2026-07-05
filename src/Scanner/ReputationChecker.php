<?php
declare(strict_types=1);

namespace DPXL\Shield\Scanner;

use DPXL\Shield\Core\Options;
use DPXL\Shield\Core\Logger;

/**
 * Checks whether the site's domain/IP appears in external blocklists.
 *
 * Checks performed:
 *   1. Google Safe Browsing API (requires free API key in settings)
 *   2. Spamhaus DBL (DNS lookup — no key needed)
 *   3. Spamhaus ZEN (DNS blacklist for site IP)
 *
 * Results cached for 24 h in wp_options.
 * Fires a CRITICAL alert if the site is listed anywhere.
 */
class ReputationChecker {

    private const CACHE_OPTION = 'dpxl_shield_reputation_cache';
    private const CACHE_TTL    = 86400; // 24 hours

    /**
     * @return array{
     *   clean: bool,
     *   checked_at: string,
     *   results: array<string, array{listed: bool, detail: string}>
     * }
     */
    public function run(): array {
        $cached = get_option(self::CACHE_OPTION);

        if (is_array($cached) && isset($cached['checked_at'])) {
            $age = time() - (int) strtotime($cached['checked_at']);

            if ($age < self::CACHE_TTL) {
                return $cached;
            }
        }

        $domain = (string) (parse_url(get_option('siteurl'), PHP_URL_HOST) ?? '');
        $ip     = $this->resolveSiteIp($domain);

        $results = [
            'google_safe_browsing' => $this->checkGoogleSafeBrowsing($domain),
            'spamhaus_dbl'         => $this->checkSpamhausDbl($domain),
            'spamhaus_zen'         => $ip ? $this->checkSpamhausZen($ip) : ['listed' => false, 'detail' => 'IP not resolved'],
        ];

        $anyListed = array_filter($results, fn ($r) => $r['listed']);
        $clean     = empty($anyListed);

        $report = [
            'clean'       => $clean,
            'checked_at'  => gmdate('c'),
            'results'     => $results,
        ];

        update_option(self::CACHE_OPTION, $report, false);

        if (!$clean) {
            $listed = implode(', ', array_keys($anyListed));

            do_action('dpxl_shield_alert', [
                'level'       => 'critical',
                'event_type'  => 'fw.reputation_hit',
                'description' => "Site {$domain} is listed in: {$listed}.",
                'context'     => ['domain' => $domain, 'ip' => $ip, 'results' => $results],
            ]);
        }

        return $report;
    }

    // ── Google Safe Browsing ───────────────────────────────────────────────

    /** @return array{listed: bool, detail: string} */
    private function checkGoogleSafeBrowsing(string $domain): array {
        $apiKey = Options::get('google_safe_browsing_key', '');

        if (empty($apiKey)) {
            return ['listed' => false, 'detail' => 'API key not configured'];
        }

        $url     = get_option('siteurl');
        $payload = wp_json_encode([
            'client'     => ['clientId' => 'dpxl-shield', 'clientVersion' => '1.0'],
            'threatInfo' => [
                'threatTypes'      => ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                'platformTypes'    => ['ANY_PLATFORM'],
                'threatEntryTypes' => ['URL'],
                'threatEntries'    => [['url' => $url]],
            ],
        ]);

        $response = wp_remote_post(
            'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . $apiKey,
            [
                'timeout' => 10,
                'headers' => ['Content-Type' => 'application/json'],
                'body'    => $payload,
            ]
        );

        if (is_wp_error($response)) {
            Logger::error('ReputationChecker: Google Safe Browsing error — ' . $response->get_error_message());
            return ['listed' => false, 'detail' => 'API error'];
        }

        $body   = json_decode(wp_remote_retrieve_body($response), true);
        $listed = !empty($body['matches']);

        return [
            'listed' => $listed,
            'detail' => $listed ? implode(', ', array_unique(array_column($body['matches'], 'threatType'))) : 'Clean',
        ];
    }

    // ── Spamhaus DBL ───────────────────────────────────────────────────────

    /** @return array{listed: bool, detail: string} */
    private function checkSpamhausDbl(string $domain): array {
        $lookup = $domain . '.dbl.spamhaus.org';

        // If DNS resolution returns any A record, the domain is listed.
        $result = @dns_get_record($lookup, DNS_A);

        if ($result === false) {
            return ['listed' => false, 'detail' => 'DNS error'];
        }

        $listed = !empty($result);

        return [
            'listed' => $listed,
            'detail' => $listed ? 'Listed in Spamhaus DBL' : 'Clean',
        ];
    }

    // ── Spamhaus ZEN ───────────────────────────────────────────────────────

    /** @return array{listed: bool, detail: string} */
    private function checkSpamhausZen(string $ip): array {
        // Reverse the IP octets for DNS blacklist lookup.
        $reversed = implode('.', array_reverse(explode('.', $ip)));
        $lookup   = $reversed . '.zen.spamhaus.org';

        $result = @dns_get_record($lookup, DNS_A);

        if ($result === false) {
            return ['listed' => false, 'detail' => 'DNS error'];
        }

        $listed = !empty($result);

        return [
            'listed' => $listed,
            'detail' => $listed ? 'Listed in Spamhaus ZEN' : 'Clean',
        ];
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private function resolveSiteIp(string $domain): ?string {
        $records = @dns_get_record($domain, DNS_A);

        if (empty($records)) {
            return null;
        }

        return (string) ($records[0]['ip'] ?? '');
    }
}
