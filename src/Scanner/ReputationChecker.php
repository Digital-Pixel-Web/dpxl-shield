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
        $ips    = $this->resolveSiteIps($domain);
        $ip     = implode(', ', $ips);

        $results = [
            'google_safe_browsing' => $this->checkGoogleSafeBrowsing($domain),
            'spamhaus_dbl'         => $this->checkSpamhausDbl($domain),
            'spamhaus_zen'         => $this->checkSpamhausZenAll($ips),
        ];

        $anyListed = array_filter($results, fn ($r) => $r['listed']);
        $clean     = empty($anyListed);

        // Checks that could not run are reported as their own state. Folding
        // them into "clean" would claim the site was verified when nothing was.
        $unavailable = array_filter($results, fn ($r) => ($r['status'] ?? '') === 'unavailable');

        $report = [
            'clean'       => $clean,
            'checked_at'  => gmdate('c'),
            'results'     => $results,
            'unavailable' => array_keys($unavailable),
        ];

        update_option(self::CACHE_OPTION, $report, false);

        if (!$clean) {
            $listed = implode(', ', array_keys($anyListed));

            do_action('dpxl_shield_alert', [
                'level'       => 'critical',
                'event_type'  => 'fw.reputation_hit',
                'description' => "Site {$domain} is listed in: {$listed}.",
                'context'     => [
                    'domain' => $domain,
                    'ip'     => $ip,
                    // One readable line per check. Passing the raw nested array
                    // here rendered as "Array, Array, Array" in the email.
                    'results' => array_map(
                        fn ($name, $r) => "{$name}: {$r['detail']}",
                        array_keys($results),
                        $results
                    ),
                ],
            ]);
        }

        return $report;
    }

    // ── Google Safe Browsing ───────────────────────────────────────────────

    /** @return array{listed: bool, detail: string} */
    private function checkGoogleSafeBrowsing(string $domain): array {
        $apiKey = Options::get('google_safe_browsing_key', '');

        if (empty($apiKey)) {
            return ['listed' => false, 'status' => 'unavailable', 'detail' => 'API key not configured'];
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
            return ['listed' => false, 'status' => 'unavailable', 'detail' => 'API error'];
        }

        $body   = json_decode(wp_remote_retrieve_body($response), true);
        $listed = !empty($body['matches']);

        return [
            'listed' => $listed,
            'status' => $listed ? 'listed' : 'clean',
            'detail' => $listed ? implode(', ', array_unique(array_column($body['matches'], 'threatType'))) : 'Clean',
        ];
    }

    // ── Spamhaus ──────────────────────────────────────────────────────────

    /**
     * Spamhaus answers "you are listed" and "I refused your query" the same
     * way — with an A record in 127.0.0.0/8. Only the address tells them apart:
     *
     *   127.0.0.0/24    ZEN listings (SBL, CSS, XBL, PBL)
     *   127.0.1.0/24    DBL listings (spam, phish, malware, botnet C&C)
     *   127.255.255.0/24 error codes, NOT listings:
     *                     .252 typing error in the DNSBL name
     *                     .254 anonymous query through a public resolver
     *                     .255 query volume exceeded / blocked
     *
     * Counting any answer as a listing is therefore wrong in the one case that
     * matters most: a host whose upstream DNS Spamhaus classes as a public
     * resolver gets .254 for *every* lookup, so every domain on that server
     * reads as listed, permanently. google.com and a domain that does not even
     * exist both come back "listed".
     *
     * Hence a third state. "Unavailable" must never raise the alarm and must
     * never be quietly folded into "clean" either — a reputation check that
     * cannot run is something the site owner needs told, not hidden.
     *
     * @param  list<string> $addresses  A records returned for the lookup.
     * @param  string       $listingPrefix  '127.0.1.' for DBL, '127.0.0.' for ZEN.
     * @return array{listed: bool, status: string, detail: string}
     */
    public static function interpret(array $addresses, string $listingPrefix, string $listName): array {
        $codes = array_values(array_filter($addresses));

        if ($codes === []) {
            return ['listed' => false, 'status' => 'clean', 'detail' => 'Clean'];
        }

        $listings = array_filter($codes, fn ($ip) => strpos($ip, $listingPrefix) === 0);

        if ($listings !== []) {
            return [
                'listed' => true,
                'status' => 'listed',
                'detail' => sprintf('Listed in %s (%s)', $listName, implode(', ', $listings)),
            ];
        }

        // Anything else in the 127.x space is Spamhaus telling us the query did
        // not run — most often 127.255.255.254 from a shared host's resolver.
        return [
            'listed' => false,
            'status' => 'unavailable',
            'detail' => sprintf(
                'Check unavailable — %s refused the query (%s). A public DNS resolver cannot query Spamhaus; this needs the host\'s own resolver or a Spamhaus DQS key.',
                $listName,
                implode(', ', $codes)
            ),
        ];
    }

    /** @return array{listed: bool, status: string, detail: string} */
    private function checkSpamhausDbl(string $domain): array {
        $result = @dns_get_record($domain . '.dbl.spamhaus.org', DNS_A);

        if ($result === false) {
            return ['listed' => false, 'status' => 'unavailable', 'detail' => 'DNS error'];
        }

        return self::interpret(array_column($result, 'ip'), '127.0.1.', 'Spamhaus DBL');
    }

    /** @return array{listed: bool, status: string, detail: string} */
    private function checkSpamhausZen(string $ip): array {
        // Reverse the IP octets for DNS blacklist lookup.
        $reversed = implode('.', array_reverse(explode('.', $ip)));
        $result   = @dns_get_record($reversed . '.zen.spamhaus.org', DNS_A);

        if ($result === false) {
            return ['listed' => false, 'status' => 'unavailable', 'detail' => 'DNS error'];
        }

        return self::interpret(array_column($result, 'ip'), '127.0.0.', 'Spamhaus ZEN');
    }

    /**
     * ZEN across every address the domain resolves to. One listed address is
     * enough to flag the site; a verdict is only reachable if at least one
     * lookup actually ran.
     *
     * @param  list<string> $ips
     * @return array{listed: bool, status: string, detail: string}
     */
    private function checkSpamhausZenAll(array $ips): array {
        if ($ips === []) {
            return ['listed' => false, 'status' => 'unavailable', 'detail' => 'IP not resolved'];
        }

        $perIp = [];

        foreach ($ips as $ip) {
            $perIp[$ip] = $this->checkSpamhausZen($ip);
        }

        return self::combineZen($perIp);
    }

    /**
     * Folds the per-address ZEN results into one verdict.
     *
     * One listed address flags the site. Otherwise the result is only "clean"
     * if at least one lookup actually ran — if every address came back refused,
     * nothing was verified and saying "clean" would be a lie.
     *
     * @param  array<string, array{listed: bool, status: string, detail: string}> $perIp
     * @return array{listed: bool, status: string, detail: string}
     */
    public static function combineZen(array $perIp): array {
        if ($perIp === []) {
            return ['listed' => false, 'status' => 'unavailable', 'detail' => 'IP not resolved'];
        }

        $details = [];
        $anyRan  = false;

        foreach ($perIp as $ip => $result) {
            if ($result['listed']) {
                return [
                    'listed' => true,
                    'status' => 'listed',
                    'detail' => "{$ip} — {$result['detail']}",
                ];
            }

            $anyRan    = $anyRan || ($result['status'] ?? '') === 'clean';
            $details[] = "{$ip}: {$result['detail']}";
        }

        return [
            'listed' => false,
            'status' => $anyRan ? 'clean' : 'unavailable',
            'detail' => implode(' | ', $details),
        ];
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    /**
     * Every A record for the domain, not just the first.
     *
     * Sites behind round-robin DNS or a CDN answer with several addresses.
     * Taking `$records[0]` checked one of them, and which one varied between
     * runs because resolvers rotate the order — so an address could sit on a
     * blocklist and go unreported for days, then surface at random.
     *
     * @return list<string>
     */
    private function resolveSiteIps(string $domain): array {
        $records = @dns_get_record($domain, DNS_A);

        if (empty($records)) {
            return [];
        }

        $ips = array_filter(array_column($records, 'ip'));

        return array_values(array_unique($ips));
    }
}
