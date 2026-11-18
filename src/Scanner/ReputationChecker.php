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

        $domain = (string) (wp_parse_url(get_option('siteurl'), PHP_URL_HOST) ?? '');
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
            // Deliberately off, not broken. Reporting it as unavailable would
            // put a permanent notice on every scan for an optional integration
            // nobody asked for.
            return ['listed' => false, 'status' => 'not_configured', 'detail' => 'API key not configured'];
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
     * A Data Query Service key, or '' when none is configured.
     *
     * Spamhaus refuses lookups that reach it through a public resolver, which
     * is what shared hosting typically uses — so on those hosts the free public
     * mirrors cannot answer at all. A DQS key (free tier available) gives the
     * site its own query zone and makes the checks work.
     */
    private static function dqsKey(): string {
        $key = trim((string) Options::get('spamhaus_dqs_key', ''));

        // Keys are 26 alphanumeric characters. Anything else is a paste error,
        // and sending it would put junk in a DNS name.
        return preg_match('/^[A-Za-z0-9]{26}$/', $key) === 1 ? $key : '';
    }

    /**
     * The zone to query, and whether it is the authenticated one.
     *
     * @return array{zone: string, authenticated: bool}
     */
    private static function zone(string $list): array {
        $key = self::dqsKey();

        return $key === ''
            ? ['zone' => "{$list}.spamhaus.org", 'authenticated' => false]
            : ['zone' => "{$key}.{$list}.dq.spamhaus.net", 'authenticated' => true];
    }

    /**
     * Reads a Spamhaus DNS answer.
     *
     * Spamhaus answers "listed" and "I refused your query" the same way — with
     * an A record in 127.0.0.0/8 — and only the address separates them:
     *
     *   127.0.0.0/16      a listing (127.0.0.x ZEN, 127.0.1.x DBL, 127.0.2.x ZRD)
     *   127.255.255.0/24  an error, NOT a listing. Most often .254,
     *                     "anonymous query through a public resolver".
     *   anything else     not a Spamhaus answer at all: a resolver that
     *                     hijacks NXDOMAIN and returns its own address. Reading
     *                     that as a listing would flag every site it touched.
     *
     * Counting any answer as a listing is what reported untouched sites as
     * blocklisted: on a host Spamhaus treats as a public resolver, every domain
     * came back listed, including ones that do not exist.
     *
     * Hence the third state. "Unavailable" must never raise the alarm, and must
     * never be folded into "clean" either — a check that could not run is
     * something the site owner needs told, not hidden.
     *
     * @param  list<string> $addresses  A records returned for the lookup.
     * @return array{listed: bool, status: string, detail: string}
     */
    public static function interpret(array $addresses, string $listName, bool $authenticated = false): array {
        $codes = array_values(array_filter($addresses));

        if ($codes === []) {
            return ['listed' => false, 'status' => 'clean', 'detail' => 'Clean'];
        }

        $listings = array_filter($codes, [self::class, 'isListingCode']);

        if ($listings !== []) {
            return [
                'listed' => true,
                'status' => 'listed',
                'detail' => sprintf('Listed in %s (%s)', $listName, implode(', ', $listings)),
            ];
        }

        $hijacked = array_filter($codes, static function (string $ip): bool {
            $long = ip2long($ip);

            return $long === false || ($long & 0xFF000000) !== (ip2long('127.0.0.0') & 0xFF000000);
        });

        if ($hijacked !== []) {
            return [
                'listed' => false,
                'status' => 'unavailable',
                'detail' => sprintf(
                    'Check unavailable — the DNS resolver answered %s instead of a %s result, so it is rewriting unknown names. The answer cannot be trusted either way.',
                    implode(', ', $hijacked),
                    $listName
                ),
            ];
        }

        $hint = $authenticated
            ? 'Verify the DQS key is active and cleared for this dataset.'
            : 'A public DNS resolver cannot query Spamhaus; configure a Spamhaus DQS key to enable this check.';

        return [
            'listed' => false,
            'status' => 'unavailable',
            'detail' => sprintf('Check unavailable — %s refused the query (%s). %s', $listName, implode(', ', $codes), $hint),
        ];
    }

    /**
     * Listings live in 127.0.0.0/16. Everything else inside 127/8 is an error
     * code, and anything outside it is not a Spamhaus answer at all.
     *
     * Compared as integers rather than by string prefix: "127.0." also prefixes
     * 127.01.2.3 and other odd-but-parseable forms, and a blocklist verdict is
     * the wrong place to be approximate.
     */
    private static function isListingCode(string $ip): bool {
        $long = ip2long($ip);

        if ($long === false) {
            return false;
        }

        return ($long & 0xFFFF0000) === (ip2long('127.0.0.0') & 0xFFFF0000);
    }

    /** @return array{listed: bool, status: string, detail: string} */
    private function checkSpamhausDbl(string $domain): array {
        $zone   = self::zone('dbl');
        $result = @dns_get_record($domain . '.' . $zone['zone'], DNS_A);

        if ($result === false) {
            return ['listed' => false, 'status' => 'unavailable', 'detail' => 'DNS error'];
        }

        return self::interpret(array_column($result, 'ip'), 'Spamhaus DBL', $zone['authenticated']);
    }

    /** @return array{listed: bool, status: string, detail: string} */
    private function checkSpamhausZen(string $ip): array {
        // Reverse the IP octets for DNS blacklist lookup.
        $reversed = implode('.', array_reverse(explode('.', $ip)));
        $zone     = self::zone('zen');
        $result   = @dns_get_record($reversed . '.' . $zone['zone'], DNS_A);

        if ($result === false) {
            return ['listed' => false, 'status' => 'unavailable', 'detail' => 'DNS error'];
        }

        return self::interpret(array_column($result, 'ip'), 'Spamhaus ZEN', $zone['authenticated']);
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
