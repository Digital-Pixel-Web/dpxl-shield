<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

/**
 * Record of the requests the pre-WordPress firewall blocks.
 *
 * Extended Protection answers a blocked request before WordPress loads, so
 * there is no $wpdb to write the Live Traffic row and the block used to leave
 * no trace at all: a false positive that cost a site a month of form leads went
 * unnoticed because of it. The loader now appends one JSON line per block to a
 * small file in data/, and the next request that loads WordPress moves those
 * lines into the traffic log, where they show up like any other block.
 *
 * The file is PHP that exits on its first line and data/ is closed to the web,
 * so its contents (IPs, URLs) are not readable from outside. Values are JSON
 * encoded with `<` and `>` escaped, so nothing in a request can ever produce
 * an opening PHP tag in it.
 */
class EarlyBlockLog {

    public const FILENAME = 'early-blocks.php';

    /** Above this size new blocks are dropped until the file is imported. */
    private const MAX_BYTES = 1048576;

    /** Rows imported per request; the newest are kept when there are more. */
    private const MAX_IMPORT = 500;

    private const HEADER = "<?php exit; ?>\n";

    /** Appends a block to the file. Pure PHP: runs before WordPress loads. */
    public static function record(string $dataDir, Request $request, RuleResult $result): bool {
        if ($dataDir === '' || !is_dir($dataDir)) {
            return false;
        }

        $path = $dataDir . '/' . self::FILENAME;

        clearstatcache(true, $path);

        if (is_file($path) && (int) @filesize($path) > self::MAX_BYTES) {
            return false;
        }

        $line = json_encode(
            [
                't'      => time(),
                'ip'     => substr($request->ip, 0, 45),
                'method' => substr($request->method, 0, 10),
                'uri'    => substr($request->uri, 0, 2000),
                'query'  => substr($request->queryString, 0, 1000),
                'ua'     => substr($request->userAgent, 0, 500),
                'ref'    => substr($request->referer, 0, 500),
                'rule'   => substr($result->ruleId, 0, 50),
                'field'  => substr($result->field, 0, 64),
                'reason' => substr($result->reason, 0, 200),
            ],
            JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR
        );

        if (!is_string($line) || $line === '') {
            return false;
        }

        $handle = @fopen($path, 'ab');

        if ($handle === false) {
            return false;
        }

        $ok = false;

        if (@flock($handle, LOCK_EX)) {
            $stat   = fstat($handle);
            $prefix = (is_array($stat) && (int) $stat['size'] === 0) ? self::HEADER : '';
            $ok     = @fwrite($handle, $prefix . $line . "\n") !== false;
            @fflush($handle);
            @flock($handle, LOCK_UN);
        }

        @fclose($handle);

        return $ok;
    }

    /**
     * Parses the file's lines into entries, oldest first. Lines that are not
     * valid entries are skipped.
     *
     * @return list<array<string,mixed>>
     */
    public static function readEntries(string $path): array {
        $raw = is_file($path) ? @file_get_contents($path) : false;

        if (!is_string($raw) || $raw === '') {
            return [];
        }

        $entries = [];

        foreach (explode("\n", $raw) as $line) {
            if ($line === '' || $line[0] !== '{') {
                continue;
            }

            $entry = json_decode($line, true);

            if (is_array($entry) && isset($entry['t'], $entry['ip'], $entry['rule'])) {
                $entries[] = $entry;
            }
        }

        return $entries;
    }

    /**
     * Moves the recorded blocks into the traffic log. Needs WordPress; costs a
     * single stat call when nothing was recorded.
     *
     * @return int Rows imported.
     */
    public static function import(string $dataDir): int {
        global $wpdb;

        $path = $dataDir . '/' . self::FILENAME;

        if (!is_file($path) || !$wpdb instanceof \wpdb) {
            return 0;
        }

        // Claimed by renaming, so two requests never import the same lines and
        // the loader starts a fresh file for blocks that arrive meanwhile.
        $claimed = $dataDir . '/early-blocks.import-' . bin2hex(random_bytes(6)) . '.php';

        if (!@rename($path, $claimed)) {
            return 0;
        }

        $entries = self::readEntries($claimed);
        @unlink($claimed);

        if ($entries === [] || !\DPXL\Shield\Core\Options::get('traffic_log_enabled', true)) {
            return 0;
        }

        $entries    = array_slice($entries, -self::MAX_IMPORT);
        $table      = $wpdb->prefix . 'dpxl_shield_traffic_log';
        $classifier = new \DPXL\Shield\Traffic\TrafficClassifier();
        $imported   = 0;

        foreach (array_chunk($entries, 100) as $chunk) {
            $rows   = [];
            $values = [];

            foreach ($chunk as $e) {
                $ip  = (string) $e['ip'];
                $ua  = (string) ($e['ua'] ?? '');

                // FROM_UNIXTIME uses the session time zone, like the column's
                // CURRENT_TIMESTAMP default that every other row gets.
                $rows[] = '(FROM_UNIXTIME(%d), %s, %s, %s, %s, 403, %s, %s, \'block\', %s, %s, %d, %s)';
                array_push(
                    $values,
                    (int) $e['t'],
                    $ip,
                    (string) ($e['method'] ?? 'GET'),
                    (string) ($e['uri'] ?? '/'),
                    (string) ($e['query'] ?? ''),
                    $ua,
                    (string) ($e['ref'] ?? ''),
                    (string) $e['rule'],
                    (string) ($e['field'] ?? ''),
                    $classifier->isBot($ua, $ip) ? 1 : 0,
                    (string) (CountryBlocker::resolveCountry($ip) ?? '')
                );
            }

            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $sql = "INSERT INTO {$table}
                (timestamp, ip, method, uri, query_string, status_code, user_agent, referer, waf_action, waf_rule_id, waf_field, is_bot, country)
                VALUES " . implode(', ', $rows);

            if ($wpdb->query($wpdb->prepare($sql, ...$values)) !== false) {
                $imported += count($chunk);
            }
        }

        return $imported;
    }
}
