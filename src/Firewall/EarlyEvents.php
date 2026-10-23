<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

use DPXL\Shield\Core\EarlyConfig;

/**
 * Hands what the pre-WordPress firewall did over to WordPress.
 *
 * Extended Protection blocks before WordPress — and its database — exists. So a
 * request stopped there was neither banned (IpBlocklist::blockIp() needs $wpdb)
 * nor logged: the attacker could keep trying, and Live Traffic and the dashboard
 * never saw the attack. The same attack in basic mode earned a one-hour ban.
 *
 * The early layer now appends one line per event to data/early-events.php, and
 * the next request that loads WordPress imports them: bans go through
 * IpBlocklist::blockIp(), blocks become traffic-log rows. From then on the
 * banned IP is stopped by the database blocklist, and — once the blocklist
 * snapshot is rewritten — before WordPress too.
 *
 * The file starts with `<?php exit;` so a web server that ignores the data/
 * .htaccess (nginx) runs it instead of serving it. It is capped in size so a
 * flood of blocked requests cannot fill the disk.
 */
final class EarlyEvents {

    private const HEADER    = "<?php exit; ?>\n";
    private const MAX_BYTES = 1048576;   // 1 MB, roughly 4,000 events
    private const MAX_FIELD = 500;

    private function __construct() {}

    public static function path(): string {
        return EarlyConfig::dataDir() . '/early-events.php';
    }

    /** A ban the early layer could not write. $duration null or <= 0 = permanent. */
    public static function queueBan(string $ip, string $reason, string $source, ?int $duration): void {
        self::append([
            'kind'     => 'ban',
            'ip'       => $ip,
            'reason'   => $reason,
            'source'   => $source,
            'duration' => $duration,
        ]);
    }

    /** A request the early layer answered with 403. */
    public static function queueBlock(Request $request, string $ruleId): void {
        self::append([
            'kind'   => 'block',
            'ip'     => $request->ip,
            'method' => $request->method,
            'uri'    => $request->uri,
            'query'  => $request->queryString,
            'ua'     => $request->userAgent,
            'ref'    => $request->referer,
            'rule'   => $ruleId,
        ]);
    }

    /**
     * Takes every queued event out of the file. The file is renamed first, so
     * two requests importing at once never process the same event twice.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function drain(): array {
        $path = self::path();

        if (!is_file($path)) {
            return [];
        }

        $claimed = $path . '.' . getmypid() . '.' . mt_rand() . '.tmp';

        if (!@rename($path, $claimed)) {
            return [];
        }

        $lines = @file($claimed, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        @unlink($claimed);

        if (!is_array($lines)) {
            return [];
        }

        $events = [];

        foreach ($lines as $line) {
            $event = json_decode($line, true);

            if (is_array($event) && isset($event['kind'], $event['ip'])
                && filter_var((string) $event['ip'], FILTER_VALIDATE_IP) !== false) {
                $events[] = $event;
            }
        }

        return $events;
    }

    /** @param array<string,mixed> $event */
    private static function append(array $event): void {
        $path = self::path();
        $dir  = dirname($path);

        if (!is_dir($dir) && !@mkdir($dir, 0755, true)) {
            return;
        }

        clearstatcache(true, $path);
        $size = is_file($path) ? (int) @filesize($path) : 0;

        if ($size >= self::MAX_BYTES) {
            return;
        }

        $event['ts'] = time();

        foreach ($event as $key => $value) {
            if (is_string($value) && strlen($value) > self::MAX_FIELD) {
                $event[$key] = substr($value, 0, self::MAX_FIELD);
            }
        }

        $line = json_encode($event, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);

        if ($line === false) {
            return;
        }

        $handle = @fopen($path, 'ab');

        if ($handle === false) {
            return;
        }

        if (flock($handle, LOCK_EX)) {
            $stat = fstat($handle);
            $now  = is_array($stat) ? (int) $stat['size'] : $size;

            if ($now === 0) {
                fwrite($handle, self::HEADER);
            }

            if ($now < self::MAX_BYTES) {
                fwrite($handle, $line . "\n");
            }

            fflush($handle);
            flock($handle, LOCK_UN);
        }

        fclose($handle);
    }
}
