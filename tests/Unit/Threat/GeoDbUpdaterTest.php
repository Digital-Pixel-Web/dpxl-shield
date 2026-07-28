<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Threat;

use Brain\Monkey;
use Brain\Monkey\Functions;
use DPXL\Shield\Threat\GeoDbUpdater;
use DPXL\Shield\Threat\ThreatFeedUpdater;
use PHPUnit\Framework\TestCase;

/**
 * Auto-download of the GeoLite2 database via the signed feed. Mirrors the rules
 * updater's guarantees for a large binary artifact: a valid, signed, hash-matching
 * gzip is decompressed and written; anything tampered, wrong, or absent leaves the
 * installed DB untouched. This is what makes geolocation work with zero manual
 * upload per site.
 */
class GeoDbUpdaterTest extends TestCase {

    private const MANIFEST_URL = 'https://feed.test/manifest.json';
    private const GEO_URL      = 'https://gh.test/GeoLite2-Country.mmdb.gz';
    private const MARKER       = "\xab\xcd\xefMaxMind.com";

    private string $secret;
    private string $publicB64;
    private string $dbPath;
    /** @var array<string,mixed> */
    private array $options = [];

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();

        if (!function_exists('sodium_crypto_sign_keypair')) {
            $this->markTestSkipped('ext-sodium not available.');
        }

        $pair            = sodium_crypto_sign_keypair();
        $this->secret    = sodium_crypto_sign_secretkey($pair);
        $this->publicB64 = base64_encode(sodium_crypto_sign_publickey($pair));
        $this->dbPath    = sys_get_temp_dir() . '/dpxl-geo-' . uniqid() . '.mmdb';
        $this->options   = [];
    }

    protected function tearDown(): void {
        @unlink($this->dbPath);
        @unlink($this->dbPath . '.bak');
        Monkey\tearDown();
        parent::tearDown();
    }

    private function stubOptions(): void {
        $store = &$this->options;
        Functions\when('get_option')->alias(function ($key, $default = false) use (&$store) {
            return $store[$key] ?? $default;
        });
        Functions\when('update_option')->alias(function ($key, $value) use (&$store) {
            $store[$key] = $value;
            return true;
        });
    }

    /** @param array<string,string> $urlToBody */
    private function stubNetwork(array $urlToBody): void {
        Functions\when('is_wp_error')->justReturn(false);
        Functions\when('wp_remote_get')->alias(fn($url, $args = []) => ['url' => $url]);
        Functions\when('wp_remote_retrieve_response_code')->alias(
            fn($resp) => isset($urlToBody[$resp['url'] ?? '']) ? 200 : 404
        );
        Functions\when('wp_remote_retrieve_body')->alias(fn($resp) => $urlToBody[$resp['url'] ?? ''] ?? '');
    }

    private function fakeMmdb(): string {
        return str_repeat('A', 200000) . self::MARKER;
    }

    /** @return array{manifest:string,gz:string} */
    private function makeFeed(string $gz): array {
        $manifest = [
            'schema'       => 1,
            'feed_version' => '2026.07.28',
            'artifacts'    => [
                'geo_db' => [
                    'url'        => self::GEO_URL,
                    'sha256'     => hash('sha256', $gz),
                    'size'       => strlen($gz),
                    'db_version' => '2026-07-24',
                ],
            ],
        ];

        $payload = ThreatFeedUpdater::signedPayload($manifest);
        $manifest['signature'] = base64_encode(sodium_crypto_sign_detached($payload, $this->secret));

        return ['manifest' => (string) json_encode($manifest), 'gz' => $gz];
    }

    private function updater(): GeoDbUpdater {
        return new GeoDbUpdater(self::MANIFEST_URL, $this->publicB64, $this->dbPath);
    }

    // ── Happy path ───────────────────────────────────────────────────────────

    public function testValidDatabaseIsDownloadedDecompressedAndWritten(): void {
        $this->stubOptions();
        $mmdb = $this->fakeMmdb();
        $feed = $this->makeFeed(gzencode($mmdb));
        $this->stubNetwork([self::MANIFEST_URL => $feed['manifest'], self::GEO_URL => $feed['gz']]);

        $this->assertSame(GeoDbUpdater::OK, $this->updater()->run());
        $this->assertSame($mmdb, file_get_contents($this->dbPath), 'The gunzipped DB is written to disk');
        $this->assertSame(hash('sha256', $feed['gz']), $this->options['dpxl_shield_geo_db_sha'] ?? '', 'Installed SHA is recorded for anti-redundancy');
    }

    // ── Integrity / safety ───────────────────────────────────────────────────

    public function testHashMismatchIsRejected(): void {
        $this->stubOptions();
        $feed = $this->makeFeed(gzencode($this->fakeMmdb()));
        // Serve a different gzip than the manifest's signed SHA-256 promises.
        $this->stubNetwork([self::MANIFEST_URL => $feed['manifest'], self::GEO_URL => gzencode('different bytes')]);

        $this->assertSame(GeoDbUpdater::HASH_FAIL, $this->updater()->run());
        $this->assertFileDoesNotExist($this->dbPath);
    }

    public function testCorruptGzipIsRejected(): void {
        $this->stubOptions();
        $notGzip = 'this-is-not-gzip-data';
        $manifest = [
            'schema' => 1, 'feed_version' => '2026.07.28',
            'artifacts' => ['geo_db' => ['url' => self::GEO_URL, 'sha256' => hash('sha256', $notGzip), 'size' => strlen($notGzip)]],
        ];
        $manifest['signature'] = base64_encode(sodium_crypto_sign_detached(ThreatFeedUpdater::signedPayload($manifest), $this->secret));
        $this->stubNetwork([self::MANIFEST_URL => (string) json_encode($manifest), self::GEO_URL => $notGzip]);

        $this->assertSame(GeoDbUpdater::DECOMPRESS_FAIL, $this->updater()->run());
        $this->assertFileDoesNotExist($this->dbPath);
    }

    public function testNonMaxmindPayloadIsRejected(): void {
        $this->stubOptions();
        // Valid gzip + hash, but the content isn't a MaxMind database.
        $feed = $this->makeFeed(gzencode(str_repeat('Z', 200000)));
        $this->stubNetwork([self::MANIFEST_URL => $feed['manifest'], self::GEO_URL => $feed['gz']]);

        $this->assertSame(GeoDbUpdater::BAD_DB, $this->updater()->run());
        $this->assertFileDoesNotExist($this->dbPath);
    }

    public function testAlreadyCurrentSkipsDownload(): void {
        $this->stubOptions();
        $feed = $this->makeFeed(gzencode($this->fakeMmdb()));
        // Pretend this DB is already installed.
        file_put_contents($this->dbPath, 'existing');
        $this->options['dpxl_shield_geo_db_sha'] = hash('sha256', $feed['gz']);
        $this->stubNetwork([self::MANIFEST_URL => $feed['manifest'], self::GEO_URL => $feed['gz']]);

        $this->assertSame(GeoDbUpdater::NO_CHANGE, $this->updater()->run());
        $this->assertSame('existing', file_get_contents($this->dbPath), 'The current DB is left untouched');
    }

    public function testManifestWithoutGeoArtifactIsNoOp(): void {
        $this->stubOptions();
        $manifest = ['schema' => 1, 'feed_version' => '2026.07.28', 'artifacts' => []];
        $manifest['signature'] = base64_encode(sodium_crypto_sign_detached(ThreatFeedUpdater::signedPayload($manifest), $this->secret));
        $this->stubNetwork([self::MANIFEST_URL => (string) json_encode($manifest)]);

        $this->assertSame(GeoDbUpdater::NO_GEO, $this->updater()->run());
    }

    public function testDisabledShortCircuits(): void {
        $this->stubOptions();
        $this->options['dpxl_shield_geo_db_enabled'] = false;

        $this->assertSame(GeoDbUpdater::DISABLED, $this->updater()->run());
    }
}
