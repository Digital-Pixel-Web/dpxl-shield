<?php
declare(strict_types=1);

namespace DPXL\Shield\Threat;

use DPXL\Shield\Core\Options;

/**
 * Auto-installs and keeps the MaxMind GeoLite2 Country database fresh, so
 * geolocation works on every install with no manual upload.
 *
 * Wordfence ships geo data automatically; so do we — through the same signed
 * feed. Digital Pixel holds one MaxMind account, publishes the gzipped .mmdb as
 * a release asset, and lists it in the signed manifest. This updater downloads
 * it, verifies the SHA-256 against that manifest (whose signature the plugin
 * already trusts), gunzips, and writes it atomically. The daily check also keeps
 * the database under MaxMind's 30-day freshness rule automatically.
 *
 * The DB is a ~9 MB binary, so — unlike the JSON feed — it is never bundled in
 * the plugin zip nor committed to git; it lives only as a release asset and on
 * each site's disk after download.
 */
class GeoDbUpdater {

    private const MAX_DB_BYTES = 33554432; // 32 MB (compressed download ceiling)
    private const MIN_DB_BYTES = 100000;   // a real GeoLite2 DB is several MB
    private const MAXMIND_MARKER = "\xab\xcd\xefMaxMind.com";

    public const OK              = 'ok';
    public const NO_CHANGE       = 'no_change';
    public const DISABLED        = 'disabled';
    public const NO_PUBKEY       = 'no_pubkey';
    public const NET_FAIL        = 'net_fail';
    public const BAD_MANIFEST    = 'bad_manifest';
    public const SIG_FAIL        = 'sig_fail';
    public const NO_GEO          = 'no_geo';
    public const HASH_FAIL       = 'hash_fail';
    public const DECOMPRESS_FAIL = 'decompress_fail';
    public const BAD_DB          = 'bad_db';
    public const WRITE_FAIL      = 'write_fail';

    private string $manifestUrl;
    private string $publicKeyB64;
    private string $dbPath;

    public function __construct(
        ?string $manifestUrl = null,
        ?string $publicKeyB64 = null,
        ?string $dbPath = null
    ) {
        $configured = (string) Options::get('threat_feed_url', '');

        $this->manifestUrl  = $manifestUrl ?? ($configured !== '' ? $configured : ThreatFeedUpdater::DEFAULT_MANIFEST_URL);
        $this->publicKeyB64 = $publicKeyB64 ?? FeedVerifier::defaultPublicKey();
        $this->dbPath       = $dbPath ?? ((defined('DPXL_SHIELD_PATH') ? DPXL_SHIELD_PATH : '') . 'data/GeoLite2-Country.mmdb');
    }

    /** Runs the update. Returns one of the status constants. */
    public function run(): string {
        if (!Options::get('geo_db_enabled', true)) {
            return $this->finish(self::DISABLED);
        }

        if (!FeedVerifier::isAvailable() || $this->publicKeyB64 === '') {
            return $this->finish(self::NO_PUBKEY);
        }

        return $this->finish($this->update());
    }

    private function update(): string {
        $rawManifest = $this->fetch($this->manifestUrl, 3);

        if ($rawManifest === null) {
            return self::NET_FAIL;
        }

        $manifest = json_decode($rawManifest, true);

        if (!is_array($manifest) || !is_string($manifest['signature'] ?? null)) {
            return self::BAD_MANIFEST;
        }

        // Same trust chain as the rules feed: verify the manifest signature, then
        // trust the SHA-256 it pins for each artifact.
        if (!FeedVerifier::verify(ThreatFeedUpdater::signedPayload($manifest), (string) $manifest['signature'], $this->publicKeyB64)) {
            return self::SIG_FAIL;
        }

        $artifact = $manifest['artifacts']['geo_db'] ?? null;
        if (!is_array($artifact) || !is_string($artifact['url'] ?? null) || !is_string($artifact['sha256'] ?? null)) {
            return self::NO_GEO;
        }

        // Anti-redundancy: skip the multi-MB download when we already have this DB.
        if ($artifact['sha256'] === (string) Options::get('geo_db_sha', '') && is_file($this->dbPath)) {
            return self::NO_CHANGE;
        }

        $gz = $this->fetch((string) $artifact['url'], 5);
        if ($gz === null) {
            return self::NET_FAIL;
        }

        if (strlen($gz) > self::MAX_DB_BYTES) {
            return self::BAD_DB;
        }

        if (!FeedVerifier::sha256Matches($gz, (string) $artifact['sha256'])) {
            return self::HASH_FAIL;
        }

        $mmdb = @gzdecode($gz);
        if ($mmdb === false || $mmdb === '') {
            return self::DECOMPRESS_FAIL;
        }

        // Sanity: it must actually look like a MaxMind DB before we trust it on disk.
        if (strlen($mmdb) < self::MIN_DB_BYTES || !str_contains($mmdb, self::MAXMIND_MARKER)) {
            return self::BAD_DB;
        }

        if (!AtomicFile::write($this->dbPath, $mmdb)) {
            AtomicFile::rollback($this->dbPath);
            return self::WRITE_FAIL;
        }

        Options::set('geo_db_sha', (string) $artifact['sha256']);
        Options::set('geo_db_version', (string) ($artifact['db_version'] ?? ''));

        return self::OK;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /** GET a URL (binary-safe); returns the raw body, or null on failure/non-200. */
    private function fetch(string $url, int $redirection): ?string {
        $response = wp_remote_get($url, [
            'timeout'     => 30,
            'sslverify'   => true,
            'redirection' => $redirection,
            'user-agent'  => 'DPXL Shield GeoDb',
        ]);

        if (is_wp_error($response) || (int) wp_remote_retrieve_response_code($response) !== 200) {
            return null;
        }

        $body = (string) wp_remote_retrieve_body($response);

        return $body !== '' ? $body : null;
    }

    private function finish(string $status): string {
        Options::set('geo_db_last_status', $status);
        Options::set('geo_db_last_run', time());

        return $status;
    }
}
