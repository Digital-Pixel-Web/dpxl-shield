<?php
declare(strict_types=1);

namespace DPXL\Shield\Threat;

use DPXL\Shield\Core\Options;
use DPXL\Shield\Firewall\Rules\RuleRepository;

/**
 * Pulls the signed threat feed and applies it — the piece that turns the feed
 * repo into live protection without a plugin release.
 *
 * Flow: fetch manifest → verify Ed25519 signature over a deterministic payload →
 * reject anything not strictly newer (anti-rollback) → fetch each artifact →
 * verify SHA-256 against the signed manifest → write atomically. Any failure is
 * non-destructive: the currently installed feed stays in place and a status is
 * recorded. Nothing downloaded is ever executed — artifacts are parsed as data.
 *
 * v1 handles the `waf_rules` artifact only; `signatures` plugs in the same way.
 */
class ThreatFeedUpdater {

    /**
     * Stable manifest URL (branch ref); the manifest points artifacts at immutable tags.
     * A JSON data file served from the public rules repository, not an asset loaded in the browser.
     */
    public const DEFAULT_MANIFEST_URL =
        'https://cdn.jsdelivr.net/gh/Digital-Pixel-Web/dpxl-shield-rules@main/dist/manifest.json'; // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- server-side data download, see readme "External services".

    private const MAX_ARTIFACT_BYTES = 524288; // 512 KB
    private const LOCK_KEY           = 'dpxl_shield_threat_feed_lock';
    private const LOCK_TTL           = 300;

    // Status codes — also stored in the threat_feed_last_status option for the UI.
    public const OK           = 'ok';
    public const NO_CHANGE    = 'no_change';
    public const DISABLED     = 'disabled';
    public const LOCKED       = 'locked';
    public const NO_PUBKEY    = 'no_pubkey';
    public const NET_FAIL     = 'net_fail';
    public const BAD_MANIFEST = 'bad_manifest';
    public const SIG_FAIL     = 'sig_fail';
    public const INCOMPATIBLE = 'incompatible';
    public const HASH_FAIL    = 'hash_fail';
    public const BAD_ARTIFACT = 'bad_artifact';
    public const WRITE_FAIL   = 'write_fail';

    private string $manifestUrl;
    private string $publicKeyB64;
    private string $activePath;

    public function __construct(
        ?string $manifestUrl = null,
        ?string $publicKeyB64 = null,
        ?string $activePath = null
    ) {
        $configured = (string) Options::get('threat_feed_url', '');

        $this->manifestUrl  = $manifestUrl ?? ($configured !== '' ? $configured : self::DEFAULT_MANIFEST_URL);
        $this->publicKeyB64 = $publicKeyB64 ?? FeedVerifier::defaultPublicKey();
        $this->activePath   = $activePath ?? (\DPXL\Shield\Core\EarlyConfig::dataDir() . '/waf-rules.active.json');
    }

    /** Runs the update. Returns one of the status constants. */
    public function run(): string {
        if (!Options::get('threat_feed_enabled', true)) {
            return $this->finish(self::DISABLED);
        }

        if (!FeedVerifier::isAvailable() || $this->publicKeyB64 === '') {
            // No way to establish trust — never apply an unverifiable feed.
            return $this->finish(self::NO_PUBKEY);
        }

        if (get_transient(self::LOCK_KEY)) {
            return self::LOCKED; // another run in flight; don't touch status
        }

        set_transient(self::LOCK_KEY, 1, self::LOCK_TTL);

        try {
            return $this->finish($this->update());
        } finally {
            delete_transient(self::LOCK_KEY);
        }
    }

    // ── Core ───────────────────────────────────────────────────────────────

    private function update(): string {
        $rawManifest = $this->fetch($this->manifestUrl);

        if ($rawManifest === null) {
            return self::NET_FAIL;
        }

        $manifest = json_decode($rawManifest, true);

        if (!is_array($manifest) || !is_string($manifest['feed_version'] ?? null) || !is_string($manifest['signature'] ?? null)) {
            return self::BAD_MANIFEST;
        }

        // 1. Authenticity — signature over a deterministic payload of the manifest.
        if (!FeedVerifier::verify(self::signedPayload($manifest), (string) $manifest['signature'], $this->publicKeyB64)) {
            return self::SIG_FAIL;
        }

        // 2. Compatibility.
        $minPlugin = (string) ($manifest['min_plugin_version'] ?? '');
        if ($minPlugin !== '' && version_compare($this->pluginVersion(), $minPlugin, '<')) {
            return self::INCOMPATIBLE;
        }

        // 3. Anti-rollback — only apply a strictly newer feed. When the active
        // file is gone (fresh data folder, restored backup) the version already
        // recorded is accepted again, so the rules come back without waiting
        // for the next feed release — but nothing older ever is.
        $newVersion = (string) $manifest['feed_version'];
        $installed  = (string) Options::get('threat_feed_version', '');
        $reinstall  = !is_file($this->activePath) && $newVersion === $installed;
        if (!$reinstall && !FeedVerifier::isNewerVersion($newVersion, $installed)) {
            return self::NO_CHANGE;
        }

        // 4. Artifact: waf_rules (v1).
        $artifact = $manifest['artifacts']['waf_rules'] ?? null;
        if (!is_array($artifact) || !is_string($artifact['url'] ?? null) || !is_string($artifact['sha256'] ?? null)) {
            return self::BAD_MANIFEST;
        }

        $body = $this->fetch((string) $artifact['url']);
        if ($body === null) {
            return self::NET_FAIL;
        }

        if (strlen($body) > self::MAX_ARTIFACT_BYTES) {
            return self::BAD_ARTIFACT;
        }

        // 5. Integrity — hash must match the signed manifest.
        if (!FeedVerifier::sha256Matches($body, (string) $artifact['sha256'])) {
            return self::HASH_FAIL;
        }

        // 6. Sanity — must be JSON with a rules array before we trust it on disk.
        $decoded = json_decode($body, true);
        if (!is_array($decoded) || !is_array($decoded['rules'] ?? null)) {
            return self::BAD_ARTIFACT;
        }

        // 7. Atomic write; roll back on failure.
        if (!AtomicFile::write($this->activePath, $body)) {
            AtomicFile::rollback($this->activePath);
            return self::WRITE_FAIL;
        }

        Options::set('threat_feed_version', $newVersion);
        Options::set('waf_rules_version', $newVersion);
        RuleRepository::flushCache();

        return self::OK;
    }

    /**
     * Deterministic, canonicalisation-free payload the manifest signs. Built from
     * parsed fields (not raw JSON) so signer and verifier never disagree over key
     * order or whitespace. Signing this — which pins each artifact's SHA-256 —
     * transitively authenticates the artifacts.
     *
     * @param array<string,mixed> $manifest
     */
    public static function signedPayload(array $manifest): string {
        $lines = [
            'dpxl-shield-feed',
            'schema=' . (int) ($manifest['schema'] ?? 0),
            'feed_version=' . (string) ($manifest['feed_version'] ?? ''),
            'min_plugin_version=' . (string) ($manifest['min_plugin_version'] ?? ''),
        ];

        // Fixed artifact order; only those present are included. New artifacts go
        // at the end so a manifest without them yields the same payload as before.
        foreach (['waf_rules', 'signatures', 'geo_db'] as $name) {
            $artifact = $manifest['artifacts'][$name] ?? null;

            if (is_array($artifact)) {
                $lines[] = "artifact.$name.sha256=" . (string) ($artifact['sha256'] ?? '');
                $lines[] = "artifact.$name.size=" . (int) ($artifact['size'] ?? 0);
            }
        }

        return implode("\n", $lines);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /** GET a URL; returns the body, or null on any transport / non-200 result. */
    private function fetch(string $url): ?string {
        $response = wp_remote_get($url, [
            'timeout'     => 15,
            'sslverify'   => true,
            'redirection' => 3,
            'user-agent'  => 'DPXL Shield ThreatFeed',
        ]);

        if (is_wp_error($response) || (int) wp_remote_retrieve_response_code($response) !== 200) {
            return null;
        }

        $body = (string) wp_remote_retrieve_body($response);

        return $body !== '' ? $body : null;
    }

    private function pluginVersion(): string {
        return defined('DPXL_SHIELD_VERSION') ? (string) DPXL_SHIELD_VERSION : '0';
    }

    /** Records status + timestamp and returns the status through. */
    private function finish(string $status): string {
        Options::set('threat_feed_last_status', $status);
        Options::set('threat_feed_last_run', time());

        return $status;
    }
}
