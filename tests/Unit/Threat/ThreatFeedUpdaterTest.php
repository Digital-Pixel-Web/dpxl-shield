<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Threat;

use Brain\Monkey;
use Brain\Monkey\Functions;
use DPXL\Shield\Threat\ThreatFeedUpdater;
use PHPUnit\Framework\TestCase;

/**
 * The updater is where signature, integrity, anti-rollback and atomic write meet
 * the network. These pin the whole decision tree with a mocked HTTP layer: a
 * clean run applies the feed, and every failure mode leaves the installed feed
 * untouched with an explicit status. A green run here is the difference between
 * "self-updating protection" and "silently shipping attacker-controlled rules".
 */
class ThreatFeedUpdaterTest extends TestCase {

    private const MANIFEST_URL = 'https://feed.test/manifest.json';
    private const ARTIFACT_URL = 'https://feed.test/waf-rules.json';

    private string $secret;
    private string $publicB64;
    private string $activePath;
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
        $this->activePath = sys_get_temp_dir() . '/dpxl-active-' . uniqid() . '.json';
        $this->options   = [];
    }

    protected function tearDown(): void {
        @unlink($this->activePath);
        @unlink($this->activePath . '.bak');
        Monkey\tearDown();
        parent::tearDown();
    }

    // ── Test harness ─────────────────────────────────────────────────────────

    private function stubOptionsAndTransients(): void {
        $store = &$this->options;

        Functions\when('get_option')->alias(function ($key, $default = false) use (&$store) {
            return $store[$key] ?? $default;
        });
        Functions\when('update_option')->alias(function ($key, $value) use (&$store) {
            $store[$key] = $value;
            return true;
        });
        Functions\when('get_transient')->justReturn(false);
        Functions\when('set_transient')->justReturn(true);
        Functions\when('delete_transient')->justReturn(true);
    }

    /** @param array<string,string> $urlToBody */
    private function stubNetwork(array $urlToBody): void {
        Functions\when('is_wp_error')->justReturn(false);
        Functions\when('wp_remote_get')->alias(fn($url, $args = []) => ['url' => $url]);
        Functions\when('wp_remote_retrieve_response_code')->alias(
            fn($resp) => isset($urlToBody[$resp['url'] ?? '']) ? 200 : 404
        );
        Functions\when('wp_remote_retrieve_body')->alias(
            fn($resp) => $urlToBody[$resp['url'] ?? ''] ?? ''
        );
    }

    /**
     * Builds a signed manifest for the given artifact body + feed version.
     *
     * @return array{manifest:string,artifact:string}
     */
    private function makeFeed(string $feedVersion, string $artifactBody, string $minPlugin = '1.0.0'): array {
        $manifest = [
            'schema'             => 1,
            'feed_version'       => $feedVersion,
            'min_plugin_version' => $minPlugin,
            'artifacts'          => [
                'waf_rules' => [
                    'url'    => self::ARTIFACT_URL,
                    'sha256' => hash('sha256', $artifactBody),
                    'size'   => strlen($artifactBody),
                ],
            ],
        ];

        // Sign the updater's own canonical payload so signer/verifier agree exactly.
        $payload = (new ThreatFeedUpdater(self::MANIFEST_URL, $this->publicB64, $this->activePath))
            ->signedPayload($manifest);
        $manifest['signature'] = base64_encode(sodium_crypto_sign_detached($payload, $this->secret));

        return ['manifest' => (string) json_encode($manifest), 'artifact' => $artifactBody];
    }

    private function updater(): ThreatFeedUpdater {
        return new ThreatFeedUpdater(self::MANIFEST_URL, $this->publicB64, $this->activePath);
    }

    private const RULES_BODY = '{"meta":{"version":"2026.07.26"},"rules":[{"id":"feed-1","pattern":"/x/","targets":["get"],"action":"block"}]}';

    // ── Happy path ───────────────────────────────────────────────────────────

    public function testValidFeedIsApplied(): void {
        $this->stubOptionsAndTransients();
        $feed = $this->makeFeed('2026.07.26', self::RULES_BODY);
        $this->stubNetwork([self::MANIFEST_URL => $feed['manifest'], self::ARTIFACT_URL => $feed['artifact']]);

        $status = $this->updater()->run();

        $this->assertSame(ThreatFeedUpdater::OK, $status);
        $this->assertSame(self::RULES_BODY, file_get_contents($this->activePath), 'Artifact is written to the active file');
        $this->assertSame('2026.07.26', $this->options['dpxl_shield_threat_feed_version'] ?? null);
    }

    // ── Security / integrity failures — installed feed must stay untouched ────

    public function testTamperedArtifactIsRejected(): void {
        $this->stubOptionsAndTransients();
        $feed = $this->makeFeed('2026.07.26', self::RULES_BODY);
        // Serve a different body than the manifest's signed SHA-256 promises.
        $this->stubNetwork([self::MANIFEST_URL => $feed['manifest'], self::ARTIFACT_URL => '{"rules":[]}TAMPERED']);

        $status = $this->updater()->run();

        $this->assertSame(ThreatFeedUpdater::HASH_FAIL, $status);
        $this->assertFileDoesNotExist($this->activePath, 'A hash mismatch never writes the file');
    }

    public function testBadSignatureIsRejected(): void {
        $this->stubOptionsAndTransients();
        $feed = $this->makeFeed('2026.07.26', self::RULES_BODY);

        // Re-sign with a different key → signature no longer matches the pinned public key.
        $decoded = json_decode($feed['manifest'], true);
        $otherPair = sodium_crypto_sign_keypair();
        $payload = $this->updater()->signedPayload($decoded);
        $decoded['signature'] = base64_encode(sodium_crypto_sign_detached($payload, sodium_crypto_sign_secretkey($otherPair)));

        $this->stubNetwork([self::MANIFEST_URL => (string) json_encode($decoded), self::ARTIFACT_URL => $feed['artifact']]);

        $this->assertSame(ThreatFeedUpdater::SIG_FAIL, $this->updater()->run());
        $this->assertFileDoesNotExist($this->activePath);
    }

    public function testOlderOrEqualVersionIsNoChange(): void {
        $this->stubOptionsAndTransients();
        $this->options['dpxl_shield_threat_feed_version'] = '2026.07.26';
        $feed = $this->makeFeed('2026.07.26', self::RULES_BODY); // same version
        $this->stubNetwork([self::MANIFEST_URL => $feed['manifest'], self::ARTIFACT_URL => $feed['artifact']]);
        file_put_contents($this->activePath, self::RULES_BODY); // the installed copy is on disk

        $this->assertSame(ThreatFeedUpdater::NO_CHANGE, $this->updater()->run());
    }

    /** A missing active file (fresh data folder) brings the recorded version back. */
    public function testSameVersionIsReinstalledWhenTheFileIsGone(): void {
        $this->stubOptionsAndTransients();
        $this->options['dpxl_shield_threat_feed_version'] = '2026.07.26';
        $feed = $this->makeFeed('2026.07.26', self::RULES_BODY);
        $this->stubNetwork([self::MANIFEST_URL => $feed['manifest'], self::ARTIFACT_URL => $feed['artifact']]);

        $this->assertSame(ThreatFeedUpdater::OK, $this->updater()->run());
        $this->assertFileExists($this->activePath);
    }

    /** ...but never an older one, even then. */
    public function testOlderVersionIsRefusedEvenWhenTheFileIsGone(): void {
        $this->stubOptionsAndTransients();
        $this->options['dpxl_shield_threat_feed_version'] = '2026.07.27';
        $feed = $this->makeFeed('2026.07.26', self::RULES_BODY);
        $this->stubNetwork([self::MANIFEST_URL => $feed['manifest'], self::ARTIFACT_URL => $feed['artifact']]);

        $this->assertSame(ThreatFeedUpdater::NO_CHANGE, $this->updater()->run());
    }

    public function testIncompatiblePluginVersionIsSkipped(): void {
        $this->stubOptionsAndTransients();
        $feed = $this->makeFeed('2026.07.26', self::RULES_BODY, '99.0.0'); // needs a newer plugin
        $this->stubNetwork([self::MANIFEST_URL => $feed['manifest'], self::ARTIFACT_URL => $feed['artifact']]);

        $this->assertSame(ThreatFeedUpdater::INCOMPATIBLE, $this->updater()->run());
    }

    public function testNetworkFailureIsNonDestructive(): void {
        $this->stubOptionsAndTransients();
        $this->stubNetwork([]); // manifest URL not served → 404

        $this->assertSame(ThreatFeedUpdater::NET_FAIL, $this->updater()->run());
        $this->assertFileDoesNotExist($this->activePath);
    }

    public function testDisabledShortCircuits(): void {
        $this->stubOptionsAndTransients();
        $this->options['dpxl_shield_threat_feed_enabled'] = false;

        $this->assertSame(ThreatFeedUpdater::DISABLED, $this->updater()->run());
    }

    public function testMissingPublicKeyRefusesToVerify(): void {
        $this->stubOptionsAndTransients();
        $feed = $this->makeFeed('2026.07.26', self::RULES_BODY);
        $this->stubNetwork([self::MANIFEST_URL => $feed['manifest'], self::ARTIFACT_URL => $feed['artifact']]);

        $updater = new ThreatFeedUpdater(self::MANIFEST_URL, '', $this->activePath); // no pinned key

        $this->assertSame(ThreatFeedUpdater::NO_PUBKEY, $updater->run());
    }
}
