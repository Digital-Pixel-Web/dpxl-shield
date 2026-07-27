<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Threat;

use DPXL\Shield\Threat\FeedVerifier;
use PHPUnit\Framework\TestCase;

/**
 * The trust boundary of the whole feed. If signature verification can be fooled,
 * a compromised CDN pushes arbitrary rules to every site. These tests pin: a
 * valid signature verifies, anything tampered or mismatched is rejected, bad
 * input never throws, and the anti-rollback comparison orders versions correctly.
 */
class FeedVerifierTest extends TestCase {

    private string $secretKeyB64;
    private string $publicKeyB64;

    protected function setUp(): void {
        parent::setUp();

        if (!FeedVerifier::isAvailable()) {
            $this->markTestSkipped('ext-sodium not available in this runtime.');
        }

        $pair = sodium_crypto_sign_keypair();
        $this->secretKeyB64 = base64_encode(sodium_crypto_sign_secretkey($pair));
        $this->publicKeyB64 = base64_encode(sodium_crypto_sign_publickey($pair));
    }

    private function sign(string $message): string {
        $secret = base64_decode($this->secretKeyB64, true);

        return base64_encode(sodium_crypto_sign_detached($message, $secret));
    }

    public function testValidSignatureVerifies(): void {
        $message = '{"feed_version":"2026.07.26"}';

        $this->assertTrue(FeedVerifier::verify($message, $this->sign($message), $this->publicKeyB64));
    }

    public function testTamperedMessageIsRejected(): void {
        $sig = $this->sign('{"feed_version":"2026.07.26"}');

        $this->assertFalse(FeedVerifier::verify('{"feed_version":"2026.07.27"}', $sig, $this->publicKeyB64));
    }

    public function testWrongPublicKeyIsRejected(): void {
        $message = 'hello';
        $sig     = $this->sign($message);

        $otherPair = sodium_crypto_sign_keypair();
        $otherPub  = base64_encode(sodium_crypto_sign_publickey($otherPair));

        $this->assertFalse(FeedVerifier::verify($message, $sig, $otherPub));
    }

    public function testMalformedInputsNeverThrow(): void {
        $this->assertFalse(FeedVerifier::verify('msg', 'not-base64!!', $this->publicKeyB64));
        $this->assertFalse(FeedVerifier::verify('msg', base64_encode('too-short'), $this->publicKeyB64));
        $this->assertFalse(FeedVerifier::verify('msg', $this->sign('msg'), base64_encode('short-key')));
        $this->assertFalse(FeedVerifier::verify('msg', '', ''));
    }

    public function testSha256Matches(): void {
        $content = 'artifact-bytes';
        $hash    = hash('sha256', $content);

        $this->assertTrue(FeedVerifier::sha256Matches($content, $hash));
        $this->assertTrue(FeedVerifier::sha256Matches($content, strtoupper($hash)), 'Hex compare is case-insensitive');
        $this->assertFalse(FeedVerifier::sha256Matches($content, hash('sha256', 'other')));
        $this->assertFalse(FeedVerifier::sha256Matches($content, ''));
    }

    /**
     * @dataProvider versionCases
     */
    public function testIsNewerVersion(string $candidate, string $current, bool $expected): void {
        $this->assertSame($expected, FeedVerifier::isNewerVersion($candidate, $current));
    }

    /** @return array<string,array{0:string,1:string,2:bool}> */
    public static function versionCases(): array {
        return [
            'newer day'          => ['2026.07.27', '2026.07.26', true],
            'older day'          => ['2026.07.25', '2026.07.26', false],
            'equal'              => ['2026.07.26', '2026.07.26', false],
            'build bump'         => ['2026.07.26.1', '2026.07.26', true],
            'build 10 beats 2'   => ['2026.07.26.10', '2026.07.26.2', true], // string compare would fail here
            'build 2 not > 10'   => ['2026.07.26.2', '2026.07.26.10', false],
            'from empty'         => ['2026.07.26', '', true],
        ];
    }
}
