<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\LoginSecurity;

use DPXL\Shield\LoginSecurity\Totp;
use ParagonIE\ConstantTime\Base32;
use PHPUnit\Framework\TestCase;

/**
 * Totp implements RFC 6238. The authority on whether it is correct is the
 * appendix B test-vector table in the RFC itself, so that table is the core of
 * this suite — if these pass, the implementation interoperates with Google
 * Authenticator, Authy, 1Password and every other conforming app.
 */
class TotpTest extends TestCase {

    /** The RFC's shared secret: the ASCII string "12345678901234567890". */
    private function rfcSecret(): string {
        return Base32::encodeUpperUnpadded('12345678901234567890');
    }

    /**
     * RFC 6238, Appendix B — SHA-1 rows. The published codes are 8 digits.
     *
     * @return array<string,array{0:int,1:string}>
     */
    public static function rfcVectors(): array {
        return [
            'T=59'          => [59, '94287082'],
            'T=1111111109'  => [1111111109, '07081804'],
            'T=1111111111'  => [1111111111, '14050471'],
            'T=1234567890'  => [1234567890, '89005924'],
            'T=2000000000'  => [2000000000, '69279037'],
            'T=20000000000' => [20000000000, '65353130'],
        ];
    }

    /**
     * @dataProvider rfcVectors
     */
    public function testMatchesRfc6238TestVectors(int $timestamp, string $expected): void {
        $totp = Totp::fromSecret($this->rfcSecret(), 8);

        $this->assertSame($expected, $totp->at($timestamp));
    }

    /**
     * @dataProvider rfcVectors
     */
    public function testVerifyAcceptsRfcVectorAtItsOwnTimestamp(int $timestamp, string $expected): void {
        $totp = Totp::fromSecret($this->rfcSecret(), 8);

        $this->assertTrue($totp->verify($expected, $timestamp, 0));
    }

    // ── Secret generation ────────────────────────────────────────────────────

    public function testGenerateProducesA160BitBase32Secret(): void {
        $secret = Totp::generate()->getSecret();

        // 20 bytes → 32 Base32 characters, unpadded.
        $this->assertSame(32, strlen($secret));
        $this->assertMatchesRegularExpression('/^[A-Z2-7]+$/', $secret);
        $this->assertSame(20, strlen(Base32::decodeUpper($secret)));
    }

    public function testGenerateProducesADifferentSecretEachTime(): void {
        $this->assertNotSame(Totp::generate()->getSecret(), Totp::generate()->getSecret());
    }

    // ── Window / drift ───────────────────────────────────────────────────────

    public function testAcceptsCodeFromThePreviousAndNextStepWithinWindow(): void {
        $totp = Totp::fromSecret($this->rfcSecret());
        $now  = 1700000000;

        $previous = $totp->at($now - Totp::PERIOD);
        $next     = $totp->at($now + Totp::PERIOD);

        $this->assertTrue($totp->verify($previous, $now, 1), 'previous step must be tolerated');
        $this->assertTrue($totp->verify($next, $now, 1), 'next step must be tolerated');
    }

    public function testRejectsCodeOutsideTheWindow(): void {
        $totp = Totp::fromSecret($this->rfcSecret());
        $now  = 1700000000;

        $farPast = $totp->at($now - (Totp::PERIOD * 5));

        $this->assertFalse($totp->verify($farPast, $now, 1));
    }

    public function testZeroWindowAcceptsOnlyTheCurrentStep(): void {
        $totp = Totp::fromSecret($this->rfcSecret());
        $now  = 1700000000;

        $this->assertTrue($totp->verify($totp->at($now), $now, 0));
        $this->assertFalse($totp->verify($totp->at($now - Totp::PERIOD), $now, 0));
    }

    // ── Malformed input ──────────────────────────────────────────────────────

    /** @return array<string,array{0:string}> */
    public static function malformedCodes(): array {
        return [
            'empty'          => [''],
            'whitespace'     => ['   '],
            'too short'      => ['12345'],
            'too long'       => ['1234567'],
            'letters'        => ['abcdef'],
            'mixed'          => ['12a456'],
            'negative'       => ['-12345'],
            'plus prefixed'  => ['+12345'],
            'float'          => ['123.45'],
        ];
    }

    /**
     * @dataProvider malformedCodes
     */
    public function testRejectsMalformedCodes(string $code): void {
        $totp = Totp::fromSecret($this->rfcSecret());

        $this->assertFalse($totp->verify($code, 1700000000, 1));
    }

    public function testCodeIsAlwaysZeroPaddedToSixDigits(): void {
        $totp = Totp::fromSecret($this->rfcSecret());

        // Sweep a year of steps; every code must be exactly six digits.
        for ($t = 1700000000; $t < 1700000000 + 86400; $t += 997) {
            $this->assertMatchesRegularExpression('/^\d{6}$/', $totp->at($t));
        }
    }

    // ── Secret normalisation ─────────────────────────────────────────────────

    public function testSecretIsNormalisedBeforeDecoding(): void {
        $plain   = $this->rfcSecret();
        $at      = Totp::fromSecret($plain)->at(1700000000);
        $spaced  = Totp::fromSecret(strtolower(chunk_split($plain, 4, ' ')))->at(1700000000);
        $padded  = Totp::fromSecret($plain . '======')->at(1700000000);

        $this->assertSame($at, $spaced, 'spacing and case must not change the code');
        $this->assertSame($at, $padded, 'padding must not change the code');
    }

    // ── Provisioning URI ─────────────────────────────────────────────────────

    public function testProvisioningUriCarriesSecretIssuerAndLabel(): void {
        $totp = Totp::fromSecret($this->rfcSecret());
        $totp->setLabel('admin@example.com');
        $totp->setIssuer('Meu Site (DPXL Shield)');

        $uri = $totp->getProvisioningUri();

        $this->assertStringStartsWith('otpauth://totp/', $uri);
        $this->assertStringContainsString('secret=' . $this->rfcSecret(), $uri);
        $this->assertStringContainsString('algorithm=SHA1', $uri);
        $this->assertStringContainsString('digits=6', $uri);
        $this->assertStringContainsString('period=30', $uri);

        // Label and issuer must survive as data, not break the URI structure.
        $parts = parse_url($uri);
        $this->assertIsArray($parts);
        parse_str($parts['query'] ?? '', $query);
        $this->assertSame('Meu Site (DPXL Shield)', $query['issuer'] ?? null);
        $this->assertStringContainsString(rawurlencode('admin@example.com'), $parts['path'] ?? '');
    }

    public function testProvisioningUriHandlesALabelWithNoIssuer(): void {
        $totp = Totp::fromSecret($this->rfcSecret());
        $totp->setLabel('admin');

        $uri = $totp->getProvisioningUri();

        $this->assertStringStartsWith('otpauth://totp/admin?', $uri);
        $this->assertStringNotContainsString('issuer=', $uri);
    }

    // ── Independence ─────────────────────────────────────────────────────────

    public function testDifferentSecretsProduceDifferentCodes(): void {
        $a = Totp::generate();
        $b = Totp::generate();
        $t = 1700000000;

        $this->assertNotSame($a->at($t), $b->at($t));
        $this->assertFalse($b->verify($a->at($t), $t, 0), 'a code must not verify against another secret');
    }
}
