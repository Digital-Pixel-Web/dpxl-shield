<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Api;

use DPXL\Shield\Api\ApiToken;
use PHPUnit\Framework\TestCase;

/**
 * The token is the only credential that reaches site data without a WordPress
 * session, so its shape, entropy and storage form are pinned here.
 */
class ApiTokenTest extends TestCase {

    // ── Generation ───────────────────────────────────────────────────────────

    public function testGeneratedTokenCarriesTheProductPrefix(): void {
        $this->assertStringStartsWith(ApiToken::PREFIX, ApiToken::generate()['plain']);
    }

    public function testGeneratedTokenHas256BitsOfEntropy(): void {
        $body = substr(ApiToken::generate()['plain'], strlen(ApiToken::PREFIX));

        // 32 random bytes, base64url, unpadded → 43 characters.
        $this->assertSame(43, strlen($body));
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $body);
    }

    public function testEveryTokenIsDifferent(): void {
        $seen = [];

        for ($i = 0; $i < 50; $i++) {
            $seen[] = ApiToken::generate()['plain'];
        }

        $this->assertCount(50, array_unique($seen));
    }

    /** The plaintext must never be derivable from what is stored. */
    public function testStoredHashDoesNotContainThePlaintext(): void {
        $token = ApiToken::generate();

        $this->assertStringNotContainsString(
            substr($token['plain'], strlen(ApiToken::PREFIX)),
            $token['hash']
        );

        $this->assertSame(64, strlen($token['hash']), 'sha256 hex');
        $this->assertSame(hash('sha256', $token['plain']), $token['hash']);
    }

    public function testLookupFragmentIsShortEnoughToBeUseless(): void {
        $token = ApiToken::generate();

        $this->assertSame($token['lookup'], substr($token['plain'], 0, ApiToken::LOOKUP_LENGTH));

        // The fragment identifies a row; it must not be most of the credential.
        $this->assertLessThan(strlen($token['plain']) / 2, strlen($token['lookup']));
    }

    // ── Shape validation ─────────────────────────────────────────────────────

    public function testAcceptsAFreshlyGeneratedToken(): void {
        $this->assertTrue(ApiToken::looksValid(ApiToken::generate()['plain']));
    }

    /** @return array<string,array{0:string}> */
    public static function malformedTokens(): array {
        return [
            'empty'            => [''],
            'no prefix'        => [str_repeat('a', 43)],
            'wrong prefix'     => ['other_' . str_repeat('a', 43)],
            'too short'        => [ApiToken::PREFIX . str_repeat('a', 42)],
            'too long'         => [ApiToken::PREFIX . str_repeat('a', 44)],
            'sql injection'    => [ApiToken::PREFIX . "' OR '1'='1"],
            'sql wildcard'     => [ApiToken::PREFIX . str_repeat('%', 43)],
            'null byte'        => [ApiToken::PREFIX . str_repeat('a', 42) . "\0"],
            'plus and slash'   => [ApiToken::PREFIX . str_repeat('a', 41) . '+/'],
            'whitespace'       => [ApiToken::PREFIX . str_repeat('a', 42) . ' '],
            'prefix only'      => [ApiToken::PREFIX],
        ];
    }

    /**
     * Malformed input is rejected before it can reach the database — a flood of
     * junk Authorization headers must not become a flood of queries.
     *
     * @dataProvider malformedTokens
     */
    public function testRejectsMalformedTokens(string $candidate): void {
        $this->assertFalse(ApiToken::looksValid($candidate));
    }

    // ── Display ──────────────────────────────────────────────────────────────

    public function testMaskShowsOnlyTheLookupFragment(): void {
        $token  = ApiToken::generate();
        $masked = ApiToken::mask($token['lookup']);

        $this->assertStringStartsWith($token['lookup'], $masked);
        $this->assertStringNotContainsString($token['plain'], $masked);
        $this->assertFalse(ApiToken::looksValid($masked), 'a masked token must not be usable');
    }
}
