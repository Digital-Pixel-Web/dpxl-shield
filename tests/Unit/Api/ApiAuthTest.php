<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Api;

use DPXL\Shield\Api\ApiAuth;
use DPXL\Shield\Api\ApiToken;
use PHPUnit\Framework\TestCase;

/**
 * Credential extraction from the request.
 *
 * This is small but load-bearing: Apache running PHP as CGI/FastCGI strips the
 * Authorization header before PHP sees it, so without the rewritten fallbacks
 * the API simply does not work on a large slice of shared hosting — which is
 * exactly the hosting this plugin targets.
 */
class ApiAuthTest extends TestCase {

    private function token(): string {
        return ApiToken::generate()['plain'];
    }

    // ── The normal path ──────────────────────────────────────────────────────

    public function testReadsTheTokenFromTheAuthorizationHeader(): void {
        $token = $this->token();

        $this->assertSame($token, ApiAuth::extractBearer('Bearer ' . $token, []));
    }

    public function testSchemeIsMatchedCaseInsensitively(): void {
        $token = $this->token();

        // Clients are inconsistent here; RFC 7235 says the scheme is case-insensitive.
        $this->assertSame($token, ApiAuth::extractBearer('bearer ' . $token, []));
        $this->assertSame($token, ApiAuth::extractBearer('BEARER ' . $token, []));
    }

    public function testSurroundingWhitespaceIsTrimmed(): void {
        $token = $this->token();

        $this->assertSame($token, ApiAuth::extractBearer('Bearer   ' . $token . '  ', []));
    }

    // ── The Apache CGI fallback ──────────────────────────────────────────────

    public function testFallsBackToHttpAuthorizationServerVar(): void {
        $token = $this->token();

        $this->assertSame(
            $token,
            ApiAuth::extractBearer('', ['HTTP_AUTHORIZATION' => 'Bearer ' . $token])
        );
    }

    public function testFallsBackToTheRewrittenRedirectVariant(): void {
        $token = $this->token();

        // What a mod_rewrite rule produces when it re-exposes the stripped header.
        $this->assertSame(
            $token,
            ApiAuth::extractBearer('', ['REDIRECT_HTTP_AUTHORIZATION' => 'Bearer ' . $token])
        );
    }

    public function testTheRealHeaderWinsOverTheFallback(): void {
        $real     = $this->token();
        $fallback = $this->token();

        $this->assertSame(
            $real,
            ApiAuth::extractBearer('Bearer ' . $real, ['HTTP_AUTHORIZATION' => 'Bearer ' . $fallback])
        );
    }

    // ── Rejections ───────────────────────────────────────────────────────────

    /** @return array<string,array{0:string}> */
    public static function unusableHeaders(): array {
        return [
            'empty'            => [''],
            'scheme only'      => ['Bearer'],
            'scheme and space' => ['Bearer '],
            'basic auth'       => ['Basic dXNlcjpwYXNz'],
            'no scheme'        => ['dpxls_abcdefghijklmnop'],
            'wrong scheme'     => ['Token dpxls_abcdefghijklmnop'],
            'bearerish'        => ['Bearertoken'],
        ];
    }

    /**
     * @dataProvider unusableHeaders
     */
    public function testRejectsHeadersThatCarryNoBearerToken(string $header): void {
        $this->assertNull(ApiAuth::extractBearer($header, []));
    }

    public function testEmptyServerFallbacksAreIgnored(): void {
        $this->assertNull(ApiAuth::extractBearer('', ['HTTP_AUTHORIZATION' => '']));
        $this->assertNull(ApiAuth::extractBearer('', ['REDIRECT_HTTP_AUTHORIZATION' => '']));
    }

    /**
     * Extraction is not validation: this returns whatever followed the scheme,
     * and ApiToken::looksValid() is what stops junk before it reaches the
     * database. Pinned so the two responsibilities do not get conflated later.
     */
    public function testExtractionDoesNotValidateTheTokenItself(): void {
        $this->assertSame('not-a-real-token', ApiAuth::extractBearer('Bearer not-a-real-token', []));
        $this->assertFalse(ApiToken::looksValid('not-a-real-token'));
    }
}
