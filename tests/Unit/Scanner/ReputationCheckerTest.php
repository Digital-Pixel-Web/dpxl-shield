<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Scanner;

use DPXL\Shield\Scanner\ReputationChecker;
use PHPUnit\Framework\TestCase;

/**
 * Spamhaus answers a listing and a refused query the same way — with an A
 * record — and only the address separates them. Treating any answer as a
 * listing reported every domain on a shared host as blocklisted, forever.
 * These pin the three states apart.
 */
class ReputationCheckerTest extends TestCase {

    public function testNoAnswerIsClean(): void {
        $r = ReputationChecker::interpret([], 'Spamhaus DBL');

        $this->assertFalse($r['listed']);
        $this->assertSame('clean', $r['status']);
    }

    /**
     * Listings occupy 127.0.0.0/16 across the datasets: 127.0.0.x ZEN,
     * 127.0.1.x DBL, 127.0.2.x ZRD.
     *
     * @dataProvider listingCodes
     */
    public function testListingCodesAreListings(string $code): void {
        $r = ReputationChecker::interpret([$code], 'Spamhaus');

        $this->assertTrue($r['listed'], "{$code} must read as a listing");
        $this->assertSame('listed', $r['status']);
        $this->assertStringContainsString($code, $r['detail']);
    }

    /** @return list<array{string}> */
    public static function listingCodes(): array {
        return [['127.0.0.2'], ['127.0.0.3'], ['127.0.0.10'], ['127.0.1.2'], ['127.0.1.5'], ['127.0.2.1']];
    }

    /**
     * The bug that produced the false positives: 127.255.255.254 means
     * "anonymous query through a public resolver", which is what a shared
     * host's upstream DNS gets for every lookup it makes.
     *
     * @dataProvider errorCodes
     */
    public function testErrorCodesAreNotListings(string $code): void {
        $r = ReputationChecker::interpret([$code], 'Spamhaus DBL');

        $this->assertFalse($r['listed'], "{$code} must not read as a listing");
        $this->assertSame('unavailable', $r['status']);
    }

    /** @return list<array{string}> */
    public static function errorCodes(): array {
        return [['127.255.255.252'], ['127.255.255.254'], ['127.255.255.255']];
    }

    /** Unavailable is its own state — never quietly reported as verified-clean. */
    public function testRefusalIsNotReportedAsClean(): void {
        $r = ReputationChecker::interpret(['127.255.255.254'], 'Spamhaus DBL');

        $this->assertNotSame('clean', $r['status']);
        $this->assertStringContainsString('unavailable', strtolower($r['detail']));
    }

    /** Without a key, the remedy to suggest is the key itself. */
    public function testRefusalWithoutKeySuggestsDqs(): void {
        $r = ReputationChecker::interpret(['127.255.255.254'], 'Spamhaus DBL', false);

        $this->assertStringContainsString('DQS', $r['detail']);
    }

    /** With a key, suggesting "get a key" would be useless advice. */
    public function testRefusalWithKeyPointsAtTheKey(): void {
        $r = ReputationChecker::interpret(['127.255.255.254'], 'Spamhaus DBL', true);

        $this->assertStringContainsString('key is active', $r['detail']);
    }

    /**
     * Some resolvers answer unknown names with their own address instead of
     * NXDOMAIN. Reading that as a listing would flag every site behind them.
     */
    public function testHijackedNxdomainIsNotAListing(): void {
        $r = ReputationChecker::interpret(['92.242.140.21'], 'Spamhaus DBL');

        $this->assertFalse($r['listed']);
        $this->assertSame('unavailable', $r['status']);
        $this->assertStringContainsString('rewriting unknown names', $r['detail']);
    }

    /** A genuine listing alongside an error code is still a listing. */
    public function testListingWinsOverAccompanyingErrorCode(): void {
        $r = ReputationChecker::interpret(['127.255.255.254', '127.0.1.5'], 'Spamhaus DBL');

        $this->assertTrue($r['listed']);
        $this->assertSame('listed', $r['status']);
    }

    // ── Multi-address folding ──────────────────────────────────────────────

    private const CLEAN       = ['listed' => false, 'status' => 'clean', 'detail' => 'Clean'];
    private const REFUSED     = ['listed' => false, 'status' => 'unavailable', 'detail' => 'Check unavailable'];
    private const IS_LISTED   = ['listed' => true, 'status' => 'listed', 'detail' => 'Listed in Spamhaus ZEN'];

    /**
     * Only the first A record used to be checked, and resolvers rotate the
     * order — so a listed address could go unreported for days, then surface
     * at random. Any listed address must flag the site.
     */
    public function testAnyListedAddressFlagsTheSite(): void {
        $r = ReputationChecker::combineZen([
            '89.116.213.138' => self::CLEAN,
            '147.79.105.252' => self::IS_LISTED,
        ]);

        $this->assertTrue($r['listed']);
        $this->assertSame('listed', $r['status']);
        $this->assertStringContainsString('147.79.105.252', $r['detail']);
    }

    public function testAllCleanAddressesAreClean(): void {
        $r = ReputationChecker::combineZen([
            '89.116.213.138' => self::CLEAN,
            '147.79.105.252' => self::CLEAN,
        ]);

        $this->assertFalse($r['listed']);
        $this->assertSame('clean', $r['status']);
    }

    /** Every lookup refused means nothing was verified — not that it is clean. */
    public function testAllRefusedIsUnavailableNotClean(): void {
        $r = ReputationChecker::combineZen([
            '89.116.213.138' => self::REFUSED,
            '147.79.105.252' => self::REFUSED,
        ]);

        $this->assertFalse($r['listed']);
        $this->assertSame('unavailable', $r['status']);
    }

    /** One address verified clean is enough for a real verdict. */
    public function testPartialVerificationCounts(): void {
        $r = ReputationChecker::combineZen([
            '89.116.213.138' => self::REFUSED,
            '147.79.105.252' => self::CLEAN,
        ]);

        $this->assertSame('clean', $r['status']);
    }

    public function testNoAddressResolvedIsUnavailable(): void {
        $r = ReputationChecker::combineZen([]);

        $this->assertFalse($r['listed']);
        $this->assertSame('unavailable', $r['status']);
    }
}
