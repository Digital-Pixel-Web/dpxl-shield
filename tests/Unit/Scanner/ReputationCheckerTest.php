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

    private const DBL = '127.0.1.';
    private const ZEN = '127.0.0.';

    public function testNoAnswerIsClean(): void {
        $r = ReputationChecker::interpret([], self::DBL, 'Spamhaus DBL');

        $this->assertFalse($r['listed']);
        $this->assertSame('clean', $r['status']);
    }

    /** 127.0.1.2 = spam domain. A real DBL listing. */
    public function testDblListingCodeIsAListing(): void {
        $r = ReputationChecker::interpret(['127.0.1.2'], self::DBL, 'Spamhaus DBL');

        $this->assertTrue($r['listed']);
        $this->assertSame('listed', $r['status']);
        $this->assertStringContainsString('127.0.1.2', $r['detail']);
    }

    /** 127.0.0.2 = SBL. A real ZEN listing. */
    public function testZenListingCodeIsAListing(): void {
        $r = ReputationChecker::interpret(['127.0.0.2'], self::ZEN, 'Spamhaus ZEN');

        $this->assertTrue($r['listed']);
        $this->assertSame('listed', $r['status']);
    }

    /**
     * The bug that produced the false positives: 127.255.255.254 means
     * "anonymous query through a public resolver", which is what a shared
     * host's upstream DNS gets for every lookup it makes.
     */
    public function testPublicResolverRefusalIsNotAListing(): void {
        foreach (['127.255.255.252', '127.255.255.254', '127.255.255.255'] as $code) {
            $dbl = ReputationChecker::interpret([$code], self::DBL, 'Spamhaus DBL');
            $zen = ReputationChecker::interpret([$code], self::ZEN, 'Spamhaus ZEN');

            $this->assertFalse($dbl['listed'], "{$code} must not read as a DBL listing");
            $this->assertFalse($zen['listed'], "{$code} must not read as a ZEN listing");
            $this->assertSame('unavailable', $dbl['status']);
            $this->assertSame('unavailable', $zen['status']);
        }
    }

    /** Unavailable is its own state — never quietly reported as verified-clean. */
    public function testRefusalIsNotReportedAsClean(): void {
        $r = ReputationChecker::interpret(['127.255.255.254'], self::DBL, 'Spamhaus DBL');

        $this->assertNotSame('clean', $r['status']);
        $this->assertStringContainsString('unavailable', strtolower($r['detail']));
    }

    /** A DBL answer must not be read with ZEN's prefix, or vice versa. */
    public function testListingPrefixesDoNotCrossMatch(): void {
        $this->assertFalse(ReputationChecker::interpret(['127.0.1.2'], self::ZEN, 'Spamhaus ZEN')['listed']);
        $this->assertFalse(ReputationChecker::interpret(['127.0.0.2'], self::DBL, 'Spamhaus DBL')['listed']);
    }

    /** A genuine listing alongside an error code is still a listing. */
    public function testListingWinsOverAccompanyingErrorCode(): void {
        $r = ReputationChecker::interpret(['127.255.255.254', '127.0.1.5'], self::DBL, 'Spamhaus DBL');

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
