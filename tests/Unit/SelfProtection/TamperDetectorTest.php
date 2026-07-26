<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\SelfProtection;

use DPXL\Shield\SelfProtection\TamperDetector;
use PHPUnit\Framework\TestCase;

/**
 * Covers the two pure pieces of self-protection:
 *  - shouldRebaseline(): the v1.0.14 guard that stops false-positive tamper
 *    alerts after a legitimate plugin update.
 *  - diffChecksums(): what counts as added / modified / deleted.
 */
class TamperDetectorTest extends TestCase {

    // ── Version-aware rebaseline (v1.0.14 fix) ─────────────────────────────

    public function testRebaselinesWhenVersionAdvances(): void {
        $this->assertTrue(TamperDetector::shouldRebaseline('1.0.23', '1.0.24'));
    }

    public function testDoesNotRebaselineOnSameVersion(): void {
        // Same version → compare against baseline (real tamper detection runs).
        $this->assertFalse(TamperDetector::shouldRebaseline('1.0.24', '1.0.24'));
    }

    public function testRebaselinesOnFirstRunFromEmptyStoredVersion(): void {
        $this->assertTrue(TamperDetector::shouldRebaseline('', '1.0.24'));
    }

    public function testNeverRebaselinesWhenCurrentVersionUnknown(): void {
        // DPXL_SHIELD_VERSION missing → never wipe the baseline.
        $this->assertFalse(TamperDetector::shouldRebaseline('1.0.24', ''));
        $this->assertFalse(TamperDetector::shouldRebaseline('', ''));
    }

    // ── Checksum diff ──────────────────────────────────────────────────────

    public function testIdenticalChecksumsProduceNoMismatch(): void {
        $map = ['a.php' => 'h1', 'b.php' => 'h2'];
        $this->assertSame([], TamperDetector::diffChecksums($map, $map));
    }

    public function testModifiedFileDetected(): void {
        $baseline = ['a.php' => 'h1', 'b.php' => 'h2'];
        $current  = ['a.php' => 'h1', 'b.php' => 'CHANGED'];

        $this->assertSame(['modified:b.php'], TamperDetector::diffChecksums($baseline, $current));
    }

    public function testAddedFileDetected(): void {
        $baseline = ['a.php' => 'h1'];
        $current  = ['a.php' => 'h1', 'evil.php' => 'x'];

        $this->assertSame(['added:evil.php'], TamperDetector::diffChecksums($baseline, $current));
    }

    public function testDeletedFileDetected(): void {
        $baseline = ['a.php' => 'h1', 'b.php' => 'h2'];
        $current  = ['a.php' => 'h1'];

        $this->assertSame(['deleted:b.php'], TamperDetector::diffChecksums($baseline, $current));
    }

    public function testMixedChangesAllReported(): void {
        $baseline = ['keep.php' => 'k', 'mod.php' => 'old', 'gone.php' => 'g'];
        $current  = ['keep.php' => 'k', 'mod.php' => 'new', 'new.php' => 'n'];

        $result = TamperDetector::diffChecksums($baseline, $current);

        $this->assertContains('modified:mod.php', $result);
        $this->assertContains('added:new.php', $result);
        $this->assertContains('deleted:gone.php', $result);
        $this->assertCount(3, $result);
    }
}
