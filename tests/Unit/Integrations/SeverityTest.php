<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Integrations;

use DPXL\Shield\Integrations\Severity;
use PHPUnit\Framework\TestCase;

class SeverityTest extends TestCase {

    public function testLevelsAreOrderedFromInfoToCritical(): void {
        $this->assertSame(
            [Severity::INFO, Severity::LOW, Severity::MEDIUM, Severity::HIGH, Severity::CRITICAL],
            Severity::all()
        );
    }

    public function testRankIncreasesWithSeverity(): void {
        $this->assertLessThan(Severity::rank(Severity::LOW), Severity::rank(Severity::INFO));
        $this->assertLessThan(Severity::rank(Severity::MEDIUM), Severity::rank(Severity::LOW));
        $this->assertLessThan(Severity::rank(Severity::HIGH), Severity::rank(Severity::MEDIUM));
        $this->assertLessThan(Severity::rank(Severity::CRITICAL), Severity::rank(Severity::HIGH));
    }

    /**
     * An unrecognised label must rank at the bottom. Ranking it high would let a
     * typo in stored config page someone at 3am.
     */
    public function testUnknownLevelRanksAsInfo(): void {
        $this->assertSame(Severity::rank(Severity::INFO), Severity::rank('apocalyptic'));
        $this->assertFalse(Severity::atLeast('apocalyptic', Severity::LOW));
    }

    public function testAtLeastIsInclusiveOfTheThreshold(): void {
        $this->assertTrue(Severity::atLeast(Severity::HIGH, Severity::HIGH));
        $this->assertTrue(Severity::atLeast(Severity::CRITICAL, Severity::HIGH));
        $this->assertFalse(Severity::atLeast(Severity::MEDIUM, Severity::HIGH));
    }

    public function testEverySeverityClearsTheInfoThreshold(): void {
        foreach (Severity::all() as $level) {
            $this->assertTrue(Severity::atLeast($level, Severity::INFO), "{$level} should clear info");
        }
    }

    public function testIsValidRecognisesOnlyKnownLevels(): void {
        $this->assertTrue(Severity::isValid(Severity::CRITICAL));
        $this->assertFalse(Severity::isValid('urgent'));
        $this->assertFalse(Severity::isValid(''));
    }
}
