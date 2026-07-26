<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\LoginSecurity;

use DPXL\Shield\LoginSecurity\BruteForceProtection;
use PHPUnit\Framework\TestCase;

/**
 * Locks the progressive lockout escalation — a security-critical curve. If
 * these thresholds drift, brute-force protection silently weakens.
 */
class BruteForceProtectionTest extends TestCase {

    private const MIN = 60;
    private const HOUR = 3600;
    private const DAY = 86400;

    public function testBelowThresholdIsNotLockedOut(): void {
        $this->assertSame(0, BruteForceProtection::lockoutDuration(4, 5));
        $this->assertSame(0, BruteForceProtection::lockoutDuration(0, 5));
    }

    public function testFirstThresholdLocksFiveMinutes(): void {
        $this->assertSame(5 * self::MIN, BruteForceProtection::lockoutDuration(5, 5));
        $this->assertSame(5 * self::MIN, BruteForceProtection::lockoutDuration(9, 5));
    }

    public function testSecondThresholdLocksOneHour(): void {
        $this->assertSame(self::HOUR, BruteForceProtection::lockoutDuration(10, 5));
        $this->assertSame(self::HOUR, BruteForceProtection::lockoutDuration(19, 5));
    }

    public function testThirdThresholdLocksTwentyFourHours(): void {
        $this->assertSame(self::DAY, BruteForceProtection::lockoutDuration(20, 5));
        $this->assertSame(self::DAY, BruteForceProtection::lockoutDuration(100, 5));
    }

    public function testEscalationScalesWithCustomThreshold(): void {
        // base 3 → 3=5min, 6=1h, 12=24h
        $this->assertSame(0, BruteForceProtection::lockoutDuration(2, 3));
        $this->assertSame(5 * self::MIN, BruteForceProtection::lockoutDuration(3, 3));
        $this->assertSame(self::HOUR, BruteForceProtection::lockoutDuration(6, 3));
        $this->assertSame(self::DAY, BruteForceProtection::lockoutDuration(12, 3));
    }
}
