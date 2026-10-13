<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Scanner;

use Brain\Monkey;
use Brain\Monkey\Actions;
use Brain\Monkey\Functions;
use DPXL\Shield\Scanner\ChecksumVerifier;
use DPXL\Shield\Scanner\FileIntegrityMonitor;
use PHPUnit\Framework\TestCase;

/**
 * The gate between "this file changed" and "you are compromised".
 *
 * A stored baseline can only say a core file is no longer what it was, which is
 * equally true of a routine WordPress update. Updates that bypass
 * `upgrader_process_complete` — background auto-updates, WP-CLI, host control
 * panels — used to leave the baseline stale and send a critical "compromise"
 * email every hour, forever. These pin the rule that resolves it: the WP.org
 * manifest decides, and only an unconfirmed file raises the alarm.
 */
class FileIntegrityMonitorTest extends TestCase {

    private const CORE_FILE = 'wp-admin/includes/plugin.php';

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();

        Functions\stubs([
            'get_transient' => false,
            'set_transient' => true,
            'current_time'  => fn($type) => '2026-10-13 14:38:23',
        ]);
    }

    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }

    /** A file that matches the official release is stock WordPress: adopt it, stay quiet. */
    public function testFileMatchingTheOfficialManifestIsRebaselinedWithoutAlerting(): void {
        $verifier = $this->createMock(ChecksumVerifier::class);
        $verifier->method('matchesOfficialCore')->with(self::CORE_FILE)->willReturn(true);

        // The whole point: the stale baseline is replaced, so the next request is silent too.
        $verifier->expects($this->once())
            ->method('record')
            ->with(ABSPATH . self::CORE_FILE, 'core');

        Actions\expectDone('dpxl_shield_alert')->never();

        (new FileIntegrityMonitor($verifier))
            ->handleViolation(ABSPATH . self::CORE_FILE, self::CORE_FILE);
    }

    /** Differs from the official release for this version — this is the real thing. */
    public function testFileDifferingFromTheOfficialManifestAlerts(): void {
        $verifier = $this->createMock(ChecksumVerifier::class);
        $verifier->method('matchesOfficialCore')->willReturn(false);
        $verifier->expects($this->never())->method('record');

        Actions\expectDone('dpxl_shield_alert')->once();

        (new FileIntegrityMonitor($verifier))
            ->handleViolation(ABSPATH . self::CORE_FILE, self::CORE_FILE);
    }

    /**
     * No verdict (wp-config.php is not shipped by core, or WP.org was
     * unreachable). Unknown is not the same as fine — a security monitor must
     * fail towards telling the admin.
     */
    public function testUnconfirmedFileStillAlerts(): void {
        $verifier = $this->createMock(ChecksumVerifier::class);
        $verifier->method('matchesOfficialCore')->willReturn(null);
        $verifier->expects($this->never())->method('record');

        Actions\expectDone('dpxl_shield_alert')->once();

        (new FileIntegrityMonitor($verifier))
            ->handleViolation(ABSPATH . 'wp-config.php', 'wp-config.php');
    }

    /** The hourly throttle still short-circuits before any work is done. */
    public function testThrottledFileNeitherChecksNorAlerts(): void {
        Functions\when('get_transient')->justReturn(true);

        $verifier = $this->createMock(ChecksumVerifier::class);
        $verifier->expects($this->never())->method('matchesOfficialCore');
        $verifier->expects($this->never())->method('record');

        Actions\expectDone('dpxl_shield_alert')->never();

        (new FileIntegrityMonitor($verifier))
            ->handleViolation(ABSPATH . self::CORE_FILE, self::CORE_FILE);
    }
}
