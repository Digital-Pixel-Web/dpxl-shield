<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Threat;

use DPXL\Shield\Threat\AtomicFile;
use PHPUnit\Framework\TestCase;

/**
 * Atomic replacement + rollback. The active feed file is read pre-WordPress, so
 * a torn write there could take the site down. These pin: the swap leaves no
 * temp debris, the previous copy is preserved as .bak, rollback restores it, and
 * an unwritable destination fails cleanly instead of corrupting anything.
 */
class AtomicFileTest extends TestCase {

    private string $dir;

    protected function setUp(): void {
        parent::setUp();
        $this->dir = sys_get_temp_dir() . '/dpxl-atomic-' . uniqid();
        mkdir($this->dir);
    }

    protected function tearDown(): void {
        foreach (glob($this->dir . '/*') ?: [] as $f) {
            @unlink($f);
        }
        @rmdir($this->dir);
        parent::tearDown();
    }

    public function testWriteCreatesFileAndLeavesNoTempDebris(): void {
        $path = $this->dir . '/feed.json';

        $this->assertTrue(AtomicFile::write($path, 'v1'));
        $this->assertSame('v1', file_get_contents($path));

        $leftovers = array_filter(glob($this->dir . '/*') ?: [], static fn($f) => str_contains($f, '.tmp'));
        $this->assertSame([], $leftovers, 'No .tmp file should survive a successful write');
    }

    public function testOverwriteBacksUpPreviousContents(): void {
        $path = $this->dir . '/feed.json';

        AtomicFile::write($path, 'old');
        AtomicFile::write($path, 'new');

        $this->assertSame('new', file_get_contents($path));
        $this->assertFileExists($path . '.bak');
        $this->assertSame('old', file_get_contents($path . '.bak'), 'Backup holds the pre-overwrite contents');
    }

    public function testRollbackRestoresPreviousContents(): void {
        $path = $this->dir . '/feed.json';

        AtomicFile::write($path, 'good');
        AtomicFile::write($path, 'bad');
        $this->assertSame('bad', file_get_contents($path));

        $this->assertTrue(AtomicFile::rollback($path));
        $this->assertSame('good', file_get_contents($path), 'Rollback restores the last good copy');
    }

    public function testRollbackWithoutBackupReturnsFalse(): void {
        $path = $this->dir . '/never-written.json';

        $this->assertFalse(AtomicFile::rollback($path));
    }

    /**
     * data/ is not in the repository and plugin updates wipe it, so the first
     * write has to create it — otherwise the feed and GeoIP never land.
     */
    public function testWriteCreatesMissingDir(): void {
        $path = $this->dir . '/data/feed.json';

        try {
            $this->assertTrue(AtomicFile::write($path, 'x'));
            $this->assertSame('x', file_get_contents($path));
        } finally {
            @unlink($path);
            @rmdir($this->dir . '/data');
        }
    }

    public function testWriteToUncreatableDirFailsCleanly(): void {
        // A regular file where the directory should be: mkdir cannot succeed.
        file_put_contents($this->dir . '/blocker', '');
        $path = $this->dir . '/blocker/feed.json';

        $this->assertFalse(AtomicFile::write($path, 'x'));
        $this->assertFileDoesNotExist($path);
    }
}
