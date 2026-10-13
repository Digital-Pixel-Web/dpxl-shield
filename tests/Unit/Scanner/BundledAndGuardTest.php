<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Scanner;

use DPXL\Shield\Scanner\MalwareScanner;
use PHPUnit\Framework\TestCase;

/**
 * Two more ways a healthy site read as compromised.
 *
 * WordPress ships Akismet and the default themes, so its checksum manifest
 * lists them — 444 files under wp-content in 7.1.3. Updating Akismet, which is
 * correct maintenance, then made 21 "modified core files" appear. And the
 * "Silence is golden" index.php that WordPress drops into directories it
 * creates was reported as executable code smuggled into uploads.
 */
class BundledAndGuardTest extends TestCase {

    private string $dir;

    protected function setUp(): void {
        parent::setUp();
        $this->dir = sys_get_temp_dir() . '/dpxl-guard-' . uniqid();
        mkdir($this->dir);
    }

    protected function tearDown(): void {
        array_map('unlink', glob($this->dir . '/*') ?: []);
        @rmdir($this->dir);
        parent::tearDown();
    }

    private function guard(string $name, string $content): bool {
        $path = $this->dir . '/' . $name;
        file_put_contents($path, $content);

        $m = new \ReflectionMethod(MalwareScanner::class, 'isDirectoryIndexGuard');
        $m->setAccessible(true);

        return (bool) $m->invoke(null, $path);
    }

    /** The exact file WordPress writes. */
    public function testSilenceIsGoldenIsAGuard(): void {
        $this->assertTrue($this->guard('index.php', "<?php\n// Silence is golden."));
    }

    public function testEmptyAndCommentOnlyVariantsAreGuards(): void {
        $this->assertTrue($this->guard('index.php', '<?php'));
        $this->assertTrue($this->guard('index.php', "<?php\n/* nothing to see */\n"));
        $this->assertTrue($this->guard('index.php', "<?php\n# silence\n"));
    }

    /** A guard carrying real code is not a guard. */
    public function testIndexWithCodeIsNotAGuard(): void {
        $this->assertFalse($this->guard('index.php', '<?php system($_GET["c"]);'));
        $this->assertFalse($this->guard('index.php', "<?php\n// comment\neval(\$_POST['x']);"));
    }

    /** Only index.php earns the exemption — a shell cannot opt in by being terse. */
    public function testOtherFilenamesAreNotGuards(): void {
        $this->assertFalse($this->guard('shell.php', "<?php\n// Silence is golden."));
    }

    /** Size is a bound, so a large file cannot hide behind comments. */
    public function testOversizedCommentFileIsNotAGuard(): void {
        $this->assertFalse($this->guard('index.php', "<?php\n// " . str_repeat('x', 600)));
    }
}
