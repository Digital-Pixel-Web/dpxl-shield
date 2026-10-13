<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Scanner;

use Brain\Monkey;
use Brain\Monkey\Functions;
use DPXL\Shield\Scanner\MalwareScanner;
use DPXL\Shield\Scanner\ScanOrchestrator;
use PHPUnit\Framework\TestCase;

/**
 * Two ways the scanner inflated its own critical count.
 *
 * Plugins generate PHP under uploads as part of normal operation, and every
 * scan re-recorded findings it had already recorded. Between them, 34 files
 * became 2,380 open critical findings on a healthy site — and a critical count
 * that large is one nobody reads.
 */
class UploadsAndDedupeTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();
        Functions\when('wp_normalize_path')->alias(fn($p) => str_replace('\\', '/', $p));
    }

    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }

    private function isPluginDir(string $path): bool {
        $m = new \ReflectionMethod(MalwareScanner::class, 'isPluginWorkingDirectory');
        $m->setAccessible(true);

        return (bool) $m->invoke(null, $path);
    }

    /** The real case: WPML compiles Twig templates to PHP under uploads. */
    public function testWpmlTwigCacheIsRecognisedAsPluginOutput(): void {
        $this->assertTrue($this->isPluginDir('/var/www/wp-content/uploads/cache/wpml/twig/06/06ecab00.php'));
    }

    /** @dataProvider pluginDirectories */
    public function testKnownPluginDirectoriesAreRecognised(string $path): void {
        $this->assertTrue($this->isPluginDir($path));
    }

    /** @return list<array{string}> */
    public static function pluginDirectories(): array {
        return [
            ['/srv/wp-content/uploads/elementor/css/post-7.php'],
            ['/srv/wp-content/uploads/wp-rocket/config/example.php'],
            ['/srv/wp-content/uploads/litespeed/cache/x.php'],
        ];
    }

    /**
     * Where media actually lands. A PHP file here is the threat the check was
     * written for and must stay critical.
     */
    public function testMediaDirectoryIsNotTreatedAsPluginOutput(): void {
        $this->assertFalse($this->isPluginDir('/var/www/wp-content/uploads/2026/10/shell.php'));
        $this->assertFalse($this->isPluginDir('/var/www/wp-content/uploads/evil.php'));
    }

    /** Case should not decide a security verdict. */
    public function testMatchIsCaseInsensitive(): void {
        $this->assertTrue($this->isPluginDir('/var/www/wp-content/Uploads/Cache/WPML/x.php'));
    }

    // ── Cross-scan identity ────────────────────────────────────────────────

    /** @param array<string,mixed> $row */
    private function key(array $row): string {
        $m = new \ReflectionMethod(ScanOrchestrator::class, 'findingKey');
        $m->setAccessible(true);

        return (string) $m->invoke(null, $row);
    }

    /** The same finding seen twice must be recognised as one, not two. */
    public function testSameFindingHasStableIdentityAcrossScans(): void {
        $first  = ['file_path' => '/srv/wp-content/uploads/cache/wpml/a.php', 'issue_type' => 'php_in_uploads', 'signature_id' => null];
        $second = ['file_path' => '/srv/wp-content/uploads/cache/wpml/a.php', 'issue_type' => 'php_in_uploads', 'signature_id' => null];

        $this->assertSame($this->key($first), $this->key($second));
    }

    public function testDifferentFilesAreDifferentFindings(): void {
        $a = ['file_path' => '/srv/uploads/a.php', 'issue_type' => 'php_in_uploads', 'signature_id' => null];
        $b = ['file_path' => '/srv/uploads/b.php', 'issue_type' => 'php_in_uploads', 'signature_id' => null];

        $this->assertNotSame($this->key($a), $this->key($b));
    }

    /** Two different problems in one file are two findings. */
    public function testDifferentIssueTypesInOneFileAreDistinct(): void {
        $a = ['file_path' => '/srv/x.php', 'issue_type' => 'malware_signature', 'signature_id' => 'sig-wso'];
        $b = ['file_path' => '/srv/x.php', 'issue_type' => 'heuristic', 'signature_id' => null];

        $this->assertNotSame($this->key($a), $this->key($b));
    }

    /** Identity must not depend on the details text, which carries counts and dates. */
    public function testIdentityIgnoresDetailsText(): void {
        $a = ['file_path' => '/srv/x.php', 'issue_type' => 'php_in_uploads', 'signature_id' => null, 'details' => 'seen once'];
        $b = ['file_path' => '/srv/x.php', 'issue_type' => 'php_in_uploads', 'signature_id' => null, 'details' => 'seen again later'];

        $this->assertSame($this->key($a), $this->key($b));
    }
}
