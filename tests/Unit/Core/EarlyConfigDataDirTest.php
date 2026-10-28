<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Core;

use DPXL\Shield\Core\EarlyConfig;
use PHPUnit\Framework\TestCase;

/**
 * Runtime files live outside the plugin folder, which WordPress replaces on
 * every update. Both the pre-WordPress loader and the plugin derive the same
 * folder: uploads/dpxl-shield beside the plugins folder.
 */
class EarlyConfigDataDirTest extends TestCase {

    private ?string $override = null;

    protected function setUp(): void {
        parent::setUp();

        // The bootstrap points the data folder at a temp dir; look past it.
        $this->override = EarlyConfig::dataDir();
        EarlyConfig::useDataDir(null);
    }

    protected function tearDown(): void {
        EarlyConfig::useDataDir($this->override);
        parent::tearDown();
    }

    public function testDataFolderIsInUploadsNotInThePlugin(): void {
        $pluginDir = dirname(__DIR__, 3);

        $this->assertSame(dirname($pluginDir, 2) . '/uploads/dpxl-shield', EarlyConfig::dataDir());
        $this->assertStringStartsNotWith($pluginDir . '/', EarlyConfig::dataDir() . '/');
    }

    public function testLegacyFolderIsTheOldDataFolderInsideThePlugin(): void {
        $this->assertSame(dirname(__DIR__, 3) . '/data', EarlyConfig::legacyDataDir());
    }

    public function testFilesTheFirewallReadsAreInTheDataFolder(): void {
        $dir = EarlyConfig::dataDir();

        $this->assertSame($dir . '/early-config.php', EarlyConfig::configPath());
        $this->assertSame($dir . '/blocked-ips.php', EarlyConfig::blockedIpsPath());
        $this->assertSame($dir . '/country.mmdb', \DPXL\Shield\Firewall\CountryBlocker::mmdbPath());
    }
}
