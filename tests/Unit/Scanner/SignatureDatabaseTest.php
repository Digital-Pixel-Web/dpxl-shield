<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Scanner;

use Brain\Monkey;
use Brain\Monkey\Functions;
use DPXL\Shield\Scanner\SignatureDatabase;
use PHPUnit\Framework\TestCase;

class SignatureDatabaseTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();
    }

    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }

    public function testEvalFunctionDetected(): void {
        $db      = new SignatureDatabase();
        $content = '<?php eval(base64_decode("aGVsbG8=")); ?>';

        $matches = $db->scan($content);

        $this->assertNotEmpty($matches, 'eval() with base64 should be flagged');
    }

    public function testBase64DecodeWithEvalDetected(): void {
        $db      = new SignatureDatabase();
        $content = '<?php $x = base64_decode("dGVzdA=="); eval($x); ?>';

        $matches = $db->scan($content);

        $this->assertNotEmpty($matches);
    }

    public function testCleanCodePassesScan(): void {
        $db      = new SignatureDatabase();
        $content = '<?php echo "Hello, World!"; ?>';

        $matches = $db->scan($content);

        $this->assertEmpty($matches, 'Clean code should produce no matches');
    }

    public function testObfuscatedVariableFunctionDetected(): void {
        $db      = new SignatureDatabase();
        $content = '<?php $f = "system"; $f($_GET["cmd"]); ?>';

        $matches = $db->scan($content);

        $this->assertNotEmpty($matches, 'Variable function with system() should be flagged');
    }

    public function testHexEncodedPayloadDetected(): void {
        $db      = new SignatureDatabase();
        // \x73\x79\x73\x74\x65\x6d = "system"
        $content = '<?php $c = "\x73\x79\x73\x74\x65\x6d"; $c("id"); ?>';

        $matches = $db->scan($content);

        $this->assertNotEmpty($matches, 'Hex-encoded strings should be flagged');
    }

    public function testShellExecDetected(): void {
        $db      = new SignatureDatabase();
        $content = '<?php shell_exec($_POST["c"]); ?>';

        $matches = $db->scan($content);

        $this->assertNotEmpty($matches);
    }

    public function testEachSignatureHasRequiredFields(): void {
        $db         = new SignatureDatabase();
        $signatures = $db->getSignatures();

        $this->assertNotEmpty($signatures);

        foreach ($signatures as $sig) {
            $this->assertArrayHasKey('id', $sig);
            $this->assertArrayHasKey('pattern', $sig);
            $this->assertArrayHasKey('severity', $sig);
            $this->assertArrayHasKey('description', $sig);
        }
    }
}
