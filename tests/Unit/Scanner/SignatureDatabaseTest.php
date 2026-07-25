<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Scanner;

use DPXL\Shield\Scanner\SignatureDatabase;
use PHPUnit\Framework\TestCase;

/**
 * SignatureDatabase::match() returns a single matched signature
 * (['id','name','severity']) or null. The database is intentionally
 * conservative — it flags high-confidence malware, not every scary-looking
 * function — so these tests lock both the detections AND the non-detections.
 */
class SignatureDatabaseTest extends TestCase {

    public function testKnownWebshellDetected(): void {
        $db = new SignatureDatabase();

        $match = $db->match('<?php $x = "wso_ver"; ?>');

        $this->assertNotNull($match, 'A known webshell signature must be flagged');
        $this->assertSame('sig-wso', $match['id']);
        $this->assertSame('critical', $match['severity']);
    }

    public function testShellExecFromUserInputDetected(): void {
        $db = new SignatureDatabase();

        $match = $db->match('<?php shell_exec($_POST["c"]); ?>');

        $this->assertNotNull($match, 'shell_exec() on user input must be flagged');
        $this->assertSame('critical', $match['severity']);
    }

    public function testObfuscatedEvalWithLongPayloadDetected(): void {
        $db      = new SignatureDatabase();
        $payload = base64_encode(str_repeat('A', 120)); // > 100 chars, matches sig-eval-b64
        $content = '<?php eval(base64_decode("' . $payload . '")); ?>';

        $match = $db->match($content);

        $this->assertNotNull($match, 'eval(base64_decode(<long payload>)) must be flagged');
    }

    public function testCleanCodeReturnsNull(): void {
        $db = new SignatureDatabase();

        $this->assertNull($db->match('<?php echo "Hello, World!"; ?>'));
    }

    /**
     * Conservative-by-design: a short base64 eval is NOT flagged, because the
     * signature requires a 100+ char payload. This documents the anti-false-
     * positive behavior — legitimate code often contains short base64.
     */
    public function testShortBase64EvalNotFlagged(): void {
        $db = new SignatureDatabase();

        $this->assertNull($db->match('<?php eval(base64_decode("aGVsbG8=")); ?>'));
    }

    public function testMatchShapeAndSignatureCount(): void {
        $db = new SignatureDatabase();

        $this->assertGreaterThan(0, $db->count(), 'The database must load signatures');

        $match = $db->match('<?php c99_buff_prepare(); ?>');
        $this->assertNotNull($match);
        foreach (['id', 'name', 'severity'] as $key) {
            $this->assertArrayHasKey($key, $match);
        }
    }
}
