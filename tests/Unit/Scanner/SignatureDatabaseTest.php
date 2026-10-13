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

    /**
     * The shape that was reported as malware on two staging installs for
     * months: a login-page customizer whose admin screen has a "disable
     * registration" switch, so it writes the option both ways. Opening
     * registration is what that setting is for — on its own it is not a
     * finding, whichever value it writes.
     */
    public function testRegistrationToggleAloneIsNotFlagged(): void {
        $db = new SignatureDatabase();

        $content = <<<'PHP'
        <?php
        public function maybe_disable_registration() {
            $options = get_option( ASENHA_SLUG_U, array() );
            $login_page_disable_registration = isset( $options['login_page_disable_registration'] ) ? $options['login_page_disable_registration'] : 'center';

            if ( $login_page_disable_registration ) {
                update_option( 'users_can_register', 0 );
            } else {
                update_option( 'users_can_register', 1 );
            }
        }
        PHP;

        $this->assertNull($db->match($content, 'php'), 'A registration setting being written is normal plugin behaviour');
    }

    /**
     * Elevating the default role is the other half, and equally ordinary on
     * its own: a membership plugin saves whatever role its admin chose.
     */
    public function testDefaultRoleWriteAloneIsNotFlagged(): void {
        $db = new SignatureDatabase();

        $this->assertNull($db->match('<?php update_option( \'default_role\', \'administrator\' );', 'php'));
    }

    /**
     * Together they are the backdoor: anyone may sign up, and everyone who
     * does becomes an administrator. No settings screen asks for that.
     */
    public function testRegistrationOpenedWithAdminDefaultRoleIsFlagged(): void {
        $db = new SignatureDatabase();

        $content = '<?php update_option("users_can_register", 1); update_option("default_role", "administrator");';

        $match = $db->match($content, 'php');

        $this->assertNotNull($match, 'Open registration plus administrator as default role must be flagged');
        $this->assertSame('sig-wp-open-registration-admin-role', $match['id']);
        $this->assertSame('high', $match['severity']);
    }

    /**
     * `regex_all` requires every pattern, in any order — a dropper writing the
     * role first must not slip through.
     */
    public function testTheCombinationIsFlaggedInEitherOrder(): void {
        $db = new SignatureDatabase();

        $content = "<?php\nadd_option('default_role', 'administrator');\n// ... 40 lines of padding ...\nadd_option('users_can_register', '1');\n";

        $match = $db->match($content, 'php');

        $this->assertNotNull($match, 'Order must not decide whether the pair is flagged');
        $this->assertSame('sig-wp-open-registration-admin-role', $match['id']);
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
