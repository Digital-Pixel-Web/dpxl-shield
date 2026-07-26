<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\LoginSecurity;

use Brain\Monkey;
use Brain\Monkey\Functions;
use DPXL\Shield\LoginSecurity\BackupCodes;
use PHPUnit\Framework\TestCase;

/**
 * Covers backup-code verification: format validation, input normalization and
 * one-time consumption. TOTP itself is delegated to spomky-labs/otphp; here we
 * lock the parts DPXL Shield owns.
 */
class BackupCodesTest extends TestCase {

    /** @var string[] Bcrypt hashes returned by the stubbed get_user_meta. */
    private array $storedHashes;

    /** @var mixed Captures whatever update_user_meta writes back. */
    private mixed $written = null;

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();

        // Two valid codes: 'a1b2c3d4' and 'deadbeef'.
        $this->storedHashes = [
            password_hash('a1b2c3d4', PASSWORD_BCRYPT, ['cost' => 4]),
            password_hash('deadbeef', PASSWORD_BCRYPT, ['cost' => 4]),
        ];

        Functions\when('get_user_meta')->justReturn($this->storedHashes);
        Functions\when('update_user_meta')->alias(function ($id, $key, $value) {
            $this->written = $value;
            return true;
        });
    }

    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }

    public function testValidCodeVerifies(): void {
        $this->assertTrue(BackupCodes::verify(1, 'a1b2c3d4'));
    }

    public function testCodeIsConsumedOnUse(): void {
        BackupCodes::verify(1, 'a1b2c3d4');

        $this->assertIsArray($this->written);
        $this->assertCount(1, $this->written, 'The used code must be removed');
        // The remaining hash must be the OTHER code, not the consumed one.
        $this->assertTrue(password_verify('deadbeef', $this->written[0]));
        $this->assertFalse(password_verify('a1b2c3d4', $this->written[0]));
    }

    public function testNormalizesSpacesDashesAndCase(): void {
        // Same code, formatted the way it is shown to the user.
        $this->assertTrue(BackupCodes::verify(1, 'A1B2-C3D4'));
        $this->assertTrue(BackupCodes::verify(1, 'a1 b2 c3 d4'));
    }

    public function testWrongCodeIsRejected(): void {
        $this->assertFalse(BackupCodes::verify(1, 'ffffffff'));
        $this->assertNull($this->written, 'Nothing should be consumed on a failed attempt');
    }

    public function testMalformedInputRejectedWithoutLookup(): void {
        // Not 8 hex chars → rejected before touching stored codes.
        $this->assertFalse(BackupCodes::verify(1, 'short'));
        $this->assertFalse(BackupCodes::verify(1, 'zzzzzzzz'));       // non-hex
        $this->assertFalse(BackupCodes::verify(1, 'a1b2c3d4e5'));     // too long
    }
}
