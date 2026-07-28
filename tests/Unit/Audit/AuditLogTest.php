<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Audit;

use Brain\Monkey;
use Brain\Monkey\Functions;
use DPXL\Shield\Audit\AuditLog;
use DPXL\Shield\Audit\AuditEvents;
use PHPUnit\Framework\TestCase;

class AuditLogTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();

        Functions\stubs([
            'get_option'     => fn($key, $default = false) => $key === 'dpxl_shield_audit_mode' ? 'all_events' : $default,
            'update_option'  => true,
            'current_time'   => fn($type) => $type === 'timestamp' ? time() : date('Y-m-d H:i:s'),
            'absint'         => fn($v) => abs((int) $v),
        ]);
    }

    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }

    public function testGenesisHashIsAllZeros(): void {
        $genesis = AuditLog::genesisHash();

        $this->assertSame(64, strlen($genesis));
        $this->assertSame(str_repeat('0', 64), $genesis);
    }

    public function testHashChainLinkIsConsistent(): void {
        $ts       = '2026-01-01 00:00:00';
        $type     = AuditEvents::AUTH_LOGIN_SUCCESS;
        $desc     = 'User admin logged in';
        $prevHash = str_repeat('0', 64);

        $hash1 = AuditLog::computeHash($ts, $type, $desc, $prevHash);
        $hash2 = AuditLog::computeHash($ts, $type, $desc, $prevHash);

        $this->assertSame(64, strlen($hash1));
        $this->assertSame($hash1, $hash2, 'Same inputs must produce same hash');
    }

    public function testHashChainChangesWithDifferentInput(): void {
        $prevHash = str_repeat('0', 64);
        $ts       = '2026-01-01 00:00:00';

        $hash1 = AuditLog::computeHash($ts, 'auth.login.success', 'User A logged in', $prevHash);
        $hash2 = AuditLog::computeHash($ts, 'auth.login.success', 'User B logged in', $prevHash);

        $this->assertNotSame($hash1, $hash2);
    }

    public function testHashIsHexString(): void {
        $hash = AuditLog::computeHash(
            '2026-01-01 00:00:00',
            AuditEvents::AUTH_LOGIN_FAILURE,
            'Failed login',
            str_repeat('0', 64)
        );

        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $hash);
    }

    public function testSignificantEventFilterExcludesContentEvents(): void {
        $this->assertFalse(
            AuditEvents::isSignificant(AuditEvents::CONTENT_POST_UPDATED),
            'Content events are not significant by default'
        );

        $this->assertTrue(
            AuditEvents::isSignificant(AuditEvents::AUTH_LOGIN_FAILURE),
            'Auth events are always significant'
        );
    }

    public function testEventCategoryMapping(): void {
        // Assert against the CATEGORY_* constants, not their string values, so
        // the test stays correct if a category label is ever renamed.
        $this->assertSame(AuditEvents::CATEGORY_AUTH,     AuditEvents::category(AuditEvents::AUTH_LOGIN_SUCCESS));
        $this->assertSame(AuditEvents::CATEGORY_FIREWALL, AuditEvents::category(AuditEvents::FW_IP_BLOCKED));
        $this->assertSame(AuditEvents::CATEGORY_SETTINGS, AuditEvents::category(AuditEvents::SETTINGS_UPDATED));
        $this->assertSame(AuditEvents::CATEGORY_PLUGIN,   AuditEvents::category(AuditEvents::PLUGIN_ACTIVATED));
    }
}
