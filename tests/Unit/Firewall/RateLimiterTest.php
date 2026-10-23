<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Firewall;

use DPXL\Shield\Firewall\RateLimiter;
use PHPUnit\Framework\TestCase;

/**
 * Login attempts are counted, page loads and the two-factor code form are not.
 * Counting needs APCu (or WordPress); without it those tests are skipped.
 */
class RateLimiterTest extends TestCase {

    public function testLoginActionPrefersPostLikeWordPress(): void {
        $this->assertSame('login', RateLimiter::loginAction(['action' => 'dpxl_2fa'], ['action' => 'login']));
        $this->assertSame('dpxl_2fa', RateLimiter::loginAction(['action' => 'dpxl_2fa'], []));
        $this->assertSame('', RateLimiter::loginAction(['action' => ['dpxl_2fa']], []));
        $this->assertSame('', RateLimiter::loginAction([], []));
    }

    private function requireApcu(): void {
        if (!function_exists('apcu_inc') || !(bool) ini_get('apc.enable_cli')) {
            $this->markTestSkipped('APCu with apc.enable_cli is needed to count requests.');
        }

        apcu_clear_cache();
        RateLimiter::updateLimit('login', 5);
    }

    public function testTwoFactorStepDoesNotCount(): void {
        $this->requireApcu();
        $this->assertFalse(RateLimiter::isExceeded('203.0.113.9', '/wp-login.php', 'POST'));

        for ($i = 0; $i < 10; $i++) {
            $this->assertFalse(RateLimiter::isExceeded('203.0.113.9', '/wp-login.php?action=dpxl_2fa', 'POST', 'dpxl_2fa'));
        }
    }

    public function testPasswordPostsStillCount(): void {
        $this->requireApcu();
        $exceeded = false;

        for ($i = 0; $i < 6; $i++) {
            $exceeded = RateLimiter::isExceeded('203.0.113.10', '/wp-login.php?action=dpxl_2fa', 'POST', 'login');
        }

        $this->assertTrue($exceeded);
    }
}
