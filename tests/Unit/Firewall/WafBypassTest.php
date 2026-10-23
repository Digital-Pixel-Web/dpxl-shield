<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Firewall;

use DPXL\Shield\Firewall\WafBypass;
use PHPUnit\Framework\TestCase;

/**
 * Locks the two WAF bypasses closed: matching on the query string, and
 * treating the anonymous admin-ajax / admin-post endpoints (or a forged login
 * cookie) as an administrator.
 */
class WafBypassTest extends TestCase {

    private const COOKIE = ['wordpress_logged_in_abc123' => 'forged'];

    public function testQueryStringCannotFakeAnAdminPath(): void {
        $this->assertFalse(WafBypass::shouldDeferEarly('/?s=<script>&x=/wp-admin/', []));
        $this->assertFalse(WafBypass::shouldDeferEarly('/?redirect=/wp-login.php', []));
        $this->assertFalse(WafBypass::shouldDeferEarly('/?a=/wp-json/', self::COOKIE));
    }

    public function testAnonymousAdminAjaxIsFiltered(): void {
        $this->assertFalse(WafBypass::shouldDeferEarly('/wp-admin/admin-ajax.php', []));
        $this->assertFalse(WafBypass::shouldDeferEarly('/wp-admin/admin-post.php?action=x', []));
        $this->assertFalse(WafBypass::shouldBypassForUser('/wp-admin/admin-ajax.php', false));
    }

    public function testDuplicateSlashesAndEncodingDoNotHideTheEndpoint(): void {
        $this->assertTrue(WafBypass::isPublicAdminEndpoint('//wp-admin//admin-ajax.php'));
        $this->assertTrue(WafBypass::isPublicAdminEndpoint('/wp-admin/admin%2Dajax.php'));
    }

    public function testAdminScreensAreDeferredNotSkipped(): void {
        $this->assertTrue(WafBypass::shouldDeferEarly('/wp-admin/post.php', []));
        $this->assertTrue(WafBypass::shouldDeferEarly('/wp-login.php', []));
        // In WordPress, only a validated session skips the rules.
        $this->assertFalse(WafBypass::shouldBypassForUser('/wp-admin/post.php', false));
        $this->assertTrue(WafBypass::shouldBypassForUser('/wp-admin/post.php', true));
    }

    public function testApiWithCookieIsDeferredAndNeedsValidation(): void {
        $this->assertTrue(WafBypass::shouldDeferEarly('/wp-json/wp/v2/posts', self::COOKIE));
        $this->assertTrue(WafBypass::shouldDeferEarly('/?rest_route=/wp/v2/posts', self::COOKIE));
        $this->assertFalse(WafBypass::shouldBypassForUser('/wp-json/wp/v2/posts', false));
        $this->assertTrue(WafBypass::shouldBypassForUser('/wp-json/wp/v2/posts', true));
    }

    public function testPublicPagesAreNeverBypassed(): void {
        $this->assertFalse(WafBypass::shouldBypassForUser('/?s=<script>', true));
        $this->assertFalse(WafBypass::shouldDeferEarly('/about/', self::COOKIE));
    }

    public function testEmptyCookieValueIsNotALogin(): void {
        $this->assertFalse(WafBypass::hasLoginCookie(['wordpress_logged_in_x' => '']));
    }
}
