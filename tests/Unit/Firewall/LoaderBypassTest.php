<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Firewall;

use DPXL\Shield\Bootstrap\Loader;
use PHPUnit\Framework\TestCase;

/**
 * Locks the pre-WordPress WAF bypass (v1.0.19 fix): wp-admin, wp-login and
 * authenticated REST/admin-ajax requests must skip the early WAF, while public
 * unauthenticated requests must not. Regressions here reintroduce HTTP 500s on
 * page-builder saves — or, worse, silently disable the WAF for public traffic.
 */
class LoaderBypassTest extends TestCase {

    private const LOGGED_IN = ['wordpress_logged_in_abc123' => 'value'];

    // ── Must bypass ────────────────────────────────────────────────────────

    public function testWpAdminBypasses(): void {
        $this->assertTrue(Loader::shouldBypassEarlyWaf('/wp-admin/post.php', []));
    }

    public function testWpLoginBypasses(): void {
        $this->assertTrue(Loader::shouldBypassEarlyWaf('/wp-login.php', []));
    }

    public function testRestWithLoginCookieBypasses(): void {
        $this->assertTrue(Loader::shouldBypassEarlyWaf('/wp-json/wp/v2/posts', self::LOGGED_IN));
    }

    public function testAdminAjaxWithLoginCookieBypasses(): void {
        $this->assertTrue(Loader::shouldBypassEarlyWaf('/wp-admin/admin-ajax.php', self::LOGGED_IN));
    }

    // ── Must NOT bypass ────────────────────────────────────────────────────

    public function testPublicRootDoesNotBypass(): void {
        $this->assertFalse(Loader::shouldBypassEarlyWaf('/', []));
    }

    public function testPublicPageDoesNotBypass(): void {
        $this->assertFalse(Loader::shouldBypassEarlyWaf('/about-us/', []));
    }

    public function testRestWithoutLoginCookieDoesNotBypass(): void {
        // Unauthenticated REST hit (e.g. a scraper) still gets WAF-filtered.
        $this->assertFalse(Loader::shouldBypassEarlyWaf('/wp-json/wp/v2/users', []));
    }

    public function testRestWithUnrelatedCookieDoesNotBypass(): void {
        $this->assertFalse(
            Loader::shouldBypassEarlyWaf('/wp-json/wp/v2/posts', ['some_other_cookie' => '1'])
        );
    }

    /**
     * The login cookie only grants a bypass on auth endpoints — a public URL
     * carrying the cookie is still filtered (defence in depth).
     */
    public function testPublicUrlWithLoginCookieStillFiltered(): void {
        $this->assertFalse(Loader::shouldBypassEarlyWaf('/?s=<script>', self::LOGGED_IN));
    }
}
