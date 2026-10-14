<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\LoginSecurity;

use Brain\Monkey;
use Brain\Monkey\Actions;
use Brain\Monkey\Functions;
use DPXL\Shield\LoginSecurity\LoginAudit;
use PHPUnit\Framework\TestCase;

/**
 * Alerting on administrator sign-ins.
 *
 * Until now an alert went out only the first time an account signed in from a
 * given network, so a routine sign-in from the usual place was silent — and the
 * sign-in that was not you looked exactly like the silence. This is the one
 * alert whose value depends on arriving every time.
 *
 * What it must not do is send two emails for one sign-in: a first-seen network
 * is the stronger signal and has its own alert, which already covers the login.
 */
class AdminLoginAlertTest extends TestCase {

    /** @var list<string> */
    private array $knownIps = [];

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();

        $this->knownIps = [];

        Functions\when('wp_normalize_path')->alias(fn($p) => $p);
        Functions\when('current_time')->justReturn('2026-10-14 10:34:03');
        Functions\when('get_user_meta')->alias(fn($id, $key, $single) => $this->knownIps);
        Functions\when('update_user_meta')->alias(function ($id, $key, $value) {
            $this->knownIps = $value;
            return true;
        });

        $_SERVER['REMOTE_ADDR']    = '201.58.91.196';
        $_SERVER['HTTP_USER_AGENT'] = 'Test';

        global $wpdb;
        $wpdb = new class {
            public string $prefix = 'wp_';
            /** @param array<string,mixed> $data @param list<string> $format */
            public function insert(string $table, array $data, array $format = []): int { return 1; }
        };
    }

    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }

    private function user(bool $isAdmin = true): \WP_User {
        Functions\when('user_can')->justReturn($isAdmin);

        $user = new \WP_User();
        $user->ID = 7;

        return $user;
    }

    /**
     * Runs a sign-in and returns the alerts it fired.
     *
     * @return list<array<string,mixed>>
     */
    private function alertsFrom(string $login, \WP_User $user): array {
        $fired = [];

        Actions\expectDone('dpxl_shield_alert')->zeroOrMoreTimes()->whenHappen(
            function (array $alert) use (&$fired): void {
                $fired[] = $alert;
            }
        );

        (new LoginAudit())->onLoginSuccess($login, $user);

        return $fired;
    }

    private function setAlertEnabled(bool $enabled): void {
        Functions\when('get_option')->alias(
            fn($name, $default = null) => $name === 'dpxl_shield_alert_admin_login_enabled' ? $enabled : null
        );
    }

    /** The reported case: signing in from the usual network produced nothing. */
    public function testKnownNetworkSignInNowAlerts(): void {
        $this->setAlertEnabled(true);
        $this->knownIps = ['201.58.91.196'];

        $alerts = $this->alertsFrom('digitalpixel', $this->user());

        $this->assertCount(1, $alerts);
        $this->assertSame('admin_login', $alerts[0]['event_type']);
    }

    /** A first-seen network keeps its own, more specific alert — and only that one. */
    public function testNewNetworkSendsOnlyTheNewNetworkAlert(): void {
        $this->setAlertEnabled(true);
        $this->knownIps = [];

        $alerts = $this->alertsFrom('digitalpixel', $this->user());

        $this->assertCount(1, $alerts, 'one sign-in must not produce two emails');
        $this->assertSame('new_admin_ip_login', $alerts[0]['event_type']);
    }

    /** Switching it off must not silence the new-network alert as well. */
    public function testDisabledSettingStillAllowsTheNewNetworkAlert(): void {
        $this->setAlertEnabled(false);
        $this->knownIps = [];

        $alerts = $this->alertsFrom('digitalpixel', $this->user());

        $this->assertCount(1, $alerts);
        $this->assertSame('new_admin_ip_login', $alerts[0]['event_type']);
    }

    public function testDisabledSettingSilencesTheRoutineAlert(): void {
        $this->setAlertEnabled(false);
        $this->knownIps = ['201.58.91.196'];

        $this->assertSame([], $this->alertsFrom('digitalpixel', $this->user()));
    }

    /** Only administrators. A subscriber signing in is not news. */
    public function testNonAdminSignInIsNotAlerted(): void {
        $this->setAlertEnabled(true);
        $this->knownIps = [];

        $this->assertSame([], $this->alertsFrom('assinante', $this->user(false)));
    }

    /** The alert must carry who and from where, or the reader cannot act on it. */
    public function testAlertCarriesUsernameAndAddress(): void {
        $this->setAlertEnabled(true);
        $this->knownIps = ['201.58.91.196'];

        $alert = $this->alertsFrom('digitalpixel', $this->user())[0];

        $this->assertSame('digitalpixel', $alert['context']['username']);
        $this->assertSame('201.58.91.196', $alert['context']['ip']);
        // Anything below medium is recorded but never emailed.
        $this->assertSame('medium', $alert['level']);
    }
}
