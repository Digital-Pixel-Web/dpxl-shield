<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Alerts;

use Brain\Monkey;
use Brain\Monkey\Actions;
use Brain\Monkey\Functions;
use DPXL\Shield\Alerts\SmtpMonitor;
use PHPUnit\Framework\TestCase;

/**
 * Monitoring the channel every other alert travels on.
 *
 * The failure mode worth guarding here is not a missed alert but a loop: the
 * alert saying mail is broken is itself dispatched through the pipeline that
 * sends mail, which fails, which fires `wp_mail_failed` again. Unguarded, one
 * failed message becomes an unbounded cascade inside a single request.
 */
class SmtpMonitorTest extends TestCase {

    /** @var array<string,mixed> */
    private array $options = [];

    /**
     * Alerts fired during the test.
     *
     * Captured once, in setUp: registering a second listener inside a test
     * silently replaces the first, and the replacement never sees what the
     * earlier calls fired.
     *
     * @var list<array<string,mixed>>
     */
    private array $fired = [];

    /**
     * Run whenever an alert is dispatched, from inside the dispatch.
     *
     * This is how re-entrancy is reproduced: Brain\Monkey executes a
     * `whenHappen` callback, but it does NOT run callbacks added with
     * `add_action`, so hooking the action would simulate nothing at all.
     *
     * @var callable|null
     */
    private $onAlertFired = null;

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();

        $this->options = [];

        Functions\when('current_time')->justReturn('2026-10-14 12:00:00');
        Functions\when('get_option')->alias(fn($k, $d = false) => $this->options[$k] ?? $d);
        Functions\when('update_option')->alias(function ($k, $v, $a = null) {
            $this->options[$k] = $v;
            return true;
        });

        $this->fired = [];

        Actions\expectDone('dpxl_shield_alert')->zeroOrMoreTimes()->whenHappen(
            function (array $alert): void {
                $this->fired[] = $alert;

                if ($this->onAlertFired !== null) {
                    ($this->onAlertFired)($alert);
                }
            }
        );
    }

    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }

    private function error(string $message): \WP_Error {
        return new \WP_Error('wp_mail_failed', $message);
    }

    /**
     * @return list<array<string,mixed>>
     */
    private function failTimes(int $times, string $message = 'SMTP connect() failed'): array {
        $monitor = new SmtpMonitor();
        $before  = count($this->fired);

        for ($i = 0; $i < $times; $i++) {
            $monitor->onFailure($this->error($message));
        }

        return array_slice($this->fired, $before);
    }

    /** One refused recipient or one timeout is not an outage. */
    public function testSingleFailureDoesNotAlert(): void {
        $this->assertSame([], $this->failTimes(1));
    }

    public function testSecondConsecutiveFailureAlerts(): void {
        $alerts = $this->failTimes(2);

        $this->assertCount(1, $alerts);
        $this->assertSame('smtp_failure', $alerts[0]['event_type']);
        $this->assertSame('high', $alerts[0]['level']);
    }

    /**
     * A broken relay fails every queued message. One alert per outage, or the
     * fact is buried in the channels that still work.
     */
    public function testOutageAlertsOnceNotPerMessage(): void {
        $this->assertCount(1, $this->failTimes(25));
    }

    /** The error text is what tells the reader where to look. */
    public function testAlertCarriesTheServerError(): void {
        $alerts = $this->failTimes(2, 'SMTP Error: Could not authenticate.');

        $this->assertStringContainsString('Could not authenticate', $alerts[0]['description']);
        $this->assertStringContainsString('Could not authenticate', $alerts[0]['context']['last_error']);
    }

    /**
     * The loop that the guard actually prevents.
     *
     * The recovery alert goes out the instant mail starts working, so it is the
     * send most likely to meet a relay that is only half back. If its own
     * failure re-enters the failure handler, the announcement that an outage
     * ended opens a new one from inside itself — and the site reports an
     * outage that only its own alert created.
     *
     * The failure path is covered twice over — by the guard and by the
     * once-per-outage flag, either of which alone would hold it. This path has
     * only the guard, which is why it is the test that can actually fail.
     */
    public function testRecoveryAlertDoesNotOpenAFreshOutageWhenItsOwnSendFails(): void {
        $monitor = new SmtpMonitor();

        $this->failTimes(2);

        $this->onAlertFired = function (array $alert) use ($monitor): void {
            if ($alert['event_type'] !== 'smtp_recovered') {
                return;
            }

            // The recovery email itself fails to go out.
            $monitor->onFailure($this->error('SMTP connect() failed'));
        };

        $monitor->onSuccess();

        $this->assertSame(
            0,
            SmtpMonitor::status()['failures'],
            'a failing recovery email must not restart the outage counter'
        );
    }

    /**
     * The failure path's own cascade: a broken relay fails the alert's send
     * too, re-entering the handler.
     *
     * Two mechanisms cover this one — the re-entrancy guard and the
     * once-per-outage flag — and removing either alone still passes, so this
     * is a regression test rather than a proof of any single mechanism.
     */
    public function testFailureAlertDoesNotCascadeOnItsOwnSend(): void {
        $monitor = new SmtpMonitor();

        $this->onAlertFired = function () use ($monitor): void {
            $monitor->onFailure($this->error('SMTP connect() failed'));
        };

        $monitor->onFailure($this->error('SMTP connect() failed'));
        $monitor->onFailure($this->error('SMTP connect() failed'));

        $this->assertCount(1, $this->fired, 'one outage must produce one alert');
    }

    /** Recovery is the moment the reader can finally be reached. */
    public function testRecoveryAfterAnAnnouncedOutageAlerts(): void {
        $this->failTimes(2);
        $before = count($this->fired);

        (new SmtpMonitor())->onSuccess();

        $recovery = array_slice($this->fired, $before);

        $this->assertCount(1, $recovery);
        $this->assertSame('smtp_recovered', $recovery[0]['event_type']);
    }

    /** A blip that healed before anyone was told is not news either way. */
    public function testRecoveryFromAnUnannouncedBlipIsSilent(): void {
        $this->failTimes(1);
        $before = count($this->fired);

        (new SmtpMonitor())->onSuccess();

        $this->assertSame([], array_slice($this->fired, $before));
    }

    /** A later outage must be able to alert again. */
    public function testOutageAfterRecoveryAlertsAgain(): void {
        $this->failTimes(2);
        (new SmtpMonitor())->onSuccess();

        $this->assertCount(1, $this->failTimes(2));
    }

    public function testStatusReportsHealthyWhenNothingFailed(): void {
        $this->assertTrue(SmtpMonitor::status()['healthy']);
    }

    public function testStatusReportsUnhealthyDuringAnOutage(): void {
        $this->failTimes(2);

        $status = SmtpMonitor::status();

        $this->assertFalse($status['healthy']);
        $this->assertSame(2, $status['failures']);
    }

    public function testDurationIsHumanReadable(): void {
        $this->assertSame('30 min', SmtpMonitor::humanDuration('2026-10-14 12:00:00', '2026-10-14 12:30:00'));
        $this->assertSame('2 h 15 min', SmtpMonitor::humanDuration('2026-10-14 12:00:00', '2026-10-14 14:15:00'));
        $this->assertSame('—', SmtpMonitor::humanDuration('', ''));
    }

    /** A failure with no WP_Error must still produce a readable line. */
    public function testMissingErrorObjectStillYieldsAMessage(): void {
        $this->assertNotSame('', SmtpMonitor::errorMessage(null));
    }
}
