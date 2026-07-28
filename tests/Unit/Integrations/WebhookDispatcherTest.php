<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Integrations;

use Brain\Monkey;
use Brain\Monkey\Functions;
use DPXL\Shield\Integrations\Event;
use DPXL\Shield\Integrations\Severity;
use DPXL\Shield\Integrations\WebhookDispatcher;
use DPXL\Shield\Integrations\WebhookEndpoint;
use PHPUnit\Framework\TestCase;

/**
 * Delivery semantics: what gets retried, what does not, what is signed, and
 * what the admin is told afterwards.
 */
class WebhookDispatcherTest extends TestCase {

    /** @var array<int,array{url:string,args:array}> Every POST the dispatcher attempted. */
    private $posts = [];

    /** @var array<string,mixed> Fake option store. */
    private $options = [];

    /** @var array<int,array{code:int}|string> Queued responses; string = WP_Error message. */
    private $responses = [];

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();

        $this->posts     = [];
        $this->options   = [];
        $this->responses = [];

        Functions\stubs([
            'wp_json_encode' => fn($data) => json_encode($data),
            'get_option'     => function ($key, $default = false) {
                return $this->options[$key] ?? $default;
            },
            'update_option'  => function ($key, $value) {
                $this->options[$key] = $value;
                return true;
            },
            'wp_parse_url'   => fn($url, $component = -1) => parse_url((string) $url, $component),
            '__'             => fn($text, $domain = null) => $text,
        ]);

        Functions\when('wp_remote_post')->alias(function ($url, $args) {
            $this->posts[] = ['url' => $url, 'args' => $args];

            $next = array_shift($this->responses);

            if ($next === null) {
                $next = ['code' => 200];
            }

            return is_string($next) ? new FakeWpError($next) : ['response' => ['code' => $next['code']], 'body' => ''];
        });

        Functions\when('is_wp_error')->alias(fn($thing) => $thing instanceof FakeWpError);
        Functions\when('wp_remote_retrieve_response_code')->alias(fn($r) => $r['response']['code'] ?? 0);
        Functions\when('wp_remote_retrieve_body')->alias(fn($r) => $r['body'] ?? '');
    }

    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }

    /** @param array<string,mixed> $overrides */
    private function configure(array $overrides = []): WebhookEndpoint {
        $data = array_merge([
            'id'        => 'ep1',
            'url'       => 'https://hooks.example.com/abc',
            'format'    => WebhookEndpoint::FORMAT_GENERIC,
            'min_level' => Severity::MEDIUM,
        ], $overrides);

        $this->options['dpxl_shield_webhook_endpoints'] = [$data];

        $endpoint = WebhookEndpoint::fromArray($data);
        $this->assertNotNull($endpoint);

        return $endpoint;
    }

    private function event(string $level = Severity::HIGH): Event {
        return new Event($level, 'fw.ip_blocked', 'IP blocked.', ['ip' => '1.2.3.4'], 1700000000);
    }

    // ── Severity routing ─────────────────────────────────────────────────────

    public function testAlertBelowThresholdIsNotDelivered(): void {
        $this->configure(['min_level' => Severity::HIGH]);

        $dispatcher = new WebhookDispatcher();
        $dispatcher->enqueue(Severity::MEDIUM, 'fw.ip_blocked', 'x');
        $dispatcher->flush();

        $this->assertSame([], $this->posts);
    }

    public function testAlertAtThresholdIsDelivered(): void {
        $this->configure(['min_level' => Severity::HIGH]);

        $dispatcher = new WebhookDispatcher();
        $dispatcher->enqueue(Severity::HIGH, 'fw.ip_blocked', 'x');
        $dispatcher->flush();

        $this->assertCount(1, $this->posts);
        $this->assertSame('https://hooks.example.com/abc', $this->posts[0]['url']);
    }

    public function testDisabledEndpointReceivesNothing(): void {
        $this->configure(['enabled' => false, 'min_level' => Severity::INFO]);

        $dispatcher = new WebhookDispatcher();
        $dispatcher->enqueue(Severity::CRITICAL, 'fw.ip_blocked', 'x');
        $dispatcher->flush();

        $this->assertSame([], $this->posts);
    }

    public function testNothingIsSentWhenNoEndpointIsConfigured(): void {
        $dispatcher = new WebhookDispatcher();
        $dispatcher->enqueue(Severity::CRITICAL, 'fw.ip_blocked', 'x');
        $dispatcher->flush();

        $this->assertSame([], $this->posts);
    }

    // ── Retry policy ─────────────────────────────────────────────────────────

    /**
     * A 5xx or a connection error is the remote's problem and may clear, so one
     * retry is worth it.
     */
    public function testServerErrorIsRetriedOnce(): void {
        $endpoint = $this->configure();
        $this->responses = [['code' => 503], ['code' => 200]];

        $result = (new WebhookDispatcher())->deliverNow($endpoint, $this->event());

        $this->assertCount(2, $this->posts);
        $this->assertSame(WebhookDispatcher::STATUS_OK, $result['status']);
    }

    public function testNetworkErrorIsRetriedOnce(): void {
        $endpoint = $this->configure();
        $this->responses = ['Connection timed out', ['code' => 200]];

        $result = (new WebhookDispatcher())->deliverNow($endpoint, $this->event());

        $this->assertCount(2, $this->posts);
        $this->assertSame(WebhookDispatcher::STATUS_OK, $result['status']);
    }

    /**
     * A 4xx means the request is wrong — revoked Slack hook, bad routing key.
     * Retrying just repeats the same mistake against the same endpoint.
     */
    public function testClientErrorIsNotRetried(): void {
        $endpoint = $this->configure();
        $this->responses = [['code' => 404], ['code' => 200]];

        $result = (new WebhookDispatcher())->deliverNow($endpoint, $this->event());

        $this->assertCount(1, $this->posts);
        $this->assertSame(WebhookDispatcher::STATUS_HTTP_FAIL, $result['status']);
        $this->assertSame(404, $result['code']);
    }

    public function testGivesUpAfterTheRetryIsAlsoExhausted(): void {
        $endpoint = $this->configure();
        $this->responses = [['code' => 500], ['code' => 500]];

        $result = (new WebhookDispatcher())->deliverNow($endpoint, $this->event());

        $this->assertCount(2, $this->posts);
        $this->assertSame(WebhookDispatcher::STATUS_HTTP_FAIL, $result['status']);
    }

    // ── Signing ──────────────────────────────────────────────────────────────

    public function testGenericPayloadIsSignedWhenASecretIsSet(): void {
        $endpoint = $this->configure(['secret' => 'shared-secret']);

        (new WebhookDispatcher())->deliverNow($endpoint, $this->event());

        $headers = $this->posts[0]['args']['headers'];

        $this->assertArrayHasKey('X-DPXL-Signature', $headers);
        $this->assertArrayHasKey('X-DPXL-Timestamp', $headers);

        // The signature must actually verify, and must cover the timestamp so a
        // captured payload cannot be replayed with a fresh one.
        $expected = 'sha256=' . hash_hmac(
            'sha256',
            $headers['X-DPXL-Timestamp'] . '.' . $this->posts[0]['args']['body'],
            'shared-secret'
        );

        $this->assertSame($expected, $headers['X-DPXL-Signature']);
    }

    public function testPayloadIsUnsignedWhenNoSecretIsSet(): void {
        $endpoint = $this->configure();

        (new WebhookDispatcher())->deliverNow($endpoint, $this->event());

        $this->assertArrayNotHasKey('X-DPXL-Signature', $this->posts[0]['args']['headers']);
    }

    /** Slack authenticates by URL; a signature header would be meaningless there. */
    public function testSlackPayloadIsNotSigned(): void {
        $endpoint = $this->configure(['format' => WebhookEndpoint::FORMAT_SLACK, 'secret' => 'x']);

        (new WebhookDispatcher())->deliverNow($endpoint, $this->event());

        $this->assertArrayNotHasKey('X-DPXL-Signature', $this->posts[0]['args']['headers']);
    }

    public function testSecretIsNeverPutInTheBody(): void {
        $endpoint = $this->configure(['secret' => 'shared-secret']);

        (new WebhookDispatcher())->deliverNow($endpoint, $this->event());

        $this->assertStringNotContainsString('shared-secret', $this->posts[0]['args']['body']);
    }

    // ── Transport hardening ──────────────────────────────────────────────────

    public function testDeliveryVerifiesTlsAndDoesNotFollowRedirects(): void {
        $endpoint = $this->configure();

        (new WebhookDispatcher())->deliverNow($endpoint, $this->event());

        $args = $this->posts[0]['args'];

        $this->assertTrue($args['sslverify']);
        // Following a redirect would let a compromised endpoint bounce the
        // payload — and its signature — to an attacker-chosen host.
        $this->assertSame(0, $args['redirection']);
        $this->assertTrue($args['blocking'], 'blocking, so failures are observable');
    }

    // ── Status reporting ─────────────────────────────────────────────────────

    public function testLastStatusIsRecordedForTheAdmin(): void {
        $endpoint = $this->configure();
        $this->responses = [['code' => 404]];

        (new WebhookDispatcher())->deliverNow($endpoint, $this->event());

        $status = $this->options['dpxl_shield_webhook_status']['ep1'];

        $this->assertSame(WebhookDispatcher::STATUS_HTTP_FAIL, $status['status']);
        $this->assertSame(404, $status['code']);
        $this->assertGreaterThan(0, $status['time']);
    }

    // ── Queue behaviour ──────────────────────────────────────────────────────

    public function testQueueIsDrainedSoASecondFlushSendsNothing(): void {
        $this->configure();

        $dispatcher = new WebhookDispatcher();
        $dispatcher->enqueue(Severity::HIGH, 'fw.ip_blocked', 'x');
        $dispatcher->flush();
        $dispatcher->flush();

        $this->assertCount(1, $this->posts);
    }

    /**
     * A volumetric attack can raise hundreds of alerts in one request; the cap
     * stops the shutdown handler from making hundreds of HTTP calls.
     */
    public function testQueueIsCappedAndTheOverflowIsAnnounced(): void {
        $this->configure(['min_level' => Severity::INFO]);

        $dispatcher = new WebhookDispatcher();

        for ($i = 0; $i < 50; $i++) {
            $dispatcher->enqueue(Severity::HIGH, 'fw.ip_blocked', "alert {$i}");
        }

        $dispatcher->flush();

        // 20 queued + 1 synthetic notice explaining the truncation.
        $this->assertCount(21, $this->posts);

        $bodies = array_map(fn($p) => $p['args']['body'], $this->posts);
        $this->assertStringContainsString('overflow', strtolower(implode(' ', $bodies)));
    }

    public function testEachEnabledEndpointGetsItsOwnCopy(): void {
        $this->options['dpxl_shield_webhook_endpoints'] = [
            ['id' => 'a', 'url' => 'https://a.example.com/h', 'min_level' => Severity::INFO],
            ['id' => 'b', 'url' => 'https://b.example.com/h', 'min_level' => Severity::INFO],
        ];

        $dispatcher = new WebhookDispatcher();
        $dispatcher->enqueue(Severity::HIGH, 'fw.ip_blocked', 'x');
        $dispatcher->flush();

        $urls = array_map(fn($p) => $p['url'], $this->posts);

        $this->assertContains('https://a.example.com/h', $urls);
        $this->assertContains('https://b.example.com/h', $urls);
    }
}

/** Minimal stand-in for WP_Error — Brain\Monkey does not provide the class. */
class FakeWpError {

    /** @var string */
    private $message;

    public function __construct(string $message) {
        $this->message = $message;
    }

    public function get_error_message(): string {
        return $this->message;
    }
}
