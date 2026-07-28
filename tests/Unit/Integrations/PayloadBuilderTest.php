<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Integrations;

use Brain\Monkey;
use Brain\Monkey\Functions;
use DPXL\Shield\Integrations\Event;
use DPXL\Shield\Integrations\PayloadBuilder;
use DPXL\Shield\Integrations\Severity;
use DPXL\Shield\Integrations\WebhookEndpoint;
use PHPUnit\Framework\TestCase;

/**
 * The payload is what actually leaves the site, so two things matter most:
 * each destination gets the envelope it requires (a wrong shape is accepted
 * with a 200 and then renders as nothing), and no credential rides along.
 */
class PayloadBuilderTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();

        Functions\stubs([
            'get_option'    => fn($key, $default = false) => $key === 'siteurl' ? 'https://exemplo.com.br' : $default,
            'wp_parse_url'  => fn($url, $component = -1) => parse_url((string) $url, $component),
            '__'            => fn($text, $domain = null) => $text,
        ]);
    }

    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }

    private function endpoint(string $format, string $secret = ''): WebhookEndpoint {
        $endpoint = WebhookEndpoint::fromArray([
            'url'    => 'https://hooks.example.com/abc',
            'format' => $format,
            'secret' => $secret,
        ]);

        $this->assertNotNull($endpoint);

        return $endpoint;
    }

    private function event(array $context = [], string $level = Severity::HIGH): Event {
        return new Event($level, 'fw.ip_blocked', 'IP 1.2.3.4 blocked.', $context, 1700000000);
    }

    // ── Redaction ────────────────────────────────────────────────────────────

    /** @return array<string,array{0:string}> */
    public static function sensitiveKeys(): array {
        return [
            'password'      => ['password'],
            'passwd prefix' => ['pass'],
            'api key'       => ['api_key'],
            'token'         => ['token'],
            'auth token'    => ['auth_token'],
            'cookie'        => ['cookie'],
            'session id'    => ['session_id'],
            'secret'        => ['client_secret'],
            'authorization' => ['authorization'],
            'private key'   => ['private_key'],
        ];
    }

    /**
     * @dataProvider sensitiveKeys
     */
    public function testCredentialLikeKeysAreRedacted(string $key): void {
        $payload = PayloadBuilder::build(
            $this->endpoint(WebhookEndpoint::FORMAT_GENERIC),
            $this->event([$key => 'hunter2-do-not-leak'])
        );

        $encoded = (string) json_encode($payload);

        $this->assertStringNotContainsString('hunter2-do-not-leak', $encoded);
        $this->assertStringContainsString('[redacted]', $encoded);
    }

    public function testRedactionReachesNestedContext(): void {
        $payload = PayloadBuilder::build(
            $this->endpoint(WebhookEndpoint::FORMAT_GENERIC),
            $this->event(['request' => ['ip' => '1.2.3.4', 'api_key' => 'leak-me']])
        );

        $encoded = (string) json_encode($payload);

        $this->assertStringNotContainsString('leak-me', $encoded);
        $this->assertStringContainsString('1.2.3.4', $encoded, 'harmless fields must survive');
    }

    public function testHarmlessContextIsPreserved(): void {
        $payload = PayloadBuilder::build(
            $this->endpoint(WebhookEndpoint::FORMAT_GENERIC),
            $this->event(['ip' => '203.0.113.5', 'rule' => 'sqli-101'])
        );

        $this->assertSame('203.0.113.5', $payload['context']['ip']);
        $this->assertSame('sqli-101', $payload['context']['rule']);
    }

    // ── Per-destination envelopes ────────────────────────────────────────────

    public function testGenericEnvelopeCarriesTheMachineReadableFields(): void {
        $payload = PayloadBuilder::build($this->endpoint(WebhookEndpoint::FORMAT_GENERIC), $this->event());

        $this->assertSame('dpxl-shield', $payload['source']);
        $this->assertSame('fw.ip_blocked', $payload['event_type']);
        $this->assertSame(Severity::HIGH, $payload['level']);
        $this->assertSame('https://exemplo.com.br', $payload['site']);
        $this->assertSame(gmdate('c', 1700000000), $payload['timestamp']);
    }

    public function testSlackPayloadHasTextAndAttachment(): void {
        $payload = PayloadBuilder::build($this->endpoint(WebhookEndpoint::FORMAT_SLACK), $this->event(['ip' => '1.2.3.4']));

        // Slack shows `text` in the notification; without it the alert is silent.
        $this->assertArrayHasKey('text', $payload);
        $this->assertStringContainsString('HIGH', $payload['text']);
        $this->assertStringContainsString('exemplo.com.br', $payload['text']);
        $this->assertCount(1, $payload['attachments']);
        $this->assertSame(1700000000, $payload['attachments'][0]['ts']);
    }

    public function testDiscordColourIsAnIntegerNotAHexString(): void {
        $payload = PayloadBuilder::build($this->endpoint(WebhookEndpoint::FORMAT_DISCORD), $this->event());

        // Discord rejects the embed outright if colour is a string.
        $this->assertIsInt($payload['embeds'][0]['color']);
    }

    public function testDiscordEmbedRespectsTheTwentyFiveFieldCap(): void {
        $context = [];

        for ($i = 0; $i < 40; $i++) {
            $context["field_{$i}"] = (string) $i;
        }

        $payload = PayloadBuilder::build($this->endpoint(WebhookEndpoint::FORMAT_DISCORD), $this->event($context));

        $this->assertLessThanOrEqual(25, count($payload['embeds'][0]['fields']));
    }

    public function testPagerDutyUsesTheEventsV2Envelope(): void {
        $payload = PayloadBuilder::build(
            $this->endpoint(WebhookEndpoint::FORMAT_PAGERDUTY, 'my-routing-key'),
            $this->event()
        );

        $this->assertSame('my-routing-key', $payload['routing_key']);
        $this->assertSame('trigger', $payload['event_action']);
        $this->assertArrayHasKey('summary', $payload['payload']);
        $this->assertArrayHasKey('dedup_key', $payload);
    }

    /**
     * PagerDuty only accepts critical/error/warning/info — sending "high" or
     * "medium" gets the event rejected.
     *
     * @return array<string,array{0:string,1:string}>
     */
    public static function pagerDutySeverities(): array {
        return [
            'critical maps through' => [Severity::CRITICAL, 'critical'],
            'high becomes error'    => [Severity::HIGH, 'error'],
            'medium becomes warning'=> [Severity::MEDIUM, 'warning'],
            'info maps through'     => [Severity::INFO, 'info'],
            'low becomes info'      => [Severity::LOW, 'info'],
        ];
    }

    /**
     * @dataProvider pagerDutySeverities
     */
    public function testPagerDutySeverityIsMappedToItsVocabulary(string $level, string $expected): void {
        $payload = PayloadBuilder::build(
            $this->endpoint(WebhookEndpoint::FORMAT_PAGERDUTY, 'key'),
            $this->event([], $level)
        );

        $this->assertSame($expected, $payload['payload']['severity']);
    }

    public function testPagerDutyDedupKeyIsStableForTheSameEventType(): void {
        $a = PayloadBuilder::build($this->endpoint(WebhookEndpoint::FORMAT_PAGERDUTY, 'k'), $this->event());
        $b = PayloadBuilder::build($this->endpoint(WebhookEndpoint::FORMAT_PAGERDUTY, 'k'), $this->event(['ip' => 'x']));

        $this->assertSame($a['dedup_key'], $b['dedup_key'], 'repeat occurrences must collapse into one incident');
    }

    // ── Encoding ─────────────────────────────────────────────────────────────

    /**
     * @dataProvider formats
     */
    public function testEveryFormatSurvivesJsonEncoding(string $format): void {
        $payload = PayloadBuilder::build(
            $this->endpoint($format, 'k'),
            $this->event(['ip' => '1.2.3.4', 'acentuação' => 'ação, coração'])
        );

        $this->assertIsString(json_encode($payload), "{$format} payload must encode");
    }

    /** @return array<string,array{0:string}> */
    public static function formats(): array {
        return [
            'generic'   => [WebhookEndpoint::FORMAT_GENERIC],
            'slack'     => [WebhookEndpoint::FORMAT_SLACK],
            'discord'   => [WebhookEndpoint::FORMAT_DISCORD],
            'pagerduty' => [WebhookEndpoint::FORMAT_PAGERDUTY],
        ];
    }
}
