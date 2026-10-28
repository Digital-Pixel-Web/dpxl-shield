<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Integrations;

use Brain\Monkey;
use Brain\Monkey\Functions;
use DPXL\Shield\Integrations\Severity;
use DPXL\Shield\Integrations\WebhookEndpoint;
use PHPUnit\Framework\TestCase;

/**
 * WebhookEndpoint is the boundary between stored (untrusted) configuration and
 * the dispatcher, so most of what matters here is what it *refuses*.
 */
class WebhookEndpointTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();
        Functions\when('wp_parse_url')->alias('parse_url');
    }

    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }

    /** @param array<string,mixed> $overrides */
    private function endpoint(array $overrides = []): ?WebhookEndpoint {
        return WebhookEndpoint::fromArray(array_merge([
            'url'    => 'https://hooks.example.com/abc',
            'format' => WebhookEndpoint::FORMAT_GENERIC,
        ], $overrides));
    }

    // ── URL validation ───────────────────────────────────────────────────────

    public function testAcceptsHttpsUrl(): void {
        $this->assertNotNull($this->endpoint());
    }

    /**
     * Plain HTTP is refused: the payload describes security events on the site,
     * so sending it unencrypted hands an eavesdropper a live attack feed.
     */
    public function testRejectsPlainHttpUrl(): void {
        $this->assertNull($this->endpoint(['url' => 'http://hooks.example.com/abc']));
    }

    /** @return array<string,array{0:string}> */
    public static function badUrls(): array {
        return [
            'empty'          => [''],
            'whitespace'     => ['   '],
            'not a url'      => ['nonsense'],
            'scheme only'    => ['https://'],
            'javascript'     => ['javascript:alert(1)'],
            'file'           => ['file:///etc/passwd'],
            'ftp'            => ['ftp://example.com/x'],
            'protocol-less'  => ['//example.com/x'],
        ];
    }

    /**
     * @dataProvider badUrls
     */
    public function testRejectsUnusableUrls(string $url): void {
        $this->assertNull($this->endpoint(['url' => $url]));
    }

    // ── Defaults and normalisation ───────────────────────────────────────────

    public function testUnknownFormatFallsBackToGeneric(): void {
        $endpoint = $this->endpoint(['format' => 'carrier-pigeon']);

        $this->assertNotNull($endpoint);
        $this->assertSame(WebhookEndpoint::FORMAT_GENERIC, $endpoint->format());
    }

    public function testInvalidSeverityFallsBackToMedium(): void {
        $endpoint = $this->endpoint(['min_level' => 'apocalyptic']);

        $this->assertNotNull($endpoint);
        $this->assertSame(Severity::MEDIUM, $endpoint->minLevel());
    }

    public function testLabelDefaultsToHostWhenBlank(): void {
        $endpoint = $this->endpoint(['label' => '   ']);

        $this->assertNotNull($endpoint);
        $this->assertSame('hooks.example.com', $endpoint->label());
    }

    public function testIdIsDerivedDeterministicallyWhenAbsent(): void {
        $a = $this->endpoint();
        $b = $this->endpoint();

        $this->assertNotNull($a);
        $this->assertNotNull($b);
        $this->assertSame($a->id(), $b->id(), 'same url+format must yield the same id');
        $this->assertNotSame('', $a->id());
    }

    public function testIdIsStrippedOfUnsafeCharacters(): void {
        $endpoint = $this->endpoint(['id' => '../../etc/passwd']);

        $this->assertNotNull($endpoint);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $endpoint->id());
    }

    public function testEnabledDefaultsToTrue(): void {
        $endpoint = $this->endpoint();

        $this->assertNotNull($endpoint);
        $this->assertTrue($endpoint->isEnabled());
    }

    // ── Severity gate ────────────────────────────────────────────────────────

    public function testAcceptsOnlyAlertsAtOrAboveItsThreshold(): void {
        $endpoint = $this->endpoint(['min_level' => Severity::HIGH]);

        $this->assertNotNull($endpoint);
        $this->assertTrue($endpoint->accepts(Severity::CRITICAL));
        $this->assertTrue($endpoint->accepts(Severity::HIGH));
        $this->assertFalse($endpoint->accepts(Severity::MEDIUM));
        $this->assertFalse($endpoint->accepts(Severity::INFO));
    }

    public function testDisabledEndpointAcceptsNothing(): void {
        $endpoint = $this->endpoint(['enabled' => false, 'min_level' => Severity::INFO]);

        $this->assertNotNull($endpoint);
        $this->assertFalse($endpoint->accepts(Severity::CRITICAL));
    }

    // ── Secret handling ──────────────────────────────────────────────────────

    public function testPublicArrayNeverExposesTheSecret(): void {
        $endpoint = $this->endpoint(['secret' => 'super-secret-value']);

        $this->assertNotNull($endpoint);

        $public = $endpoint->toPublicArray();

        $this->assertSame('', $public['secret']);
        $this->assertTrue($public['has_secret']);
        $this->assertStringNotContainsString('super-secret-value', (string) json_encode($public));
    }

    public function testPublicArrayFlagsAbsenceOfSecret(): void {
        $endpoint = $this->endpoint();

        $this->assertNotNull($endpoint);
        $this->assertFalse($endpoint->toPublicArray()['has_secret']);
    }

    public function testRoundTripsThroughStorageForm(): void {
        $original = $this->endpoint([
            'label'     => 'SIEM',
            'format'    => WebhookEndpoint::FORMAT_PAGERDUTY,
            'min_level' => Severity::CRITICAL,
            'secret'    => 'routing-key',
        ]);

        $this->assertNotNull($original);

        $restored = WebhookEndpoint::fromArray($original->toArray());

        $this->assertNotNull($restored);
        $this->assertSame($original->toArray(), $restored->toArray());
    }
}
