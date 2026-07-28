<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Integrations;

use PHPUnit\Framework\TestCase;
use ReflectionClass;

/**
 * Webhook endpoints must never reach the settings export bundle.
 *
 * The bundle is a plain JSON file an administrator downloads and may forward,
 * and an endpoint row carries live credentials: signing secrets, PagerDuty
 * routing keys, and — for Slack and Discord — the URL itself. This is pinned by
 * a test because the exporter works by prefix (`dpxl_shield_%`), so any new
 * option is included by default and the safe direction is opt-out.
 */
class WebhookExportSafetyTest extends TestCase {

    /** @return string[] */
    private function excludedOptions(): array {
        $reflection = new ReflectionClass(\DPXL\Shield\Tools\ImportExport::class);

        /** @var string[] $excluded */
        $excluded = $reflection->getConstant('EXCLUDED_OPTS');

        return $excluded;
    }

    public function testWebhookEndpointsAreExcludedFromExport(): void {
        $this->assertContains(
            'webhook_endpoints',
            $this->excludedOptions(),
            'Exporting webhook endpoints would leak signing secrets, routing keys and Slack/Discord URLs.'
        );
    }

    public function testWebhookStatusIsExcludedFromExport(): void {
        $this->assertContains('webhook_status', $this->excludedOptions());
    }

    /** The pre-existing exclusions must survive too — this list is security-critical. */
    public function testExistingExclusionsAreStillInPlace(): void {
        $excluded = $this->excludedOptions();

        $this->assertContains('_site_check_enc_key', $excluded);
        $this->assertContains('_site_check_timeout_shwp', $excluded);
    }
}
