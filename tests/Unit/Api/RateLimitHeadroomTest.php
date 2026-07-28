<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Api;

use DPXL\Shield\Api\ApiAuth;
use DPXL\Shield\Firewall\RateLimiter;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

/**
 * Two rate limits sit in front of the integration API, and the order matters.
 *
 * The WAF limits `/wp-json/` per IP *before WordPress loads*; ApiAuth limits per
 * token once the request is inside. If the API's own ceiling were the higher of
 * the two, the firewall would cut the client off first — the caller would get an
 * opaque block instead of a 429 that says what happened, and repeated hits could
 * get the integration's IP blocked outright.
 *
 * This is pinned because the two numbers live in different files and neither
 * mentions the other in a way a compiler could enforce.
 */
class RateLimitHeadroomTest extends TestCase {

    private function apiLimit(): int {
        return (int) (new ReflectionClass(ApiAuth::class))->getConstant('RATE_LIMIT');
    }

    private function wafRestLimit(): int {
        $reflection = new ReflectionClass(RateLimiter::class);

        $property = $reflection->getProperty('limits');
        $property->setAccessible(true);

        /** @var array<string,int> $limits */
        $limits = $property->getValue();

        return (int) $limits['rest'];
    }

    public function testApiLimitStaysBelowTheFirewallRestLimit(): void {
        $this->assertLessThan(
            $this->wafRestLimit(),
            $this->apiLimit(),
            'The API ceiling must sit under the WAF REST ceiling, or the firewall blocks clients first.'
        );
    }

    /**
     * Equal values would still race: the WAF counts every REST call from that
     * IP, including the admin panel's own, so the API needs real headroom.
     */
    public function testThereIsMeaningfulHeadroomNotJustOneRequest(): void {
        $this->assertLessThanOrEqual(
            (int) ($this->wafRestLimit() * 0.75),
            $this->apiLimit(),
            'Leave at least 25% headroom for admin-panel REST traffic from the same IP.'
        );
    }

    /** Still has to be usable: a SIEM polling every few seconds must fit. */
    public function testLimitIsGenerousEnoughForFrequentPolling(): void {
        $this->assertGreaterThanOrEqual(
            12,
            $this->apiLimit(),
            'Polling every 5 seconds is 12 requests per minute and must not be throttled.'
        );
    }
}
