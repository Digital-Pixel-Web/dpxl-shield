<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Scanner;

use Brain\Monkey;
use Brain\Monkey\Functions;
use DPXL\Shield\Scanner\ReputationChecker;
use PHPUnit\Framework\TestCase;

/**
 * Which zone the lookups go to.
 *
 * Spamhaus refuses queries arriving through a public resolver, which is what
 * shared hosting uses — so without a DQS key the free mirrors cannot answer at
 * all. The key moves the lookups to the site's own authenticated zone, and it
 * has to be placed in the name exactly right or the query is meaningless.
 */
class ReputationZoneTest extends TestCase {

    private const KEY = 'abcdefghij0123456789klmnop'; // 26 chars, per Spamhaus.

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();
    }

    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }

    private function setKey(string $key): void {
        Functions\when('get_option')->alias(
            fn($name, $default = null) => $name === 'dpxl_shield_spamhaus_dqs_key' ? $key : null
        );
    }

    /** @return array{zone: string, authenticated: bool} */
    private function zone(string $list): array {
        $m = new \ReflectionMethod(ReputationChecker::class, 'zone');
        $m->setAccessible(true);

        return $m->invoke(null, $list);
    }

    public function testWithoutKeyUsesPublicMirror(): void {
        $this->setKey('');

        $this->assertSame('dbl.spamhaus.org', $this->zone('dbl')['zone']);
        $this->assertSame('zen.spamhaus.org', $this->zone('zen')['zone']);
        $this->assertFalse($this->zone('dbl')['authenticated']);
    }

    /** Documented DQS form: <key>.<dataset>.dq.spamhaus.net — .net, not .org. */
    public function testKeyBuildsTheDqsZone(): void {
        $this->setKey(self::KEY);

        $this->assertSame(self::KEY . '.dbl.dq.spamhaus.net', $this->zone('dbl')['zone']);
        $this->assertSame(self::KEY . '.zen.dq.spamhaus.net', $this->zone('zen')['zone']);
        $this->assertTrue($this->zone('zen')['authenticated']);
    }

    /** The full query name, as it reaches the resolver. */
    public function testQueryNamesAreWellFormed(): void {
        $this->setKey(self::KEY);

        $this->assertSame(
            'example.com.' . self::KEY . '.dbl.dq.spamhaus.net',
            'example.com.' . $this->zone('dbl')['zone']
        );
        $this->assertSame(
            '79.113.0.203.' . self::KEY . '.zen.dq.spamhaus.net',
            '79.113.0.203.' . $this->zone('zen')['zone']
        );
    }

    /**
     * A mistyped or truncated key must fall back to the mirror rather than be
     * pasted into a DNS name, which would only produce junk lookups.
     *
     * @dataProvider malformedKeys
     */
    public function testMalformedKeyFallsBackToMirror(string $key): void {
        $this->setKey($key);

        $this->assertSame('dbl.spamhaus.org', $this->zone('dbl')['zone']);
        $this->assertFalse($this->zone('dbl')['authenticated']);
    }

    /** @return list<array{string}> */
    public static function malformedKeys(): array {
        return [
            ['short'],
            ['abcdefghij0123456789klmno'],   // 25 — one short
            ['abcdefghij0123456789klmnopq'], // 27 — one long
            ['abcdefghij0123456789klmno.'],  // a dot would split the name
            ['abcdefghij0123456789klmn p'],  // whitespace
        ];
    }

    /** Keys get pasted with stray whitespace; that alone should not disable DQS. */
    public function testSurroundingWhitespaceIsTolerated(): void {
        $this->setKey("  \n" . self::KEY . "  ");

        $this->assertSame(self::KEY . '.dbl.dq.spamhaus.net', $this->zone('dbl')['zone']);
    }
}
