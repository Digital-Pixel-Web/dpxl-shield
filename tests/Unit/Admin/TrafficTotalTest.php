<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Admin;

use Brain\Monkey;
use Brain\Monkey\Functions;
use DPXL\Shield\Admin\RestApi;
use PHPUnit\Framework\TestCase;

/**
 * The `total` of /traffic under a filter.
 *
 * getTraffic() builds one WHERE clause and uses it twice: once for the page of
 * rows, prepared, and once for the COUNT. The COUNT used to run unprepared, so
 * the %s placeholders of the ip / uri filters reached the database verbatim, the
 * query failed, get_var() returned null and `total` came back as 0 while `items`
 * held a full page of matching rows. Confirmed on the staging install before the
 * fix: 25 items, total 0.
 *
 * It was latent — admin.js does not read `total`, because the pagination it
 * belongs to was never built — but it is the kind of thing that only surfaces
 * once someone wires up the pagination and trusts the number.
 *
 * A static scan of the source cannot catch this: the placeholders are not
 * written in the SQL literal, they arrive at runtime inside $wc. So the test
 * drives the method against a $wpdb that fails the same way the real one does.
 */
class TrafficTotalTest extends TestCase {

    /** @var FakeWpdb */
    private $wpdb;

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();

        Functions\when('sanitize_text_field')->returnArg(1);
        Functions\when('rest_ensure_response')->alias(fn($data) => new \WP_REST_Response($data));

        $GLOBALS['wpdb'] = $this->wpdb = new FakeWpdb();
    }

    protected function tearDown(): void {
        unset($GLOBALS['wpdb']);
        Monkey\tearDown();
        parent::tearDown();
    }

    /** @param array<string,mixed> $params */
    private function getTraffic(array $params): array {
        return (new RestApi())->getTraffic(new \WP_REST_Request($params))->get_data();
    }

    public function testTotalIsCountedWhenAUrlFilterIsApplied(): void {
        $this->wpdb->matchingRows = 3;

        $data = $this->getTraffic(['url' => 'admin-ajax.php', 'limit' => 25]);

        $this->assertSame(3, $data['total'], 'A filtered request must report the real number of matches.');
        $this->assertCount(3, $data['items']);
    }

    public function testTotalIsCountedWhenAnIpFilterIsApplied(): void {
        $this->wpdb->matchingRows = 7;

        $this->assertSame(7, $this->getTraffic(['ip' => '203.0.113.9'])['total']);
    }

    public function testTotalIsCountedWithBothFiltersAtOnce(): void {
        $this->wpdb->matchingRows = 2;

        $this->assertSame(2, $this->getTraffic(['ip' => '203.0.113.9', 'url' => '/wp-login.php'])['total']);
    }

    public function testTotalIsStillCountedWithNoFilterAtAll(): void {
        $this->wpdb->matchingRows = 11;

        $this->assertSame(11, $this->getTraffic([])['total'], 'The unfiltered COUNT takes no values and must not be prepared.');
    }

    public function testNoQueryReachesTheDatabaseHoldingAPlaceholder(): void {
        $this->getTraffic(['ip' => '203.0.113.9', 'url' => 'admin-ajax.php', 'type' => 'blocked']);

        foreach ($this->wpdb->executed as $sql) {
            $this->assertDoesNotMatchRegularExpression(
                '/%[sdf]/',
                $sql,
                "A placeholder reached the database unprepared, which fails the query: {$sql}"
            );
        }

        $this->assertNotEmpty($this->wpdb->executed);
    }

    public function testThePaginationValuesDoNotLeakIntoTheCount(): void {
        $this->getTraffic(['ip' => '203.0.113.9', 'limit' => 25, 'offset' => 50]);

        $count = $this->wpdb->lastCountSql();

        $this->assertStringNotContainsStringIgnoringCase('limit', (string) $count);
        $this->assertStringNotContainsStringIgnoringCase('offset', (string) $count);
        $this->assertStringContainsString("ip = '203.0.113.9'", (string) $count, 'The COUNT repeats the same WHERE as the page query.');
    }
}

/**
 * Enough of wpdb to drive getTraffic().
 *
 * get_var() returns null for SQL that still holds a placeholder, which is what
 * MySQL does with it — a syntax error, so wpdb hands back null and the cast to
 * int turns it into 0. That is the behaviour this test exists to pin.
 */
class FakeWpdb {

    /** @var string */
    public $prefix = 'wp_';

    /** @var int */
    public $matchingRows = 0;

    /** @var string[] Every statement that reached the "database". */
    public $executed = [];

    public function esc_like(string $text): string {
        return addcslashes($text, '_%\\');
    }

    /** @param mixed ...$args */
    public function prepare(string $sql, ...$args): string {
        foreach ($args as $arg) {
            $replacement = is_int($arg) || is_float($arg)
                ? (string) $arg
                : "'" . str_replace("'", "\\'", (string) $arg) . "'";

            $sql = preg_replace('/%[sdf]/', $replacement, $sql, 1) ?? $sql;
        }

        return $sql;
    }

    /** @return array<int,array<string,mixed>> */
    public function get_results(string $sql, $output = null): array {
        $this->executed[] = $sql;

        if (preg_match('/%[sdf]/', $sql)) {
            return [];
        }

        return array_fill(0, $this->matchingRows, ['id' => 1, 'ip' => '203.0.113.9', 'uri' => '/']);
    }

    /** @return string|null */
    public function get_var(string $sql) {
        $this->executed[] = $sql;

        return preg_match('/%[sdf]/', $sql) ? null : (string) $this->matchingRows;
    }

    public function lastCountSql(): ?string {
        foreach (array_reverse($this->executed) as $sql) {
            if (stripos($sql, 'COUNT(') !== false) {
                return $sql;
            }
        }

        return null;
    }
}
