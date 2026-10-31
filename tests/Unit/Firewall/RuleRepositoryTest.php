<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Firewall;

use DPXL\Shield\Firewall\Rules\JsonRule;
use DPXL\Shield\Firewall\Rules\RuleEngine;
use DPXL\Shield\Firewall\Rules\RuleRepository;
use PHPUnit\Framework\TestCase;

/**
 * The loader that turns the signed feed file into runtime rules. Its whole job
 * is to be paranoid: never throw, drop bad entries individually, and — above all
 * — never let the feed shrink the built-in protection floor.
 */
class RuleRepositoryTest extends TestCase {

    /** @var list<string> temp files to clean up */
    private array $tmp = [];

    protected function tearDown(): void {
        RuleRepository::flushCache();

        foreach ($this->tmp as $path) {
            if (is_file($path)) {
                @unlink($path);
            }
        }

        $this->tmp = [];
        parent::tearDown();
    }

    private function writeFeed(array $data): string {
        $path = tempnam(sys_get_temp_dir(), 'dpxlrules') . '.json';
        file_put_contents($path, json_encode($data));
        $this->tmp[] = $path;

        return $path;
    }

    public function testLoadsValidRulesAndSkipsBadOnes(): void {
        $path = $this->writeFeed(['meta' => ['version' => '2026.07.26'], 'rules' => [
            ['id' => 'ok-1',  'pattern' => '/union\s+select/i', 'targets' => ['get'],  'action' => 'block'],
            ['id' => 'ok-2',  'pattern' => '/etc\/passwd/i',    'targets' => ['uri'],  'action' => 'block'],
            ['id' => '',      'pattern' => '/x/',               'targets' => ['get'],  'action' => 'block'], // no id
            ['id' => 'no-pat','pattern' => '',                  'targets' => ['get'],  'action' => 'block'], // no pattern
            ['id' => 'bad-re','pattern' => '/unterminated(',    'targets' => ['get'],  'action' => 'block'], // invalid regex
            ['id' => 'logon', 'pattern' => '/y/',               'targets' => ['get'],  'action' => 'log_only'], // not block
        ]]);

        $rules = RuleRepository::load($path);
        $ids   = array_map(static fn(JsonRule $r) => $r->getId(), $rules);

        $this->assertSame(['ok-1', 'ok-2'], $ids, 'Only well-formed, block-action rules with valid regex survive');
    }

    public function testMissingFileYieldsEmptySet(): void {
        $this->assertSame([], RuleRepository::load(sys_get_temp_dir() . '/does-not-exist-' . uniqid() . '.json'));
    }

    public function testMalformedJsonYieldsEmptySet(): void {
        $path = tempnam(sys_get_temp_dir(), 'dpxlrules') . '.json';
        file_put_contents($path, '{ this is not json ]');
        $this->tmp[] = $path;

        $this->assertSame([], RuleRepository::load($path));
    }

    public function testUnknownTargetsAreDroppedAndDefaultApplies(): void {
        $path = $this->writeFeed(['rules' => [
            ['id' => 'r1', 'pattern' => '/x/', 'targets' => ['get', 'bogus', 'body'], 'action' => 'block'],
            ['id' => 'r2', 'pattern' => '/x/', 'targets' => [], 'action' => 'block'], // empty → default
        ]]);

        $rules = RuleRepository::load($path);

        $this->assertCount(2, $rules, 'A rule keeps its known targets even if some are bogus; empty falls back to default');
    }

    public function testVersionReadsMeta(): void {
        $path = $this->writeFeed(['meta' => ['version' => '2026.07.26.3'], 'rules' => []]);

        $this->assertSame('2026.07.26.3', RuleRepository::version($path));
    }

    public function testFeedNeverShrinksTheBuiltInFloor(): void {
        // A RuleEngine with no feed file present has exactly the 6 built-in rules.
        $defaultFeed = \DPXL\Shield\Core\EarlyConfig::dataDir() . '/waf-rules.active.json';

        if (is_file($defaultFeed)) {
            $this->markTestSkipped('A real feed file is present; skipping the floor-count assertion.');
        }

        RuleRepository::flushCache();
        $builtInCount = count((new RuleEngine())->getRules());
        $this->assertSame(6, $builtInCount, 'The six built-in rules are the immutable floor');

        // With a feed file, the engine has the floor PLUS the feed rules — never fewer.
        $feed = json_encode(['rules' => [
            ['id' => 'feed-1', 'pattern' => '/union\s+select/i', 'targets' => ['get'], 'action' => 'block'],
            ['id' => 'feed-2', 'pattern' => '/etc\/passwd/i',    'targets' => ['uri'], 'action' => 'block'],
        ]]);

        $createdDir = !is_dir(dirname($defaultFeed)) && mkdir(dirname($defaultFeed), 0755, true);

        try {
            file_put_contents($defaultFeed, $feed);
            RuleRepository::flushCache();

            $withFeed = count((new RuleEngine())->getRules());
            $this->assertSame($builtInCount + 2, $withFeed, 'Feed rules add on top of the floor');
        } finally {
            @unlink($defaultFeed);
            if ($createdDir) {
                @rmdir(dirname($defaultFeed));
            }
            RuleRepository::flushCache();
        }
    }
}
