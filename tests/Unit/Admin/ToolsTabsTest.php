<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Admin;

use PHPUnit\Framework\TestCase;

/**
 * The Tools screen keeps its tab list in three places, and they have to agree.
 *
 * AdminMenu whitelists the tab before dispatching, Views/tools.php draws the
 * nav, and Views/tools/ holds one partial per tab. Integrações was in two of
 * the three: the link was drawn and the partial existed, but the whitelist did
 * not know the slug, so it silently rewrote the request to live-traffic.
 * Clicking the tab landed on the traffic log — and the traffic log then sat on
 * "Carregando…" forever, because the JavaScript that loads it keys off the slug
 * in the URL, which still said integrations.
 *
 * Nothing failed loudly. The screen holding the webhook and API-token setup was
 * simply unreachable.
 */
class ToolsTabsTest extends TestCase {

    public function testTheThreeListsAgree(): void {
        $whitelist = self::whitelist();
        $nav       = self::navTabs();
        $partials  = self::partials();

        sort($whitelist);
        sort($nav);
        sort($partials);

        $this->assertSame($nav, $whitelist, 'AdminMenu whitelist and the tab nav disagree.');
        $this->assertSame($nav, $partials, 'The tab nav and the view partials disagree.');
    }

    /** Every tab the nav offers has somewhere to land. */
    public function testEveryNavTabHasAPartial(): void {
        foreach (self::navTabs() as $slug) {
            $this->assertFileExists(
                dirname(__DIR__, 3) . "/src/Admin/Views/tools/{$slug}.php",
                "The nav links to {$slug} but there is no partial for it."
            );
        }
    }

    /** @return list<string> */
    private static function whitelist(): array {
        $source = (string) file_get_contents(dirname(__DIR__, 3) . '/src/Admin/AdminMenu.php');

        preg_match("/\\\$tabs\s*=\s*\[([^\]]*'live-traffic'[^\]]*)\]/", $source, $m);

        return $m ? self::slugs($m[1]) : [];
    }

    /** @return list<string> */
    private static function navTabs(): array {
        $source = (string) file_get_contents(dirname(__DIR__, 3) . '/src/Admin/Views/tools.php');

        $start = strpos($source, '$dpxlToolTabs = [');
        $end   = $start === false ? false : strpos($source, '];', $start);

        return $start === false || $end === false ? [] : self::slugs(substr($source, $start, $end - $start));
    }

    /** @return list<string> */
    private static function partials(): array {
        $files = glob(dirname(__DIR__, 3) . '/src/Admin/Views/tools/*.php') ?: [];

        return array_map(static function (string $path): string {
            return basename($path, '.php');
        }, $files);
    }

    /**
     * The quoted slugs in a block.
     *
     * Tab labels are accented Portuguese, so they cannot be mistaken for a
     * slug; the text domain can, and is dropped by name.
     *
     * @return list<string>
     */
    private static function slugs(string $block): array {
        preg_match_all("/'([a-z0-9-]+)'/", $block, $m);

        $slugs = array_filter($m[1], static function (string $slug): bool {
            return $slug !== 'dpxl-shield';
        });

        return array_values(array_unique($slugs));
    }
}
