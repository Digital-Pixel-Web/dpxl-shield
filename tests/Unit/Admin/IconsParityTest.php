<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Admin;

use DPXL\Shield\Admin\Icons;
use PHPUnit\Framework\TestCase;

/**
 * The icon set exists twice: Icons::PATHS renders server-side markup, and the
 * ICONS object in assets/js/admin.js renders the same glyphs for rows the panel
 * builds from REST data. Nothing enforced the two lists, so they drifted: through
 * 1.7.3 the PHP side had 25 icons and the JS side 21, and every client-rendered
 * use of the four missing names ('lock', 'sliders', 'upload-cloud', 'users')
 * silently fell back to the generic info circle via `ICONS[name] || ICONS.info`.
 *
 * A silent fallback is exactly the kind of regression that survives review, so
 * the parity is asserted here instead of trusted to a comment.
 */
class IconsParityTest extends TestCase {

    /** @return string[] */
    private function phpIconNames(): array {
        /** @var array<string,string> $paths */
        $paths = (new \ReflectionClass(Icons::class))->getConstant('PATHS');

        $names = array_keys($paths);
        sort($names);

        return $names;
    }

    /** @return string[] */
    private function jsIconNames(): array {
        $file = dirname(__DIR__, 3) . '/assets/js/admin.js';

        $this->assertFileExists($file, 'assets/js/admin.js is missing.');

        $source = (string) file_get_contents($file);
        $start  = strpos($source, 'const ICONS = {');

        $this->assertNotFalse($start, 'Could not find the ICONS object in assets/js/admin.js.');

        $end = strpos($source, '};', (int) $start);

        $this->assertNotFalse($end, 'Could not find the end of the ICONS object in assets/js/admin.js.');

        $block = substr($source, (int) $start, (int) $end - (int) $start);

        preg_match_all("/^\s*'([a-z0-9-]+)'\s*:/m", $block, $matches);

        $names = $matches[1];
        sort($names);

        return $names;
    }

    public function testJsMirrorsEveryPhpIcon(): void {
        $php = $this->phpIconNames();
        $js  = $this->jsIconNames();

        $this->assertNotEmpty($php, 'Icons::PATHS came back empty — the constant was probably renamed.');
        $this->assertNotEmpty($js, 'No icon names were parsed out of assets/js/admin.js.');

        $missingInJs  = array_values(array_diff($php, $js));
        $missingInPhp = array_values(array_diff($js, $php));

        $this->assertSame(
            [],
            $missingInJs,
            'Icons in Icons::PATHS with no counterpart in assets/js/admin.js (ICONS): '
            . implode(', ', $missingInJs)
            . '. Client-rendered markup would fall back to the info icon.'
        );

        $this->assertSame(
            [],
            $missingInPhp,
            'Icons in assets/js/admin.js (ICONS) with no counterpart in Icons::PATHS: '
            . implode(', ', $missingInPhp)
            . '. Server-rendered markup would fall back to the info icon.'
        );

        $this->assertSame($php, $js, 'The two icon lists must hold exactly the same names.');
    }
}
