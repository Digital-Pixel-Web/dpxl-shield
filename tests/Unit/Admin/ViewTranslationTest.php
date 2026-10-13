<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Admin;

use PHPUnit\Framework\TestCase;

/**
 * No English sentence reaches a screen.
 *
 * The plugin has no .mo catalogue: the admin UI is translated by a gettext
 * filter whose map lives in AdminMenu, so a string a view asks for and the map
 * does not carry is printed in English, in the middle of a Portuguese screen.
 * That is how the Firewall screen ended up showing a developer's note comparing
 * the plugin to Wordfence, and how about sixty strings — whole paragraphs about
 * webhooks, API tokens and the Spamhaus key — sat untranslated for months.
 *
 * The check is deliberately a sentence detector rather than a demand that every
 * string be mapped: most view strings are already written in Portuguese at the
 * call site and need no entry. A bare English noun ("Name") would slip through;
 * an English sentence, which is what actually embarrasses the product, does not.
 */
class ViewTranslationTest extends TestCase {

    /**
     * Words that do not occur in Portuguese and are hard to avoid in an English
     * sentence. Matched whole-word, case-insensitively.
     */
    private const ENGLISH_MARKERS = [
        'the', 'and', 'with', 'your', 'you', 'this', 'that', 'from', 'not',
        'for', 'when', 'are', 'is', 'be', 'it', 'its', 'has', 'have', 'will',
        'can', 'cannot', 'each', 'they', 'their', 'what', 'which', 'would',
        'should', 'must', 'already', 'through', 'without', 'into',
    ];

    public function testNoViewPrintsAnUntranslatedEnglishSentence(): void {
        $map     = self::translationMap();
        $offends = [];

        foreach (self::viewStrings() as $string => $files) {
            if (isset($map[$string]) || !self::looksEnglish($string)) {
                continue;
            }

            $offends[] = sprintf('%s  (%s)', self::clip($string), implode(', ', $files));
        }

        $this->assertSame(
            [],
            $offends,
            "Strings reaching a screen in English, with no entry in AdminMenu's map:\n  "
                . implode("\n  ", $offends) . "\n"
        );
    }

    /** An entry that maps a sentence to itself is a translation nobody finished. */
    public function testNoMapEntryLeavesAnEnglishSentenceUntouched(): void {
        $untouched = [];

        foreach (self::translationMap() as $en => $pt) {
            if ($en === $pt && self::looksEnglish($en)) {
                $untouched[] = self::clip($en);
            }
        }

        $this->assertSame([], $untouched, 'Map entries still in English: ' . implode(' | ', $untouched));
    }

    public function testTheMapAndTheViewsAreBothFound(): void {
        $this->assertNotEmpty(self::translationMap(), 'No translation map found — the scraper is broken.');
        $this->assertNotEmpty(self::viewStrings(), 'No view strings found — the scraper is broken.');
    }

    // ── Internals ──────────────────────────────────────────────────────────

    private static function looksEnglish(string $text): bool {
        $words = preg_split('/[^a-z]+/i', mb_strtolower($text)) ?: [];
        $hits  = array_intersect($words, self::ENGLISH_MARKERS);

        // Two markers, so a stray "is" inside a Portuguese string (or a product
        // name) is not enough to fail the build.
        return count($hits) >= 2;
    }

    private static function clip(string $text): string {
        return mb_strlen($text) > 70 ? mb_substr($text, 0, 70) . '…' : $text;
    }

    /** @return array<string,string> */
    private static function translationMap(): array {
        $source = (string) file_get_contents(dirname(__DIR__, 3) . '/src/Admin/AdminMenu.php');
        $start  = strpos($source, 'static $map = [');

        if ($start === false) {
            return [];
        }

        $end   = (int) strpos($source, "\n        ];", $start);
        $block = substr($source, $start, $end - $start);

        preg_match_all("/'((?:[^'\\\\]|\\\\.)*)'\s*=>\s*'((?:[^'\\\\]|\\\\.)*)'/", $block, $m, PREG_SET_ORDER);

        $map = [];

        foreach ($m as $pair) {
            $map[stripslashes($pair[1])] = stripslashes($pair[2]);
        }

        return $map;
    }

    /** @return array<string,list<string>> string => the views that print it */
    private static function viewStrings(): array {
        $root  = dirname(__DIR__, 3) . '/src/Admin/Views';
        $found = [];

        $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root));

        foreach ($files as $file) {
            if (!$file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }

            $source = (string) file_get_contents($file->getPathname());

            preg_match_all(
                "/(?:esc_html_e|esc_html__|esc_attr_e|esc_attr__|__|_n)\(\s*'((?:[^'\\\\]|\\\\.)*)'/",
                $source,
                $m
            );

            foreach ($m[1] as $string) {
                $found[stripslashes($string)][] = $file->getBasename();
            }
        }

        return $found;
    }
}
