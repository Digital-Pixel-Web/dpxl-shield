<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Alerts;

use DPXL\Shield\Alerts\EventCatalog;
use PHPUnit\Framework\TestCase;

/**
 * Every context key a detector sends has to have a Portuguese label.
 *
 * Without one, EventCatalog falls back to humanising the slug, and the row
 * lands in the email as "Lockout seconds" or "Hibp count" inside an otherwise
 * pt-BR message. That is the half-translation 1.8.0 set out to remove, and it
 * came back the moment another change added two new context keys.
 *
 * So this reads the dispatch sites rather than a list someone remembers to
 * update: add a key to a `dpxl_shield_alert` payload without labelling it and
 * this test names it.
 */
class FieldLabelCoverageTest extends TestCase {

    /** Payload-level keys — not context fields, never rendered as a row. */
    private const ENVELOPE = ['level', 'event_type', 'description', 'context'];

    public function testEveryDispatchedContextKeyHasAPortugueseLabel(): void {
        $keys = self::dispatchedContextKeys();

        $this->assertNotEmpty($keys, 'No alert dispatch sites found — the scraper is broken, not the code.');

        $labels  = self::fieldLabels();
        $missing = array_values(array_diff($keys, array_keys($labels)));

        $this->assertSame(
            [],
            $missing,
            'Context keys with no entry in EventCatalog::FIELD_LABELS: ' . implode(', ', $missing)
        );
    }

    /** A label that is empty would render as a blank column header. */
    public function testNoLabelIsEmpty(): void {
        foreach (self::fieldLabels() as $key => $label) {
            $this->assertNotSame('', trim($label), "{$key} has an empty label");
        }
    }

    /**
     * @return array<string,string>
     */
    private static function fieldLabels(): array {
        $ref = new \ReflectionClass(EventCatalog::class);

        /** @var array<string,string> $labels */
        $labels = $ref->getConstant('FIELD_LABELS');

        return $labels;
    }

    /**
     * Keys from every `do_action('dpxl_shield_alert', [...])` across src/.
     *
     * Walks brackets from the call to its matching close rather than matching
     * the whole payload with one pattern, because the payloads nest arrays and
     * span up to twenty lines.
     *
     * @return list<string>
     */
    private static function dispatchedContextKeys(): array {
        $keys = [];

        $files = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator(dirname(__DIR__, 3) . '/src')
        );

        foreach ($files as $file) {
            if (!$file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }

            $source = (string) file_get_contents($file->getPathname());
            $offset = 0;

            while (($start = strpos($source, "dpxl_shield_alert", $offset)) !== false) {
                $offset  = $start + 1;
                $payload = self::balancedArray($source, $start);

                if ($payload === '') {
                    continue;
                }

                preg_match_all("/'([a-z_0-9]+)'\s*=>/", $payload, $matches);

                foreach ($matches[1] as $key) {
                    if (!in_array($key, self::ENVELOPE, true)) {
                        $keys[$key] = true;
                    }
                }
            }
        }

        $found = array_keys($keys);
        sort($found);

        return $found;
    }

    /** The `[ ... ]` that follows $from, bracket-balanced. */
    private static function balancedArray(string $source, int $from): string {
        $open = strpos($source, '[', $from);

        if ($open === false) {
            return '';
        }

        $depth = 0;

        for ($i = $open, $len = strlen($source); $i < $len; $i++) {
            if ($source[$i] === '[') {
                $depth++;
            } elseif ($source[$i] === ']') {
                $depth--;

                if ($depth === 0) {
                    return substr($source, $open, $i - $open + 1);
                }
            }
        }

        return '';
    }
}
