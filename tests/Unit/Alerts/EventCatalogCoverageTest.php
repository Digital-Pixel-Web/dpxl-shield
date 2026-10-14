<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Alerts;

use DPXL\Shield\Alerts\EventCatalog;
use PHPUnit\Framework\TestCase;

/**
 * Every event the code fires must be described by the catalogue.
 *
 * The catalogue decides the email's title and summary from the event type
 * alone, so an event type that is missing falls back to a humanised slug — and,
 * worse, two different facts sharing one type are both announced with the
 * wording of the first. That is what happened with `plugin_deleted`: deleting
 * any plugin on the site produced an email headed "O DPXL Shield foi excluído",
 * including when the plugin deleted was somebody else's. It fired five times
 * across two months before anyone traced the email to its cause.
 *
 * This is the fourth guard of its kind, after the icon lists, the alert field
 * labels and the untranslated-string check. They all exist because the same
 * shape of mistake — two sides of a mapping drifting apart with nothing
 * connecting them — keeps coming back.
 */
class EventCatalogCoverageTest extends TestCase {

    /**
     * Event types fired anywhere under src/, read from the source.
     *
     * Reading the code rather than keeping a list is the point: a list would
     * drift exactly like the mapping it is meant to protect.
     *
     * @return list<string>
     */
    private function firedEventTypes(): array {
        $types = [];

        $files = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator(DPXL_SHIELD_PATH . 'src', \FilesystemIterator::SKIP_DOTS)
        );

        foreach ($files as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }

            $source = (string) file_get_contents($file->getRealPath());

            // Only the two forms that actually name an event:
            //   'event_type' => 'slug'
            //   'event_type' => $cond ? 'a' : 'b'
            // Anything else is an expression — a REST parameter of the same
            // name, a value read off an object — and naming no literal event.
            $patterns = [
                "/'event_type'\s*=>\s*'([a-z0-9_.]+)'/i",
                "/'event_type'\s*=>\s*\\\$\w+\s*\?\s*'([a-z0-9_.]+)'\s*:\s*'([a-z0-9_.]+)'/i",
            ];

            foreach ($patterns as $pattern) {
                if (!preg_match_all($pattern, $source, $matches)) {
                    continue;
                }

                foreach (array_slice($matches, 1) as $group) {
                    foreach (array_filter($group) as $slug) {
                        $types[$slug] = true;
                    }
                }
            }
        }

        ksort($types);

        return array_keys($types);
    }

    public function testEveryFiredEventTypeHasATitle(): void {
        $missing = [];

        foreach ($this->firedEventTypes() as $type) {
            // An uncatalogued type falls back to a humanised version of its own
            // slug, which is how it is recognised here.
            if (EventCatalog::label($type) === self::humanise($type)) {
                $missing[] = $type;
            }
        }

        $this->assertSame([], $missing, 'Event types with no title in EventCatalog: ' . implode(', ', $missing));
    }

    public function testEveryFiredEventTypeHasASummary(): void {
        $missing = array_values(array_filter(
            $this->firedEventTypes(),
            fn(string $type) => EventCatalog::summary($type) === ''
        ));

        $this->assertSame([], $missing, 'Event types with no summary: ' . implode(', ', $missing));
    }

    /**
     * Since 1.8.0 every alert says what to do, including when the answer is
     * nothing. An event with no steps leaves that block empty.
     */
    public function testEveryFiredEventTypeSaysWhatToDo(): void {
        $missing = array_values(array_filter(
            $this->firedEventTypes(),
            fn(string $type) => EventCatalog::actions($type) === []
        ));

        $this->assertSame([], $missing, 'Event types with no "what to do" steps: ' . implode(', ', $missing));
    }

    /** The two halves of the plugin-removal pair must not share a type again. */
    public function testOurPluginAndOtherPluginAreDistinctEvents(): void {
        $this->assertNotSame(
            EventCatalog::label('plugin_deleted'),
            EventCatalog::label('other_plugin_deleted')
        );
        $this->assertNotSame(
            EventCatalog::label('plugin_deactivated'),
            EventCatalog::label('other_plugin_deactivated')
        );
        $this->assertStringNotContainsString('DPXL Shield', EventCatalog::label('other_plugin_deleted'));
        $this->assertStringNotContainsString('DPXL Shield', EventCatalog::label('other_plugin_deactivated'));
    }

    /** Mirrors EventCatalog's own fallback. */
    private static function humanise(string $slug): string {
        return ucfirst(str_replace(['_', '.'], ' ', $slug));
    }
}
