<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Alerts;

use DPXL\Shield\Alerts\ReportI18n;
use PHPUnit\Framework\TestCase;

/**
 * The report's own pt-BR layer. The plugin's UI translation filter never runs
 * under WP-Cron, so these gettext/ngettext callbacks are what put the scheduled
 * report into Portuguese. They must translate the report's own strings and leave
 * everything else (other domains, unmapped strings) untouched.
 */
class ReportI18nTest extends TestCase {

    public function testGettextTranslatesMappedReportStrings(): void {
        $this->assertSame(
            'Ataques bloqueados',
            ReportI18n::filterGettext('Attacks blocked', 'Attacks blocked', 'dpxl-shield')
        );
        $this->assertSame(
            'Arquivos modificados recentemente',
            ReportI18n::filterGettext('Recently modified files', 'Recently modified files', 'dpxl-shield')
        );
    }

    public function testGettextLeavesUnknownStringsUntouched(): void {
        $this->assertSame(
            'Some other UI label',
            ReportI18n::filterGettext('Some other UI label', 'Some other UI label', 'dpxl-shield')
        );
    }

    public function testGettextIgnoresOtherTextDomains(): void {
        // A core string that happens to equal a mapped key must not be hijacked.
        $this->assertSame(
            'Blocks',
            ReportI18n::filterGettext('Blocks', 'Blocks', 'default')
        );
    }

    public function testNgettextPicksSingularOrPluralInPortuguese(): void {
        $single = '%d component is running an outdated version.';
        $plural = '%d components are running an outdated version.';

        $this->assertSame(
            '%d componente está com versão desatualizada.',
            ReportI18n::filterNgettext('ignored', $single, $plural, 1, 'dpxl-shield')
        );
        $this->assertSame(
            '%d componentes estão com versão desatualizada.',
            ReportI18n::filterNgettext('ignored', $single, $plural, 3, 'dpxl-shield')
        );
    }

    public function testNgettextPassesThroughUnmapped(): void {
        $this->assertSame(
            'fallback',
            ReportI18n::filterNgettext('fallback', 'x singular', 'x plural', 2, 'dpxl-shield')
        );
    }
}
