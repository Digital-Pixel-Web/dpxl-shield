<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Alerts;

use DPXL\Shield\Alerts\EventCatalog;
use PHPUnit\Framework\TestCase;

/**
 * The catalog is the contract between a machine slug and what a human reads.
 *
 * Until 1.8.0 it was English while the email shell around it was pt-BR, so
 * every alert arrived half-translated — subject included. These tests pin the
 * four things an alert needs for each catalogued event: a title, a sentence
 * saying what happened, at least one next step, and a button that opens the
 * screen the event is about.
 */
class EventCatalogTest extends TestCase {

    /**
     * Every event the plugin can dispatch today. Adding a slug to the catalog
     * without adding it here is fine; dispatching one that is not catalogued
     * is what this list exists to catch.
     *
     * @return list<array{0: string}>
     */
    public function catalogued(): array {
        return array_map(
            static function (string $slug): array {
                return [$slug];
            },
            [
                'new_admin_ip_login',
                'brute_force_lockout',
                'auth.lockout',
                '2fa_activated',
                '2fa_deactivated',
                'pwned_password_login',
                'pwned_password_reset',
                'user.created',
                'user.deleted',
                'user.role_changed',
                'fw.ip_blocked',
                'fw.rule_triggered',
                'fw.reputation_hit',
                'anomaly_detected',
                'honeypot_triggered',
                'decoy_accessed',
                'file_modified',
                'plugin_tampered',
                'plugin_deactivated',
                'plugin_deleted',
                'integrity_store_conflict',
                'scan_found_criticals',
            ]
        );
    }

    /** @dataProvider catalogued */
    public function testEveryEventHasATitleAndAnExplanation(string $slug): void {
        $this->assertNotSame('', EventCatalog::label($slug), "{$slug} has no title");
        $this->assertNotSame('', EventCatalog::summary($slug), "{$slug} has no summary");
    }

    /**
     * An alert that cannot be acted on still has to say so. "Nenhuma ação é
     * necessária" is an answer; silence is what teaches people to ignore the
     * sender.
     *
     * @dataProvider catalogued
     */
    public function testEveryEventHasAtLeastOneNextStep(string $slug): void {
        $actions = EventCatalog::actions($slug);

        $this->assertNotEmpty($actions, "{$slug} tells the reader nothing to do");

        foreach ($actions as $action) {
            $this->assertNotSame('', trim($action));
        }
    }

    /** @dataProvider catalogued */
    public function testEveryEventPointsAtAnAdminScreen(string $slug): void {
        $link = EventCatalog::primaryLink($slug);

        $this->assertArrayHasKey('label', $link);
        $this->assertArrayHasKey('query', $link);
        $this->assertStringStartsWith('page=dpxl-shield', $link['query'], "{$slug} links somewhere else");
        $this->assertNotSame('', $link['label']);
    }

    /**
     * The button used to send every alert to the plugin's front page, leaving
     * the reader to hunt for what the email had just told them.
     */
    public function testLinksAreSpecificToTheKindOfEvent(): void {
        $this->assertSame('page=dpxl-shield-login', EventCatalog::primaryLink('new_admin_ip_login')['query']);
        $this->assertSame('page=dpxl-shield-scan', EventCatalog::primaryLink('scan_found_criticals')['query']);
        $this->assertSame(
            'page=dpxl-shield-tools&tab=audit-log',
            EventCatalog::primaryLink('user.role_changed')['query']
        );
    }

    /** The catalog is pt-BR; a leftover English title is a regression. */
    public function testTitlesAreInPortuguese(): void {
        $this->assertSame('Login de administrador de um endereço novo', EventCatalog::label('new_admin_ip_login'));
        $this->assertSame('Seu site foi listado em uma blocklist', EventCatalog::label('fw.reputation_hit'));
        $this->assertSame('Endereço IP', EventCatalog::fieldLabel('ip'));
        $this->assertSame('ID do usuário', EventCatalog::fieldLabel('user_id'));
    }

    /**
     * Only the events that genuinely fire on normal activity carry a caveat.
     * A reassurance on every alert would discount all of them.
     */
    public function testCaveatsExistOnlyWhereTheAlertIsRoutine(): void {
        $this->assertStringContainsString('IPv6', EventCatalog::caveat('new_admin_ip_login'));
        $this->assertStringContainsString('atualiz', EventCatalog::caveat('file_modified'));

        $this->assertSame('', EventCatalog::caveat('plugin_tampered'));
        $this->assertSame('', EventCatalog::caveat('pwned_password_login'));
    }

    /**
     * A slug nobody catalogued yet still has to produce a readable email
     * rather than printing the slug in the subject line.
     */
    public function testUncataloguedSlugFallsBackToAReadableForm(): void {
        $this->assertSame('Something new', EventCatalog::label('fw.something_new'));
        $this->assertSame('', EventCatalog::summary('fw.something_new'));
        $this->assertSame([], EventCatalog::actions('fw.something_new'));
        $this->assertSame('page=dpxl-shield', EventCatalog::primaryLink('fw.something_new')['query']);
    }
}
