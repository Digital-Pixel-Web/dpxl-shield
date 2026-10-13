<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Scanner;

use Brain\Monkey;
use Brain\Monkey\Functions;
use DPXL\Shield\Scanner\ChecksumVerifier;
use DPXL\Shield\Scanner\FileIntegrityMonitor;
use PHPUnit\Framework\TestCase;

/**
 * "Não consegui conferir" deixou de ser dito como "comprometido".
 *
 * `matchesOfficialCore()` tem três respostas, e por dois meses duas delas
 * caíram no mesmo lugar. `false` é o caso que merece alarme: o arquivo foi
 * comparado com o manifesto oficial daquela release e difere. `null` é outra
 * coisa inteira — a consulta não pôde ser feita, porque a versão que o
 * WordPress reporta não corresponde aos arquivos em disco (o que acontece
 * enquanto uma atualização de core está em andamento), porque o arquivo não
 * consta do manifesto daquela versão, ou porque api.wordpress.org não
 * respondeu.
 *
 * Numa das homologações isso rendeu de 1 a 8 e-mails "Critical file modified"
 * por dia, durante semanas, sobre wp-admin/includes/plugin.php — um arquivo
 * que `wp core verify-checksums` dava como idêntico ao oficial. Pararam
 * sozinhos no segundo em que uma atualização de core terminou e a linha de
 * base foi regravada.
 */
class IntegrityUnverifiedTest extends TestCase {

    /** @var list<array<string,mixed>> */
    private array $alerts = [];

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();

        $this->alerts = [];

        Functions\when('get_transient')->justReturn(false);
        Functions\when('set_transient')->justReturn(true);
        Functions\when('current_time')->justReturn('2026-10-13 22:00:00');
        Functions\when('do_action')->alias(function (string $hook, $payload = null): void {
            if ($hook === 'dpxl_shield_alert') {
                $this->alerts[] = $payload;
            }
        });
    }

    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }

    /**
     * @param bool|null $official what matchesOfficialCore() answers
     * @return array<string,mixed>|null the alert that was dispatched, if any
     */
    private function violationWith(?bool $official): ?array {
        $verifier = $this->createMock(ChecksumVerifier::class);
        $verifier->method('matchesOfficialCore')->willReturn($official);

        $monitor = new FileIntegrityMonitor($verifier);
        $monitor->handleViolation('/var/www/wp-admin/includes/plugin.php', 'wp-admin/includes/plugin.php');

        return $this->alerts[0] ?? null;
    }

    /** Stock WordPress: adopt it as the new baseline and say nothing. */
    public function testAFileThatMatchesTheOfficialReleaseRaisesNothing(): void {
        $this->assertNull($this->violationWith(true));
    }

    /** Genuinely different from the official release: that is the alarm. */
    public function testAFileThatDiffersFromTheOfficialReleaseIsCritical(): void {
        $alert = $this->violationWith(false);

        $this->assertNotNull($alert);
        $this->assertSame('critical', $alert['level']);
        $this->assertSame('file_modified', $alert['event_type']);
        $this->assertStringContainsString('difere da versão oficial', $alert['description']);
    }

    /**
     * The case that produced weeks of false critical mail: the check could not
     * be made. It is reported, because the file did change — but it is not
     * reported as a compromise, and it does not claim the comparison happened.
     */
    public function testAFileThatCouldNotBeCheckedIsNotCritical(): void {
        $alert = $this->violationWith(null);

        $this->assertNotNull($alert, 'A mudança ainda precisa ser registrada.');
        $this->assertNotSame('critical', $alert['level']);
        $this->assertSame('file_unverified', $alert['event_type']);
        $this->assertStringContainsString('não foi possível conferir', $alert['description']);
        $this->assertStringContainsString('não', $alert['context']['conferido']);
    }

    /** Both paths say, in the alert itself, whether the comparison happened. */
    public function testTheAlertRecordsWhetherTheComparisonWasActuallyMade(): void {
        $this->assertStringContainsString('sim', (string) $this->violationWith(false)['context']['conferido']);

        $this->alerts = [];

        $this->assertStringContainsString('não', (string) $this->violationWith(null)['context']['conferido']);
    }
}
