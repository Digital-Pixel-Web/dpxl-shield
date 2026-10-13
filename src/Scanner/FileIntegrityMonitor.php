<?php
declare(strict_types=1);

namespace DPXL\Shield\Scanner;

use DPXL\Shield\Core\Options;
use DPXL\Shield\Core\Logger;

/**
 * Continuous per-request monitor for critical WordPress and plugin files.
 *
 * Different from MalwareScanner (periodic): this runs on every WordPress
 * request (init hook, priority 1) and checks only a small curated list
 * of files whose modification would indicate active compromise.
 */
class FileIntegrityMonitor {

    /**
     * Critical WordPress core files checked on every request.
     * Relative paths from ABSPATH.
     */
    private const CRITICAL_CORE_FILES = [
        'wp-config.php',
        'wp-includes/functions.php',
        'wp-includes/pluggable.php',
        'wp-includes/class-wp-hook.php',
        'wp-includes/load.php',
        'wp-admin/includes/plugin.php',
    ];

    private ChecksumVerifier $verifier;

    public function __construct(?ChecksumVerifier $verifier = null) {
        $this->verifier = $verifier ?? new ChecksumVerifier();
    }

    // ── Hook Registration ──────────────────────────────────────────────────

    public function registerHooks(): void {
        // Per-request integrity check — priority 1 = runs before almost everything.
        add_action('init', [$this, 'checkCriticalFiles'], 1);

        // Re-record baselines after WordPress or plugin updates.
        add_action('upgrader_process_complete', [$this, 'onUpgrade'], 10, 2);

        // Alert handler.
        add_action('dpxl_shield_integrity_violation', [$this, 'handleViolation'], 10, 2);
    }

    // ── Per-request Check ──────────────────────────────────────────────────

    /**
     * Runs on `init` (priority 1). Fast: only checks the small critical list.
     */
    public function checkCriticalFiles(): void {
        if (!Options::get('file_integrity_monitor_enabled', true)) {
            return;
        }

        foreach (self::CRITICAL_CORE_FILES as $relative) {
            $absolute = ABSPATH . $relative;

            if (!file_exists($absolute)) {
                continue;
            }

            $status = $this->verifier->verify($absolute);

            if ($status === false) {
                do_action('dpxl_shield_integrity_violation', $absolute, $relative);
            }
            // null means no baseline yet — silent until first baseline is recorded.
        }

    }

    // ── Violation Handler ──────────────────────────────────────────────────

    public function handleViolation(string $absolutePath, string $relativePath): void {
        // Alert at most once per hour per modified file to prevent flooding on every request.
        // The admin sees the alert once and can review; repeated alerts serve no purpose.
        $transientKey = 'dpxl_integrity_alerted_' . md5($absolutePath);

        if (get_transient($transientKey)) {
            return;
        }

        // A baseline mismatch only means the file is not what it was. It does not
        // mean the file is not WordPress. Core updates rewrite these files for
        // perfectly good reasons, and plenty of them never reach
        // `upgrader_process_complete`: background auto-updates, WP-CLI, and host
        // control panels (hPanel, cPanel) that update core behind WordPress's back.
        // Re-baselining only on that hook therefore leaves the baseline stale and
        // turns every later request into a "critical compromise" email.
        //
        // So before raising the alarm, ask the authority. If the file on disk is
        // byte-for-byte the official release for the running version, it is stock
        // WordPress: adopt it as the new baseline and say nothing.
        $official = $this->verifier->matchesOfficialCore($relativePath);

        if ($official === true) {
            $this->verifier->record($absolutePath, 'core');
            Logger::debug("Linha de base de integridade atualizada pelo manifesto do WP.org: {$relativePath}");
            return;
        }

        set_transient($transientKey, true, HOUR_IN_SECONDS);

        // `null` é a terceira resposta, e por dois meses ela foi tratada como se
        // fosse `false`: o manifesto não pôde ser consultado — a versão que o
        // WordPress reporta não é a dos arquivos em disco (acontece durante uma
        // atualização de core), o arquivo não está no manifesto daquela versão,
        // ou a consulta à api.wordpress.org não respondeu. Nada disso é prova de
        // comprometimento, e chamar de "crítico" o que não foi verificado é
        // exatamente o que ensina o leitor a ignorar o alerta.
        //
        // Numa homologação isso rendeu de 1 a 8 e-mails críticos por dia durante
        // semanas sobre wp-admin/includes/plugin.php, um arquivo que o próprio
        // `wp core verify-checksums` dava como idêntico ao oficial. Pararam
        // sozinhos no segundo em que uma atualização de core terminou e versão e
        // arquivos voltaram a concordar.
        $verified = $official === false;

        Logger::error(($verified ? 'Integridade: arquivo difere do oficial: ' : 'Integridade: não foi possível verificar: ') . $absolutePath);

        do_action('dpxl_shield_alert', [
            'level'       => $verified ? 'critical' : 'medium',
            'event_type'  => $verified ? 'file_modified' : 'file_unverified',
            'description' => $verified
                ? "Arquivo do WordPress difere da versão oficial: {$relativePath}"
                : "Arquivo do WordPress mudou e não foi possível conferir contra o manifesto oficial: {$relativePath}",
            'context'     => [
                'file'      => $relativePath,
                'timestamp' => current_time('mysql', true),
                'conferido' => $verified ? 'sim, difere do manifesto oficial' : 'não, o manifesto oficial não pôde ser consultado',
            ],
        ]);
    }

    // ── Baseline Management ────────────────────────────────────────────────

    /**
     * Records the initial baseline — called during plugin activation.
     */
    public function recordInitialBaseline(): void {
        // Core critical files.
        foreach (self::CRITICAL_CORE_FILES as $relative) {
            $absolute = ABSPATH . $relative;

            if (file_exists($absolute)) {
                $this->verifier->record($absolute, 'core');
            }
        }

        // Plugin own files.
        $this->recordPluginBaseline();

        update_option('dpxl_shield_integrity_baseline_at', current_time('mysql', true));
    }

    public function recordPluginBaseline(): void {
        $this->verifier->recordDirectory(DPXL_SHIELD_PATH . 'src/', 'shieldwp');
        $this->verifier->record(DPXL_SHIELD_PATH . 'dpxl-shield.php', 'shieldwp');
        $this->verifier->record(DPXL_SHIELD_PATH . 'dpxl-shield-waf.php', 'shieldwp');
    }

    /**
     * Called after a WordPress core or plugin update — re-records baselines
     * so the monitor doesn't alert on legitimate update-induced changes.
     *
     * @param mixed $upgrader WP_Upgrader instance — unused, but part of the hook signature.
     */
    public function onUpgrade($upgrader, array $hookExtra): void {
        $type = $hookExtra['type'] ?? '';

        if ($type === 'core') {
            // Invalidate WP.org checksum cache so next scan fetches the new version.
            WpOrgChecksumApi::invalidateCache();

            foreach (self::CRITICAL_CORE_FILES as $relative) {
                $absolute = ABSPATH . $relative;

                if (file_exists($absolute)) {
                    $this->verifier->record($absolute, 'core');
                }
            }
        }

        if ($type === 'plugin') {
            // Re-record our own plugin files if we were updated.
            $plugins = $hookExtra['plugins'] ?? [];

            if (in_array(DPXL_SHIELD_BASENAME, $plugins, true)) {
                $this->recordPluginBaseline();
            }
        }
    }
}
