<?php
declare(strict_types=1);

namespace DPXL\Shield\Scanner;

use DPXL\Shield\Core\Logger;

/**
 * Coordinates all scan stages and persists results.
 * Designed to run via WP-Cron (full scan daily, incremental hourly).
 */
class ScanOrchestrator {

    private const STALE_TIMEOUT_SECONDS = 900; // 15 minutes without progress update.

    private string $scanId;
    private array  $results   = [];
    private bool   $cancelled = false;

    /** @var array<string, string> stage => pending|running|done|error|cancelled */
    private array $stageStatus = [];

    public function __construct() {
        $this->scanId = wp_generate_uuid4();
    }

    // ── Public API ─────────────────────────────────────────────────────────

    /**
     * Runs all stages sequentially and writes results to the database.
     * Called by the daily cron hook `dpxl_shield_full_scan`.
     */
    public function runFullScan(): array {
        @set_time_limit(0);
        @ignore_user_abort(true);

        $this->results     = [];
        $this->cancelled   = false;
        $this->stageStatus = [];

        $stages = $this->getStages();
        $this->stageStatus = array_fill_keys(array_keys($stages), 'pending');

        $this->startProgress();

        register_shutdown_function(function (): void {
            $error = error_get_last();

            if (!$error || !(bool) get_option('dpxl_shield_scan_running', false)) {
                return;
            }

            $fatalTypes = [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR];

            if (in_array((int) ($error['type'] ?? 0), $fatalTypes, true)) {
                update_option('dpxl_shield_scan_running', false, false);
                update_option('dpxl_shield_scan_current_stage', 'failed', false);
                update_option('dpxl_shield_scan_last_error', 'Scan stopped because PHP returned a fatal error: ' . ($error['message'] ?? 'Unknown error'), false);
                update_option('dpxl_shield_scan_updated_at', current_time('mysql', true), false);
            }
        });

        try {
            foreach ($stages as $name => $callback) {
                if ($this->shouldCancel()) {
                    $this->cancelled = true;
                    $this->stageStatus[$name] = 'cancelled';
                    break;
                }

                $this->setStage($name, 'running');
                $this->runStage($name, $callback);
            }

            if (!$this->cancelled) {
                $this->results = $this->normalizeResults($this->results);
                $this->persistResults();
            }
        } finally {
            $this->finalize();
        }

        return $this->results;
    }

    /**
     * Incremental scan: only checks files modified since the last scan.
     * Called by the hourly cron hook `dpxl_shield_incremental_scan`.
     */
    public function runIncrementalScan(): array {
        $this->results   = [];
        $this->cancelled = false;

        $lastScanAt = get_option('dpxl_shield_last_scan_at', '');
        $scanner    = new MalwareScanner();

        if ($lastScanAt === '') {
            return [];
        }

        $lastScanTime = strtotime($lastScanAt);
        $dirs = [
            ABSPATH . 'wp-includes/',
            ABSPATH . 'wp-admin/',
            WP_CONTENT_DIR . '/plugins/',
            WP_CONTENT_DIR . '/themes/',
            WP_CONTENT_DIR . '/uploads/',
        ];

        foreach ($dirs as $dir) {
            if (!is_dir($dir)) {
                continue;
            }

            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)
            );

            foreach ($iterator as $file) {
                if (!$file->isFile()) {
                    continue;
                }

                // Only scan files newer than the last scan.
                if ($file->getMTime() < $lastScanTime) {
                    continue;
                }

                $path = $file->getRealPath();

                if (!$path) {
                    continue;
                }

                $context = 'core';
                $normalizedPath = wp_normalize_path($path);
                if (str_contains($normalizedPath, '/uploads/')) {
                    $context = 'upload';
                } elseif (str_contains($normalizedPath, '/plugins/')) {
                    $context = 'plugin';
                } elseif (str_contains($normalizedPath, '/themes/')) {
                    $context = 'theme';
                }

                $result = $scanner->scanFile($path, $context);

                if ($result !== null) {
                    $this->results[] = $result;
                }
            }
        }

        if (!empty($this->results)) {
            $this->results = $this->normalizeResults($this->results);
            $this->persistResults();
        }

        update_option('dpxl_shield_last_incremental_scan_at', current_time('mysql', true));

        return $this->results;
    }

    public function cancel(): void {
        $this->cancelled = true;
        update_option('dpxl_shield_scan_cancel_requested', true, false);
        update_option('dpxl_shield_scan_last_error', 'Scan cancellation requested by admin.', false);
        update_option('dpxl_shield_scan_updated_at', current_time('mysql', true), false);
    }

    public function getScanId(): string {
        return $this->scanId;
    }

    /**
     * Resets an orphaned running state left by WP-Cron/PHP fatal errors.
     * A valid scan keeps dpxl_shield_scan_updated_at fresh while it is running.
     */
    public static function resetStaleScanIfNeeded(): void {
        if (!(bool) get_option('dpxl_shield_scan_running', false)) {
            return;
        }

        $updatedAt = (string) get_option('dpxl_shield_scan_updated_at', '');
        $updatedTs = $updatedAt ? strtotime($updatedAt) : 0;

        if (!$updatedTs || (time() - $updatedTs) > self::STALE_TIMEOUT_SECONDS) {
            update_option('dpxl_shield_scan_running', false, false);
            update_option('dpxl_shield_scan_current_stage', 'failed', false);
            update_option('dpxl_shield_scan_last_error', 'The previous scan stopped responding and was reset automatically. Please start a new scan.', false);
            update_option('dpxl_shield_scan_updated_at', current_time('mysql', true), false);
        }
    }

    public static function prepareQueuedScan(): void {
        $now = current_time('mysql', true);

        update_option('dpxl_shield_scan_running', true, false);
        update_option('dpxl_shield_scan_current_stage', 'queued', false);
        update_option('dpxl_shield_scan_started_at', $now, false);
        update_option('dpxl_shield_scan_updated_at', $now, false);
        update_option('dpxl_shield_scan_files_scanned', 0, false);
        update_option('dpxl_shield_scan_files_total', 0, false);
        update_option('dpxl_shield_scan_current_file', '', false);
        update_option('dpxl_shield_scan_issues_found', 0, false);
        update_option('dpxl_shield_scan_last_error', '', false);
        update_option('dpxl_shield_scan_cancel_requested', false, false);
        update_option('dpxl_shield_scan_stage_status', [], false);
    }

    // ── Stages ─────────────────────────────────────────────────────────────

    /** @return array<string, callable():array> */
    private function getStages(): array {
        return [
            'spam_check'      => [$this, 'stageSpamCheck'],
            'block_check'     => [$this, 'stageBlockCheck'],
            'server_state'    => [$this, 'stageServerState'],
            'file_changes'    => [$this, 'stageFileChanges'],
            'malware_scan'    => [$this, 'stageMalwareScan'],
            'content_safety'  => [$this, 'stageContentSafety'],
            'public_files'    => [$this, 'stagePublicFiles'],
            'password_audit'  => [$this, 'stagePasswordAudit'],
            'vulnerability'   => [$this, 'stageVulnerabilityScan'],
        ];
    }

    private function stageSpamCheck(): array {
        // Placeholder for future spamvertising feed checks. Keeping it as a real
        // stage prevents the UI from showing skipped steps as completed by mistake.
        return [];
    }

    private function stageBlockCheck(): array {
        $report = (new ReputationChecker())->run();

        if (($report['clean'] ?? true) === true) {
            return [];
        }

        return [[
            'file_path'  => 'site/reputation',
            'issue_type' => 'unknown',
            'severity'   => 'critical',
            'details'    => 'Site was found in at least one reputation/blocklist check.',
        ]];
    }

    private function stageServerState(): array {
        return (new MalwareScanner())->checkServerState();
    }

    private function stageFileChanges(): array {
        return (new ChecksumVerifier())->detectChangedCoreFiles();
    }

    private function stageMalwareScan(): array {
        $scanner = new MalwareScanner();
        $total   = $scanner->countAllScannableFiles();

        update_option('dpxl_shield_scan_files_total', $total, false);
        update_option('dpxl_shield_scan_files_scanned', 0, false);
        update_option('dpxl_shield_scan_current_file', '', false);
        $this->touchProgress();

        $lastProgressWrite = 0;

        return $scanner->scanAllFiles(function (string $filePath, int $scanned) use (&$lastProgressWrite): bool {
            if ($this->shouldCancel()) {
                $this->cancelled = true;
                return false;
            }

            // Update WP options every 10 files to avoid excessive database writes,
            // and always update the first file so the UI does not sit at zero.
            if ($scanned === 1 || $scanned - $lastProgressWrite >= 10) {
                update_option('dpxl_shield_scan_files_scanned', $scanned, false);
                update_option('dpxl_shield_scan_current_file', $this->relativePath($filePath), false);
                update_option('dpxl_shield_scan_issues_found', count($this->results), false);
                $this->touchProgress();
                $lastProgressWrite = $scanned;
            }

            return true;
        });
    }

    private function stagePublicFiles(): array {
        return (new MalwareScanner())->checkPublicFiles();
    }

    private function stageContentSafety(): array {
        $results = [];

        foreach ((new ContentSafetyChecker())->scanAllContent() as $result) {
            $results[] = $result;
        }

        return $results;
    }

    private function stagePasswordAudit(): array {
        return (new PasswordStrengthAudit())->run();
    }

    private function stageVulnerabilityScan(): array {
        return (new VulnerabilityScanner())->run();
    }

    // ── Internal ───────────────────────────────────────────────────────────

    private function runStage(string $name, callable $callback): void {
        try {
            $stageResults = $callback();

            if (is_array($stageResults)) {
                $this->results = array_merge($this->results, $stageResults);
                $this->stageStatus[$name] = $this->cancelled ? 'cancelled' : 'done';
                update_option('dpxl_shield_scan_issues_found', count($this->results), false);
            }
        } catch (\Throwable $e) {
            Logger::error("Scan stage '{$name}' failed: " . $e->getMessage());
            $this->stageStatus[$name] = 'error';
            update_option('dpxl_shield_scan_last_error', "Stage {$name} failed: " . $e->getMessage(), false);
        }

        update_option('dpxl_shield_scan_stage_status', $this->stageStatus, false);
        $this->touchProgress();
    }

    /**
     * Reduces scanner noise before saving results:
     * - removes duplicate findings from repeated detectors;
     * - downgrades low-confidence content/link findings;
     * - keeps only high-confidence issues as CRITICAL;
     * - sorts by severity so the UI shows the most important items first.
     *
     * @param list<array> $results
     * @return list<array>
     */
    private function normalizeResults(array $results): array {
        $normalized = [];
        $seen       = [];

        foreach ($results as $result) {
            $filePath = (string) ($result['file_path'] ?? 'unknown');
            $type     = (string) ($result['issue_type'] ?? 'unknown');
            $details  = (string) ($result['details'] ?? '');
            $severity = strtolower((string) ($result['severity'] ?? 'medium'));

            if (!in_array($severity, ['critical', 'high', 'medium', 'low', 'info'], true)) {
                $severity = 'medium';
            }

            if ($type === 'unknown' && str_starts_with($filePath, 'post:')) {
                if (str_contains($details, 'Dangerous iframe protocol') || str_contains($details, 'Obfuscated inline script') || str_contains($details, 'Hidden external link')) {
                    $severity = $severity === 'low' ? 'medium' : $severity;
                } else {
                    $severity = 'low';
                }
            }

            if ($type === 'heuristic' && in_array($severity, ['critical', 'high'], true)) {
                $path = wp_normalize_path($filePath);

                if ((str_contains($path, '/plugins/') || str_contains($path, '/themes/'))
                    && !str_contains($details, 'Shell execution using user-supplied input')) {
                    $severity = $severity === 'critical' ? 'high' : 'medium';
                }
            }

            if ($type === 'malware_signature' && $severity === 'critical') {
                $criticalIds = ['sig-wso', 'sig-c99', 'sig-r57', 'sig-b374k', 'sig-shell-get', 'sig-eval-b64', 'sig-wp-admin-create', 'sig-skimmer-js', 'sig-php-in-img'];
                $signatureId = (string) ($result['signature_id'] ?? '');

                if (!in_array($signatureId, $criticalIds, true)) {
                    $severity = 'high';
                }
            }

            $result['severity'] = $severity;

            $dedupeKey = md5(wp_normalize_path($filePath) . '|' . $type . '|' . (string) ($result['signature_id'] ?? '') . '|' . substr($details, 0, 180));

            if (isset($seen[$dedupeKey])) {
                continue;
            }

            $seen[$dedupeKey] = true;
            $normalized[] = $result;
        }

        $rank = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 4];

        usort($normalized, static function (array $a, array $b) use ($rank): int {
            $aRank = $rank[$a['severity'] ?? 'medium'] ?? 2;
            $bRank = $rank[$b['severity'] ?? 'medium'] ?? 2;

            if ($aRank === $bRank) {
                return strcmp((string) ($a['file_path'] ?? ''), (string) ($b['file_path'] ?? ''));
            }

            return $aRank <=> $bRank;
        });

        return array_values($normalized);
    }

    private function persistResults(): void {
        global $wpdb;

        foreach ($this->results as $result) {
            $wpdb->insert(
                $wpdb->prefix . 'dpxl_shield_scan_results',
                [
                    'scan_id'      => $this->scanId,
                    'file_path'    => $result['file_path'] ?? 'unknown',
                    'issue_type'   => $result['issue_type'] ?? 'unknown',
                    'severity'     => $result['severity'] ?? 'medium',
                    'signature_id' => $result['signature_id'] ?? null,
                    'details'      => $result['details'] ?? null,
                    'status'       => 'new',
                ],
                ['%s', '%s', '%s', '%s', '%s', '%s', '%s']
            );
        }
    }

    private function startProgress(): void {
        $now = current_time('mysql', true);

        update_option('dpxl_shield_scan_running', true, false);
        update_option('dpxl_shield_scan_current_stage', 'starting', false);
        update_option('dpxl_shield_scan_started_at', $now, false);
        update_option('dpxl_shield_scan_updated_at', $now, false);
        update_option('dpxl_shield_scan_files_scanned', 0, false);
        update_option('dpxl_shield_scan_files_total', 0, false);
        update_option('dpxl_shield_scan_current_file', '', false);
        update_option('dpxl_shield_scan_issues_found', 0, false);
        update_option('dpxl_shield_scan_last_error', '', false);
        update_option('dpxl_shield_scan_cancel_requested', false, false);
        update_option('dpxl_shield_scan_stage_status', $this->stageStatus, false);
    }

    private function setStage(string $name, string $status): void {
        $this->stageStatus[$name] = $status;
        update_option('dpxl_shield_scan_current_stage', $name, false);
        update_option('dpxl_shield_scan_stage_status', $this->stageStatus, false);
        $this->touchProgress();
    }

    private function touchProgress(): void {
        update_option('dpxl_shield_scan_updated_at', current_time('mysql', true), false);
    }

    private function finalize(): void {
        $status = $this->cancelled ? 'cancelled' : 'idle';
        $now    = current_time('mysql', true);

        // Count and alert on real threats only — advisory recommendations
        // (hardening notices, low-confidence heuristics) must not drive the
        // "issues found" badge or fire a critical alert email.
        $threats  = array_filter($this->results, [ScanClassifier::class, 'isThreat']);
        $threatCt = count($threats);

        update_option('dpxl_shield_scan_running', false, false);
        update_option('dpxl_shield_scan_current_stage', $status, false);
        update_option('dpxl_shield_last_scan_id', $this->scanId, false);
        update_option('dpxl_shield_last_scan_at', $now, false);
        update_option('dpxl_shield_last_scan_issue_count', $threatCt, false);
        update_option('dpxl_shield_scan_issues_found', $threatCt, false);
        update_option('dpxl_shield_scan_updated_at', $now, false);
        update_option('dpxl_shield_scan_cancel_requested', false, false);

        if ($this->cancelled) {
            update_option('dpxl_shield_scan_last_error', 'Scan cancelled by admin before completion.', false);
        }

        // Fire alert only if a critical *threat* was found.
        $criticals = array_filter($threats, fn($r) => ($r['severity'] ?? '') === 'critical');

        if (!empty($criticals)) {
            do_action('dpxl_shield_alert', [
                'level'       => 'critical',
                'event_type'  => 'scan_found_criticals',
                'description' => count($criticals) . ' critical issue(s) found during malware scan.',
                'context'     => ['scan_id' => $this->scanId, 'count' => count($criticals)],
            ]);
        }
    }

    private function shouldCancel(): bool {
        return (bool) get_option('dpxl_shield_scan_cancel_requested', false);
    }

    private function relativePath(string $absolutePath): string {
        $absolutePath = wp_normalize_path($absolutePath);
        $base         = wp_normalize_path(ABSPATH);

        if (str_starts_with($absolutePath, $base)) {
            return ltrim(substr($absolutePath, strlen($base)), '/');
        }

        return $absolutePath;
    }
}
