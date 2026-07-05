<?php defined('ABSPATH') || exit; ?>
<div class="wrap dpxl-wrap" id="dpxl-scanner">
    <?php \DPXL\Shield\Admin\AdminMenu::renderPageTitle('Varredura do DPXL Shield'); ?>

    <!-- Status gauges -->
    <div class="dpxl-gauges-row dpxl-gauges-row--3">
        <div class="dpxl-gauge" id="gauge-scan-type">
            <div class="dpxl-gauge__circle"><span class="dpxl-gauge__pct">—</span></div>
            <div class="dpxl-gauge__label"><?php esc_html_e('Scan Type', 'dpxl-shield'); ?></div>
            <div class="dpxl-gauge__sub"><?php esc_html_e('Standard', 'dpxl-shield'); ?></div>
        </div>
        <div class="dpxl-gauge" id="gauge-signatures">
            <div class="dpxl-gauge__circle"><span class="dpxl-gauge__pct">—</span></div>
            <div class="dpxl-gauge__label"><?php esc_html_e('Malware Signatures', 'dpxl-shield'); ?></div>
            <div class="dpxl-gauge__sub" id="sig-status"><?php esc_html_e('Checking…', 'dpxl-shield'); ?></div>
        </div>
        <div class="dpxl-gauge" id="gauge-reputation">
            <div class="dpxl-gauge__circle"><span class="dpxl-gauge__pct">—</span></div>
            <div class="dpxl-gauge__label"><?php esc_html_e('Reputation', 'dpxl-shield'); ?></div>
            <div class="dpxl-gauge__sub"><?php esc_html_e('Blacklist checks', 'dpxl-shield'); ?></div>
        </div>
    </div>

    <!-- Scan controls -->
    <div class="dpxl-card dpxl-scan-controls">
        <div class="dpxl-scan-actions">
            <button class="dpxl-btn dpxl-btn--primary dpxl-btn--lg" id="btn-start-scan">
                <?php esc_html_e('Start New Scan', 'dpxl-shield'); ?>
            </button>
            <button class="dpxl-btn dpxl-btn--danger dpxl-hidden" id="btn-cancel-scan">
                <?php esc_html_e('Cancel Scan', 'dpxl-shield'); ?>
            </button>
            <a href="<?php echo esc_url(admin_url('admin.php?page=dpxl-shield-options#scan')); ?>" class="dpxl-btn">
                ⚙ <?php esc_html_e('Scan Options &amp; Scheduling', 'dpxl-shield'); ?>
            </a>
        </div>
        <div id="scan-last-run" class="dpxl-scan-meta"></div>
    </div>

    <!-- Scan progress -->
    <div class="dpxl-card" id="scan-progress-card">
        <div class="dpxl-stages-bar" id="stages-bar">
            <?php
            $stages = [
                'spam_check'    => 'Spam Check',
                'block_check'   => 'Block Check',
                'server_state'  => 'Server State',
                'file_changes'  => 'Files Changed',
                'malware_scan'  => 'Malware Scan',
                'content_safety'=> 'Content Safety',
                'public_files'  => 'Public Files',
                'password_audit'=> 'Pass Audit',
            ];
            foreach ($stages as $id => $label) : ?>
                <div class="dpxl-stage" id="stage-<?php echo esc_attr($id); ?>">
                    <span class="dpxl-stage__dot">○</span>
                    <span class="dpxl-stage__label"><?php echo esc_html($label); ?></span>
                </div>
            <?php endforeach; ?>
        </div>
        <div class="dpxl-scan-status-bar">
            <span id="scan-status-text"><?php esc_html_e('Idle', 'dpxl-shield'); ?></span>
            <span class="dpxl-scan-meta-actions">
                <button class="dpxl-btn dpxl-btn--sm" id="btn-email-log"><?php esc_html_e('Email Log', 'dpxl-shield'); ?></button>
            </span>
        </div>
    </div>

    <!-- Results -->
    <div class="dpxl-card" id="scan-results-card">
        <div class="dpxl-results-header">
            <h2>
                <?php esc_html_e('Results Found', 'dpxl-shield'); ?>
                <span class="dpxl-badge dpxl-badge--red" id="results-count">0</span>
            </h2>
            <div class="dpxl-results-actions">
                <button class="dpxl-btn dpxl-btn--danger" id="btn-repair-all"><?php esc_html_e('Repair All Repairable', 'dpxl-shield'); ?></button>
            </div>
        </div>

        <!-- Stats row -->
        <div class="dpxl-scan-stats" id="scan-stats">
            <div class="dpxl-stat"><span id="stat-files">0</span><small><?php esc_html_e('Files Scanned', 'dpxl-shield'); ?></small></div>
            <div class="dpxl-stat"><span id="stat-issues">0</span><small><?php esc_html_e('Issues Found', 'dpxl-shield'); ?></small></div>
            <div class="dpxl-stat"><span id="stat-critical">0</span><small><?php esc_html_e('Critical', 'dpxl-shield'); ?></small></div>
        </div>

        <div id="scan-results-list" class="dpxl-results-list">
            <div class="dpxl-empty-state">
                ✅ <?php esc_html_e('No security issues found. Your site is clean.', 'dpxl-shield'); ?>
            </div>
        </div>
    </div>
</div>
