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
                <?php \DPXL\Shield\Admin\Icons::render('settings'); ?> <?php esc_html_e('Scan Options &amp; Scheduling', 'dpxl-shield'); ?>
            </a>
        </div>
        <div id="scan-last-run" class="dpxl-scan-meta"></div>
    </div>

    <!-- Scan progress -->
    <div class="dpxl-card" id="scan-progress-card">
        <div class="dpxl-stepper" id="stages-bar">
            <?php
            $stages = [
                'spam_check'    => 'Spam',
                'block_check'   => 'Blocklist',
                'server_state'  => 'Servidor',
                'file_changes'  => 'Arquivos',
                'malware_scan'  => 'Malware',
                'content_safety'=> 'Conteúdo',
                'public_files'  => 'Públicos',
                'password_audit'=> 'Senhas',
            ];
            foreach ($stages as $id => $label) : ?>
                <div class="dpxl-step" id="stage-<?php echo esc_attr($id); ?>" data-state="pending">
                    <span class="dpxl-step__icon"></span>
                    <span class="dpxl-step__label"><?php echo esc_html($label); ?></span>
                </div>
            <?php endforeach; ?>
        </div>
        <div class="dpxl-scan-progressbar" id="scan-progressbar" hidden>
            <div class="dpxl-scan-progressbar__fill" id="scan-progressbar-fill"></div>
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
                <?php esc_html_e('Ameaças encontradas', 'dpxl-shield'); ?>
                <span class="dpxl-badge dpxl-badge--red dpxl-hidden" id="results-count">0</span>
            </h2>
            <div class="dpxl-results-actions">
                <button class="dpxl-btn dpxl-btn--primary dpxl-hidden" id="btn-repair-all"><?php esc_html_e('Repair All Repairable', 'dpxl-shield'); ?></button>
            </div>
        </div>

        <!-- Stats row -->
        <div class="dpxl-scan-stats" id="scan-stats">
            <div class="dpxl-stat"><span id="stat-files">0</span><small><?php esc_html_e('Arquivos verificados', 'dpxl-shield'); ?></small></div>
            <div class="dpxl-stat"><span id="stat-issues">0</span><small><?php esc_html_e('Ameaças', 'dpxl-shield'); ?></small></div>
            <div class="dpxl-stat dpxl-stat--critical"><span id="stat-critical">0</span><small><?php esc_html_e('Críticas', 'dpxl-shield'); ?></small></div>
        </div>

        <div id="scan-results-list" class="dpxl-results-list">
            <div class="dpxl-empty-state dpxl-empty-state--clean">
                <?php esc_html_e('Nenhuma ameaça encontrada. Seu site está limpo.', 'dpxl-shield'); ?>
            </div>
        </div>
    </div>

    <!-- Recommendations (advisory — not counted as threats) -->
    <div class="dpxl-card dpxl-recs-card dpxl-hidden" id="scan-recs-card">
        <div class="dpxl-results-header">
            <h2>
                <?php esc_html_e('Recomendações', 'dpxl-shield'); ?>
                <span class="dpxl-badge dpxl-badge--muted" id="recs-count">0</span>
            </h2>
            <button class="dpxl-btn dpxl-btn--sm" id="btn-toggle-recs" aria-expanded="false"><?php esc_html_e('Mostrar', 'dpxl-shield'); ?></button>
        </div>
        <p class="dpxl-recs-intro"><?php esc_html_e('Melhorias de segurança e avisos de baixa confiança. Não são comprometimentos e não entram na contagem de ameaças.', 'dpxl-shield'); ?></p>
        <div id="scan-recs-list" class="dpxl-results-list dpxl-hidden"></div>
    </div>
</div>
