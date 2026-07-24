<?php defined('ABSPATH') || exit; ?>
<div class="dpxl-tab-pane" id="tab-diagnostics">
    <div class="dpxl-card">
        <h2>
            <?php \DPXL\Shield\Admin\Icons::render('settings'); ?> <?php esc_html_e('Diagnostics', 'dpxl-shield'); ?>
            <button class="dpxl-btn dpxl-btn--sm dpxl-float-right" id="btn-copy-diagnostics">
                <?php esc_html_e('Copy Diagnostics', 'dpxl-shield'); ?>
            </button>
        </h2>
        <button class="dpxl-btn dpxl-btn--primary dpxl-btn--sm" id="btn-run-diagnostics">
            <?php esc_html_e('Run Diagnostics', 'dpxl-shield'); ?>
        </button>
        <div id="diagnostics-container" class="dpxl-diagnostics-container">
            <div class="dpxl-loading-cell"><?php esc_html_e('Click "Run Diagnostics" to start.', 'dpxl-shield'); ?></div>
        </div>
    </div>
</div>
