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

        <?php
        // Required attribution: DPXL Shield redistributes the GeoLite2 database
        // through its update feed, which makes MaxMind's attribution clause apply
        // to us. Must stay visible wherever the geo data is used.
        ?>
        <p class="dpxl-attribution">
            <?php
            printf(
                /* translators: %s: MaxMind website link. */
                esc_html__('This product includes GeoLite2 data created by MaxMind, available from %s.', 'dpxl-shield'),
                '<a href="https://www.maxmind.com" target="_blank" rel="noopener noreferrer">https://www.maxmind.com</a>'
            );
            ?>
        </p>
    </div>
</div>
