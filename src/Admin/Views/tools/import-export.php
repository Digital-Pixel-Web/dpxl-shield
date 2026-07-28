<?php defined('ABSPATH') || exit; ?>
<div class="dpxl-tab-pane" id="tab-import-export">
    <div class="dpxl-card">
        <h2><?php \DPXL\Shield\Admin\Icons::render('upload-cloud'); ?> <?php esc_html_e('Import / Export Options', 'dpxl-shield'); ?></h2>

        <!-- Export -->
        <div class="dpxl-ie-section">
            <h3><?php esc_html_e('Export', 'dpxl-shield'); ?></h3>
            <p><?php esc_html_e('Download all DPXL Shield settings as a signed JSON file.', 'dpxl-shield'); ?></p>
            <ul class="dpxl-ie-list">
                <li><?php \DPXL\Shield\Admin\Icons::render('check', 'dpxl-icon--ok'); ?> <?php esc_html_e('WAF rules, blocking config, scan settings, alert preferences, login security settings', 'dpxl-shield'); ?></li>
                <li><?php \DPXL\Shield\Admin\Icons::render('x', 'dpxl-icon--critical'); ?> <?php esc_html_e('Logs, scan results, TOTP secrets and webhook endpoints are NOT exported', 'dpxl-shield'); ?></li>
            </ul>
            <button class="dpxl-btn dpxl-btn--primary" id="btn-export">
                <?php esc_html_e('Export Options', 'dpxl-shield'); ?>
            </button>
        </div>

        <hr class="dpxl-divider">

        <!-- Import -->
        <div class="dpxl-ie-section">
            <h3><?php esc_html_e('Import', 'dpxl-shield'); ?></h3>
            <div class="dpxl-notice dpxl-notice--warning">
                <?php \DPXL\Shield\Admin\Icons::render('alert-triangle', 'dpxl-icon--medium'); ?> <?php esc_html_e('This will overwrite your current settings. Make sure to export a backup first.', 'dpxl-shield'); ?>
            </div>
            <div class="dpxl-file-upload">
                <input type="file" class="dpxl-input-file" id="import-file-input" accept=".json">
                <label for="import-file-input" class="dpxl-btn">
                    <?php esc_html_e('Choose File', 'dpxl-shield'); ?>
                </label>
                <span class="dpxl-file-name" id="import-file-name"><?php esc_html_e('No file selected', 'dpxl-shield'); ?></span>
            </div>
            <button class="dpxl-btn dpxl-btn--primary dpxl-hidden" id="btn-import">
                <?php esc_html_e('Import Options', 'dpxl-shield'); ?>
            </button>
            <div class="dpxl-notice dpxl-hidden" id="import-result"></div>
        </div>
    </div>
</div>
