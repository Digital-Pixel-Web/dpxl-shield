<?php defined('ABSPATH') || exit; ?>
<div class="dpxl-tab-pane" id="tab-audit-log">
    <div class="dpxl-card">
        <h2><?php esc_html_e('Audit Log', 'dpxl-shield'); ?> <a href="#" class="dpxl-learn-more"><?php esc_html_e('Learn more', 'dpxl-shield'); ?> <?php \DPXL\Shield\Admin\Icons::render('external-link', '', 13); ?></a></h2>

        <!-- Options accordion -->
        <div class="dpxl-option-group">
            <button type="button" class="dpxl-option-group__toggle">
                <span class="dpxl-toggle-arrow"><?php \DPXL\Shield\Admin\Icons::render('chevron-down'); ?></span> <?php esc_html_e('Audit Log Options', 'dpxl-shield'); ?>
            </button>
            <div class="dpxl-option-group__body">
                <div class="dpxl-mode-selector">
                    <label><?php esc_html_e('Logging mode:', 'dpxl-shield'); ?></label>
                    <?php foreach (['disabled' => __('Desativado', 'dpxl-shield'), 'preview' => __('Pré-visualização', 'dpxl-shield'), 'significant_events' => __('Eventos significativos', 'dpxl-shield'), 'all_events' => __('Todos os eventos', 'dpxl-shield')] as $val => $label) : ?>
                        <button class="dpxl-btn dpxl-mode-btn <?php echo \DPXL\Shield\Core\Options::get('audit_mode', 'significant_events') === $val ? 'dpxl-btn--active' : ''; ?>"
                                data-mode="<?php echo esc_attr($val); ?>"><?php echo esc_html($label); ?></button>
                    <?php endforeach; ?>
                </div>
                <input type="hidden" id="audit-mode-value" name="audit_mode" value="<?php echo esc_attr((string) \DPXL\Shield\Core\Options::get('audit_mode', 'significant_events')); ?>">
                <div class="dpxl-option-group__footer">
                    <button class="dpxl-btn dpxl-btn--sm" id="btn-restore-audit"><?php esc_html_e('Restore Defaults', 'dpxl-shield'); ?></button>
                    <button class="dpxl-btn dpxl-btn--primary dpxl-btn--sm" id="btn-save-audit"><?php esc_html_e('Save Changes', 'dpxl-shield'); ?></button>
                </div>
            </div>
        </div>

        <!-- Chain integrity -->
        <div class="dpxl-integrity-bar">
            <span><?php \DPXL\Shield\Admin\Icons::render('shield'); ?> <?php esc_html_e('Integrity:', 'dpxl-shield'); ?></span>
            <button class="dpxl-btn dpxl-btn--sm" id="btn-verify-chain"><?php esc_html_e('Verify Log Chain', 'dpxl-shield'); ?></button>
            <span class="dpxl-chain-status" id="chain-status"></span>
        </div>

        <!-- Filters -->
        <div class="dpxl-audit-filters">
            <select class="dpxl-select" id="audit-severity-filter">
                <option value=""><?php esc_html_e('All Severities', 'dpxl-shield'); ?></option>
                <option value="critical"><?php esc_html_e('Critical', 'dpxl-shield'); ?></option>
                <option value="high"><?php esc_html_e('High', 'dpxl-shield'); ?></option>
                <option value="medium"><?php esc_html_e('Medium', 'dpxl-shield'); ?></option>
                <option value="low"><?php esc_html_e('Low', 'dpxl-shield'); ?></option>
                <option value="info"><?php esc_html_e('Info', 'dpxl-shield'); ?></option>
            </select>
            <select class="dpxl-select" id="audit-type-filter">
                <option value=""><?php esc_html_e('All Event Types', 'dpxl-shield'); ?></option>
                <option value="auth"><?php esc_html_e('Authentication', 'dpxl-shield'); ?></option>
                <option value="user"><?php esc_html_e('User / Permissions', 'dpxl-shield'); ?></option>
                <option value="plugin"><?php esc_html_e('Plugins / Updates', 'dpxl-shield'); ?></option>
                <option value="fw"><?php esc_html_e('Firewall', 'dpxl-shield'); ?></option>
                <option value="settings"><?php esc_html_e('Site Settings', 'dpxl-shield'); ?></option>
            </select>
            <button class="dpxl-btn dpxl-btn--primary dpxl-btn--sm" id="btn-filter-audit"><?php esc_html_e('Filter', 'dpxl-shield'); ?></button>
        </div>

        <table class="dpxl-table" id="audit-log-table">
            <thead><tr>
                <th style="width:32px;"><?php esc_html_e('Type', 'dpxl-shield'); ?></th>
                <th><?php esc_html_e('Time', 'dpxl-shield'); ?></th>
                <th><?php esc_html_e('Event', 'dpxl-shield'); ?></th>
                <th><?php esc_html_e('Actor', 'dpxl-shield'); ?></th>
                <th><?php esc_html_e('IP', 'dpxl-shield'); ?></th>
            </tr></thead>
            <tbody id="audit-log-tbody">
                <tr><td colspan="5" class="dpxl-loading-cell"><?php esc_html_e('Loading…', 'dpxl-shield'); ?></td></tr>
            </tbody>
        </table>
        <div class="dpxl-pagination" id="audit-pagination"></div>

        <!-- Category legend -->
        <div class="dpxl-audit-legend">
            <?php
            $cats = [
                'auth'     => ['color' => 'yellow',  'label' => __('Authentication', 'dpxl-shield')],
                'user'     => ['color' => 'purple',  'label' => __('User/Permissions', 'dpxl-shield')],
                'plugin'   => ['color' => 'blue',    'label' => __('Plugin/Updates', 'dpxl-shield')],
                'firewall' => ['color' => 'red',     'label' => __('Firewall', 'dpxl-shield')],
                'settings' => ['color' => 'green',   'label' => __('Site Settings', 'dpxl-shield')],
                'content'  => ['color' => 'gray',    'label' => __('Content', 'dpxl-shield')],
            ];
            foreach ($cats as $cat => $meta) : ?>
                <span class="dpxl-audit-dot dpxl-audit-dot--<?php echo esc_attr($meta['color']); ?>"></span>
                <?php echo esc_html($meta['label']); ?>
            <?php endforeach; ?>
        </div>
    </div>
</div>
