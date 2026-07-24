<?php defined('ABSPATH') || exit; ?>
    <!-- Live Traffic tab -->
    <div class="dpxl-tab-pane" id="tab-live-traffic">
        <div class="dpxl-card">
            <div class="dpxl-traffic-toolbar">
                <select class="dpxl-select" id="traffic-type-filter">
                    <option value=""><?php esc_html_e('All Hits', 'dpxl-shield'); ?></option>
                    <option value="human"><?php esc_html_e('Human', 'dpxl-shield'); ?></option>
                    <option value="bot"><?php esc_html_e('Bot / Crawler', 'dpxl-shield'); ?></option>
                    <option value="blocked"><?php esc_html_e('Blocked', 'dpxl-shield'); ?></option>
                </select>
                <button class="dpxl-btn" id="btn-show-filters"><?php \DPXL\Shield\Admin\Icons::render('sliders'); ?> <?php esc_html_e('Show Advanced Filters', 'dpxl-shield'); ?></button>
                <label class="dpxl-toggle-label">
                    <input type="checkbox" id="traffic-live-update" checked>
                    <?php esc_html_e('Live Update', 'dpxl-shield'); ?>
                </label>
            </div>

            <!-- Advanced filters (hidden) -->
            <div class="dpxl-advanced-filters dpxl-hidden" id="advanced-filters">
                <div class="dpxl-filter-grid">
                    <label><?php esc_html_e('IP', 'dpxl-shield'); ?> <input type="text" class="dpxl-input" id="filter-ip" placeholder="1.2.3.4"></label>
                    <label><?php esc_html_e('URL', 'dpxl-shield'); ?> <input type="text" class="dpxl-input" id="filter-url" placeholder="/wp-login.php"></label>
                    <label><?php esc_html_e('Response', 'dpxl-shield'); ?>
                        <select class="dpxl-select" id="filter-response">
                            <option value=""><?php esc_html_e('All', 'dpxl-shield'); ?></option>
                            <option value="200">200</option><option value="403">403</option>
                            <option value="404">404</option><option value="500">500</option>
                        </select>
                    </label>
                </div>
                <button class="dpxl-btn dpxl-btn--primary" id="btn-apply-filters"><?php esc_html_e('Apply Filters', 'dpxl-shield'); ?></button>
                <button class="dpxl-btn" id="btn-reset-filters"><?php esc_html_e('Reset', 'dpxl-shield'); ?></button>
            </div>

            <table class="dpxl-table dpxl-table--traffic" id="traffic-table">
                <thead><tr>
                    <th style="width:28px;"></th>
                    <th><?php esc_html_e('Type', 'dpxl-shield'); ?></th>
                    <th><?php esc_html_e('Location', 'dpxl-shield'); ?></th>
                    <th><?php esc_html_e('Page Visited', 'dpxl-shield'); ?></th>
                    <th><?php esc_html_e('IP', 'dpxl-shield'); ?></th>
                    <th><?php esc_html_e('Response', 'dpxl-shield'); ?></th>
                    <th></th>
                </tr></thead>
                <tbody id="traffic-tbody">
                    <tr><td colspan="7" class="dpxl-loading-cell"><?php esc_html_e('Loading…', 'dpxl-shield'); ?></td></tr>
                </tbody>
            </table>
            <div id="traffic-pagination" class="dpxl-pagination"></div>
        </div>
    </div>

    <!-- Request detail modal -->
    <div class="dpxl-modal dpxl-hidden" id="traffic-detail-modal" role="dialog" aria-modal="true" aria-label="<?php esc_attr_e('Request Detail', 'dpxl-shield'); ?>">
        <div class="dpxl-modal__backdrop" id="modal-backdrop"></div>
        <div class="dpxl-modal__content">
            <div class="dpxl-modal__header">
                <h2><?php esc_html_e('Request Detail', 'dpxl-shield'); ?></h2>
                <button class="dpxl-modal__close" id="btn-close-modal" aria-label="<?php esc_attr_e('Close', 'dpxl-shield'); ?>"><?php \DPXL\Shield\Admin\Icons::render('x'); ?></button>
            </div>
            <div class="dpxl-modal__body" id="modal-body">
                <table class="dpxl-detail-table" id="request-detail-table"></table>
            </div>
            <div class="dpxl-modal__footer">
                <button class="dpxl-btn dpxl-btn--danger" id="modal-btn-block"><?php esc_html_e('Block This IP', 'dpxl-shield'); ?></button>
                <button class="dpxl-btn" id="modal-btn-whois"><?php esc_html_e('Whois Lookup', 'dpxl-shield'); ?></button>
                <button class="dpxl-btn" id="modal-btn-whitelist"><?php esc_html_e('Whitelist', 'dpxl-shield'); ?></button>
            </div>
        </div>
    </div>
