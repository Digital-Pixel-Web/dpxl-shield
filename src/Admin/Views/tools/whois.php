<?php defined('ABSPATH') || exit; ?>
<div class="dpxl-tab-pane" id="tab-whois">
    <div class="dpxl-card">
        <h2><?php \DPXL\Shield\Admin\Icons::render('search'); ?> <?php esc_html_e('Whois Lookup', 'dpxl-shield'); ?></h2>
        <div class="dpxl-whois-form">
            <input type="text" class="dpxl-input dpxl-input--lg" id="whois-ip-input"
                   placeholder="<?php esc_attr_e('Enter IP address or domain…', 'dpxl-shield'); ?>"
                   value="<?php echo esc_attr(sanitize_text_field(wp_unslash($_GET['ip'] ?? ''))); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only prefill of the lookup box. ?>">
            <button class="dpxl-btn dpxl-btn--primary" id="btn-whois-lookup">
                <?php esc_html_e('Lookup', 'dpxl-shield'); ?>
            </button>
        </div>
        <div class="dpxl-whois-result dpxl-hidden" id="whois-result">
            <h3><?php esc_html_e('Results for:', 'dpxl-shield'); ?> <span id="whois-result-ip"></span></h3>
            <table class="dpxl-detail-table" id="whois-detail-table"></table>
            <hr>
            <div class="dpxl-whois-actions">
                <button class="dpxl-btn dpxl-btn--danger" id="whois-btn-block"><?php esc_html_e('Block This IP', 'dpxl-shield'); ?></button>
                <button class="dpxl-btn" id="whois-btn-block-range"><?php esc_html_e('Block Range /24', 'dpxl-shield'); ?></button>
                <button class="dpxl-btn" id="whois-btn-whitelist"><?php esc_html_e('Add to Whitelist', 'dpxl-shield'); ?></button>
            </div>
            <details class="dpxl-raw-whois">
                <summary><?php esc_html_e('Raw WHOIS response', 'dpxl-shield'); ?></summary>
                <pre id="whois-raw-output"></pre>
            </details>
        </div>
        <div class="dpxl-whois-loading dpxl-hidden" id="whois-loading">
            <div class="dpxl-spinner"></div> <?php esc_html_e('Looking up…', 'dpxl-shield'); ?>
        </div>
        <div class="dpxl-notice dpxl-notice--error dpxl-hidden" id="whois-error"></div>
    </div>
</div>
