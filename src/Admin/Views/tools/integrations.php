<?php defined('ABSPATH') || exit; ?>
    <!-- Outbound integrations tab -->
    <div class="dpxl-tab-pane" id="tab-integrations">
        <div class="dpxl-card">
            <h2>
                <?php \DPXL\Shield\Admin\Icons::render('bell'); ?>
                <?php esc_html_e('Outbound webhooks', 'dpxl-shield'); ?>
            </h2>

            <p class="dpxl-card__intro">
                <?php esc_html_e('Push security events to Slack, Discord, PagerDuty or any SIEM as they happen. Each endpoint has its own severity threshold, so a chat channel can take only the serious ones while a SIEM takes everything.', 'dpxl-shield'); ?>
            </p>

            <p class="dpxl-card__intro">
                <?php esc_html_e('Events are queued during the request and delivered after the response is sent, so a slow endpoint never adds latency to your site.', 'dpxl-shield'); ?>
            </p>

            <div id="webhooks-container" class="dpxl-loading-cell"><?php esc_html_e('Loading…', 'dpxl-shield'); ?></div>

            <button class="dpxl-btn dpxl-btn--primary" id="btn-add-webhook">
                <?php esc_html_e('Add endpoint', 'dpxl-shield'); ?>
            </button>
        </div>

        <!-- Add / edit form (hidden until used) -->
        <div class="dpxl-card dpxl-hidden" id="webhook-form-card">
            <h3 id="webhook-form-title"><?php esc_html_e('Add endpoint', 'dpxl-shield'); ?></h3>

            <input type="hidden" id="webhook-id" value="">

            <div class="dpxl-form-grid">
                <label><?php esc_html_e('Name', 'dpxl-shield'); ?>
                    <input type="text" class="dpxl-input" id="webhook-label" placeholder="Slack #security">
                </label>

                <label><?php esc_html_e('Destination', 'dpxl-shield'); ?>
                    <select class="dpxl-select" id="webhook-format">
                        <option value="slack">Slack</option>
                        <option value="discord">Discord</option>
                        <option value="pagerduty">PagerDuty</option>
                        <option value="generic"><?php esc_html_e('Generic JSON (SIEM)', 'dpxl-shield'); ?></option>
                    </select>
                </label>

                <label class="dpxl-form-grid__wide"><?php esc_html_e('Webhook URL (HTTPS)', 'dpxl-shield'); ?>
                    <input type="url" class="dpxl-input" id="webhook-url" placeholder="https://hooks.slack.com/services/…">
                    <span class="dpxl-field-hint">
                        <?php esc_html_e('Plain HTTP is refused — these payloads describe attacks on your site and must not travel in the clear.', 'dpxl-shield'); ?>
                    </span>
                </label>

                <label><?php esc_html_e('Send events from', 'dpxl-shield'); ?>
                    <select class="dpxl-select" id="webhook-min-level">
                        <option value="critical"><?php esc_html_e('Critical only', 'dpxl-shield'); ?></option>
                        <option value="high"><?php esc_html_e('High and above', 'dpxl-shield'); ?></option>
                        <option value="medium" selected><?php esc_html_e('Medium and above', 'dpxl-shield'); ?></option>
                        <option value="low"><?php esc_html_e('Low and above', 'dpxl-shield'); ?></option>
                        <option value="info"><?php esc_html_e('Everything', 'dpxl-shield'); ?></option>
                    </select>
                </label>

                <label id="webhook-secret-field">
                    <span id="webhook-secret-label"><?php esc_html_e('Signing secret (optional)', 'dpxl-shield'); ?></span>
                    <input type="password" class="dpxl-input" id="webhook-secret" autocomplete="new-password">
                    <span class="dpxl-field-hint" id="webhook-secret-hint">
                        <?php esc_html_e('Signs each payload so your receiver can verify it really came from this site. Leave blank when editing to keep the current value.', 'dpxl-shield'); ?>
                    </span>
                </label>

                <label class="dpxl-toggle-label">
                    <input type="checkbox" id="webhook-enabled" checked>
                    <?php esc_html_e('Enabled', 'dpxl-shield'); ?>
                </label>

                <div class="dpxl-form-actions">
                    <button class="dpxl-btn dpxl-btn--primary" id="btn-save-webhook"><?php esc_html_e('Save', 'dpxl-shield'); ?></button>
                    <button class="dpxl-btn" id="btn-cancel-webhook"><?php esc_html_e('Cancel', 'dpxl-shield'); ?></button>
                </div>
            </div>
        </div>
    </div>
