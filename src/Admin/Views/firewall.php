<?php defined('ABSPATH') || exit;
use DPXL\Shield\Bootstrap\AutoPrepend;

$tab  = sanitize_key($_GET['tab'] ?? 'firewall');
$tabs = ['firewall', 'blocking'];
$tab  = in_array($tab, $tabs, true) ? $tab : 'firewall';

$autoPrepend        = new AutoPrepend();
$extendedStatus     = $autoPrepend->getStatus();
$downloadBackupUrl  = wp_nonce_url(admin_url('admin-post.php?action=dpxl_shield_download_htaccess_backup'), 'dpxl_shield_download_htaccess_backup');
$enableExtendedUrl  = admin_url('admin-post.php');
$backupDownloaded   = !empty($extendedStatus['htaccess_backup_downloaded']);
$extendedActive     = !empty($extendedStatus['active']);
?>
<div class="wrap dpxl-wrap" id="dpxl-firewall">
    <?php \DPXL\Shield\Admin\AdminMenu::renderPageTitle('Firewall do DPXL Shield'); ?>

    <!-- Tab nav -->
    <nav class="dpxl-tab-nav">
        <a class="dpxl-tab-nav__item <?php echo $tab === 'firewall' ? 'is-active' : ''; ?>"
           href="<?php echo esc_url(admin_url('admin.php?page=dpxl-shield-firewall&tab=firewall')); ?>">
            <?php esc_html_e('Firewall', 'dpxl-shield'); ?>
        </a>
        <a class="dpxl-tab-nav__item <?php echo $tab === 'blocking' ? 'is-active' : ''; ?>"
           href="<?php echo esc_url(admin_url('admin.php?page=dpxl-shield-firewall&tab=blocking')); ?>">
            <?php esc_html_e('Blocking', 'dpxl-shield'); ?>
        </a>
    </nav>

    <?php if ($tab === 'firewall') : ?>
    <div class="dpxl-tab-pane" id="tab-firewall">
        <!-- Extended Protection -->
        <div class="dpxl-card" id="extended-protection" data-backup-downloaded="<?php echo $backupDownloaded ? '1' : '0'; ?>">
            <h2><?php esc_html_e('Extended Protection', 'dpxl-shield'); ?></h2>
            <p id="extended-status" class="dpxl-muted">
                <?php
                if ($extendedActive) {
                    \DPXL\Shield\Admin\Icons::render('check-circle', 'dpxl-icon--ok');
                    echo ' ' . esc_html__('Extended Protection active. The WAF is loading before WordPress.', 'dpxl-shield');
                } else {
                    \DPXL\Shield\Admin\Icons::render('alert-triangle', 'dpxl-icon--medium');
                    echo ' ' . esc_html__('Extended Protection inactive. Follow the steps below to enable it safely.', 'dpxl-shield');
                }
                ?>
            </p>
            <p class="dpxl-muted"><?php esc_html_e('This works like Wordfence: DPXL Shield downloads your current .htaccess as a backup, then automatically writes the auto_prepend_file rule and verifies it with a loopback request. You can start the flow from either button; if the backup has not been downloaded yet, DPXL Shield will download it first.', 'dpxl-shield'); ?></p>

            <ol class="dpxl-extended-steps">
                <li>
                    <strong><?php esc_html_e('Backup current .htaccess', 'dpxl-shield'); ?></strong>
                    <span id="extended-backup-status" class="dpxl-step-status <?php echo $backupDownloaded ? 'is-complete' : ''; ?>">
                        <?php
                        echo $backupDownloaded
                            ? esc_html__('Backup downloaded. Ready to apply or already applied.', 'dpxl-shield')
                            : esc_html__('Required. The automatic setup starts right after the backup download.', 'dpxl-shield');
                        ?>
                    </span>
                    <a class="dpxl-btn" id="btn-download-htaccess" href="<?php echo esc_url($downloadBackupUrl); ?>">
                        <?php esc_html_e('Download Backup & Enable', 'dpxl-shield'); ?>
                    </a>
                </li>
                <li>
                    <strong><?php esc_html_e('Apply Extended Protection', 'dpxl-shield'); ?></strong>
                    <span class="dpxl-step-status">
                        <?php
                        printf(
                            /* translators: %s: server label */
                            esc_html__('Detected server: %s', 'dpxl-shield'),
                            esc_html((string) ($extendedStatus['server'] ?? 'Unknown'))
                        );
                        ?>
                    </span>
                    <form id="extended-enable-form" method="post" action="<?php echo esc_url($enableExtendedUrl); ?>" class="dpxl-inline-form">
                        <input type="hidden" name="action" value="dpxl_shield_enable_extended">
                        <?php wp_nonce_field('dpxl_shield_enable_extended'); ?>
                        <button type="submit" class="dpxl-btn dpxl-btn--primary" id="btn-enable-extended" <?php disabled($extendedActive); ?>>
                            <?php echo $extendedActive ? esc_html__('Extended Protection Active', 'dpxl-shield') : esc_html__('Enable Extended Protection', 'dpxl-shield'); ?>
                        </button>
                    </form>
                </li>
            </ol>

            <div id="extended-action-status" class="dpxl-notice dpxl-notice--warning dpxl-extended-action-status dpxl-hidden" role="status" aria-live="polite"></div>

            <table class="dpxl-detail-table dpxl-extended-meta">
                <tbody>
                    <tr><td><?php esc_html_e('.htaccess path', 'dpxl-shield'); ?></td><td><code><?php echo esc_html((string) $extendedStatus['htaccess_path']); ?></code></td></tr>
                    <tr><td><?php esc_html_e('Safe prepend loader', 'dpxl-shield'); ?></td><td><code><?php echo esc_html((string) ($extendedStatus['prepend_loader_file'] ?? '')); ?></code></td></tr>
                    <tr><td><?php esc_html_e('Plugin WAF file', 'dpxl-shield'); ?></td><td><code><?php echo esc_html((string) $extendedStatus['waf_file']); ?></code></td></tr>
                    <tr><td><?php esc_html_e('Writable', 'dpxl-shield'); ?></td><td id="extended-writable-status"><?php echo !empty($extendedStatus['htaccess_writable']) ? esc_html__('Yes', 'dpxl-shield') : esc_html__('No', 'dpxl-shield'); ?></td></tr>
                </tbody>
            </table>

            <details id="extended-manual-fallback" class="dpxl-manual-fallback">
                <summary><?php esc_html_e('Manual configuration fallback', 'dpxl-shield'); ?></summary>
                <p class="dpxl-muted"><?php esc_html_e('If DPXL Shield cannot update .htaccess automatically because of server permissions or hosting restrictions, add the configuration below manually and keep the downloaded .htaccess backup before changing anything. The auto_prepend_file rule should point to the safe prepend loader, not directly to the plugin folder.', 'dpxl-shield'); ?></p>
                <pre id="extended-snippet" class="dpxl-code-block"><?php echo esc_html((string) ($extendedStatus['manual_snippet'] ?? '')); ?></pre>
            </details>
        </div>

        <!-- Status gauges -->
        <div class="dpxl-gauges-row dpxl-gauges-row--4">
            <?php
            $gauges = [
                ['id' => 'waf',      'label' => 'WAF',          'sub' => 'Web Application Firewall'],
                ['id' => 'rules',    'label' => 'Rules',         'sub' => 'Active WAF rules'],
                ['id' => 'blocklist','label' => 'IP Blocklist',  'sub' => 'Blocked IPs'],
                ['id' => 'brute',    'label' => 'Brute Force',   'sub' => 'Login protection'],
            ];
            foreach ($gauges as $g) : ?>
                <div class="dpxl-gauge dpxl-gauge--sm" id="gauge-<?php echo esc_attr($g['id']); ?>">
                    <div class="dpxl-gauge__circle"><span class="dpxl-gauge__pct">—</span></div>
                    <div class="dpxl-gauge__label"><?php echo esc_html($g['label']); ?></div>
                    <div class="dpxl-gauge__sub"><?php echo esc_html($g['sub']); ?></div>
                </div>
            <?php endforeach; ?>
        </div>

        <!-- Top blocked IPs -->
        <div class="dpxl-card">
            <h2>
                <?php esc_html_e('Top IPs Blocked', 'dpxl-shield'); ?>
                <span class="dpxl-tab-bar">
                    <button class="dpxl-tab active" data-period="24h">24h</button>
                    <button class="dpxl-tab" data-period="7d">7 Days</button>
                    <button class="dpxl-tab" data-period="30d">30 Days</button>
                </span>
            </h2>
            <table class="dpxl-table" id="top-ips-table">
                <thead><tr>
                    <th><?php esc_html_e('IP', 'dpxl-shield'); ?></th>
                    <th><?php esc_html_e('Country', 'dpxl-shield'); ?></th>
                    <th><?php esc_html_e('Hits', 'dpxl-shield'); ?></th>
                    <th><?php esc_html_e('Actions', 'dpxl-shield'); ?></th>
                </tr></thead>
                <tbody id="top-ips-tbody"><tr><td colspan="4" class="dpxl-loading-cell"><?php esc_html_e('Loading…', 'dpxl-shield'); ?></td></tr></tbody>
            </table>
        </div>
    </div>

    <?php else : ?>
    <div class="dpxl-tab-pane" id="tab-blocking">
        <!-- Block type selector -->
        <div class="dpxl-card">
            <div class="dpxl-block-type-bar">
                <strong><?php esc_html_e('Block Type:', 'dpxl-shield'); ?></strong>
                <button class="dpxl-btn dpxl-btn--active" id="btn-type-ip"><?php esc_html_e('IP Address', 'dpxl-shield'); ?></button>
                <button class="dpxl-btn" id="btn-type-country"><?php esc_html_e('Country', 'dpxl-shield'); ?></button>
                <button class="dpxl-btn" id="btn-type-pattern"><?php esc_html_e('Custom Pattern', 'dpxl-shield'); ?></button>
            </div>
        </div>

        <!-- IP address blocking panel -->
        <div class="dpxl-card dpxl-blocking-panel" id="panel-ip">
            <div class="dpxl-toolbar">
                <input type="text" class="dpxl-input" id="ip-filter" placeholder="<?php esc_attr_e('Filter by IP, reason…', 'dpxl-shield'); ?>">
                <button class="dpxl-btn dpxl-btn--primary" id="btn-block-ip"><?php esc_html_e('Block IP', 'dpxl-shield'); ?></button>
            </div>
            <table class="dpxl-table" id="blocked-ips-table">
                <thead><tr>
                    <th><input type="checkbox" id="select-all-ips"></th>
                    <th><?php esc_html_e('IP / CIDR', 'dpxl-shield'); ?></th>
                    <th><?php esc_html_e('Reason', 'dpxl-shield'); ?></th>
                    <th><?php esc_html_e('Source', 'dpxl-shield'); ?></th>
                    <th><?php esc_html_e('Expires', 'dpxl-shield'); ?></th>
                    <th><?php esc_html_e('Actions', 'dpxl-shield'); ?></th>
                </tr></thead>
                <tbody id="blocked-ips-tbody"><tr><td colspan="6" class="dpxl-loading-cell"><?php esc_html_e('Loading…', 'dpxl-shield'); ?></td></tr></tbody>
            </table>
            <div class="dpxl-pagination" id="ip-pagination"></div>
        </div>

        <!-- Country blocking panel (hidden initially) -->
        <div class="dpxl-card dpxl-blocking-panel dpxl-hidden" id="panel-country">
            <div class="dpxl-country-mode">
                <label><input type="radio" name="country_mode" value="block" checked> <?php esc_html_e('Block countries below', 'dpxl-shield'); ?></label>
                <label><input type="radio" name="country_mode" value="allow"> <?php esc_html_e('Allow only countries below', 'dpxl-shield'); ?></label>
            </div>
            <div id="country-list-container" class="dpxl-loading-cell"><?php esc_html_e('Loading…', 'dpxl-shield'); ?></div>
            <button class="dpxl-btn dpxl-btn--primary" id="btn-save-countries"><?php esc_html_e('Save Changes', 'dpxl-shield'); ?></button>
        </div>

        <!-- Custom pattern panel (hidden initially) -->
        <div class="dpxl-card dpxl-blocking-panel dpxl-hidden" id="panel-pattern">
            <h3><?php esc_html_e('Add Custom Pattern', 'dpxl-shield'); ?></h3>
            <div class="dpxl-form-grid">
                <label><?php esc_html_e('Field', 'dpxl-shield'); ?>
                    <select class="dpxl-select" id="pattern-field">
                        <option value="user_agent">User-Agent</option>
                        <option value="referer">Referer</option>
                        <option value="hostname">Hostname</option>
                        <option value="url">URL</option>
                    </select>
                </label>
                <label><?php esc_html_e('Pattern', 'dpxl-shield'); ?>
                    <input type="text" class="dpxl-input" id="pattern-value" placeholder="sqlmap">
                </label>
                <label><?php esc_html_e('Match', 'dpxl-shield'); ?>
                    <select class="dpxl-select" id="pattern-match">
                        <option value="contains"><?php esc_html_e('Contains', 'dpxl-shield'); ?></option>
                        <option value="equals"><?php esc_html_e('Equals', 'dpxl-shield'); ?></option>
                        <option value="regex"><?php esc_html_e('Regex', 'dpxl-shield'); ?></option>
                    </select>
                </label>
                <label><?php esc_html_e('Action', 'dpxl-shield'); ?>
                    <select class="dpxl-select" id="pattern-action">
                        <option value="block"><?php esc_html_e('Block', 'dpxl-shield'); ?></option>
                        <option value="log_only"><?php esc_html_e('Log Only', 'dpxl-shield'); ?></option>
                    </select>
                </label>
                <label><?php esc_html_e('Reason (optional)', 'dpxl-shield'); ?>
                    <input type="text" class="dpxl-input" id="pattern-reason">
                </label>
                <div class="dpxl-form-actions">
                    <button class="dpxl-btn dpxl-btn--primary" id="btn-add-pattern"><?php esc_html_e('Add Rule', 'dpxl-shield'); ?></button>
                </div>
            </div>
            <table class="dpxl-table" id="custom-patterns-table">
                <thead><tr>
                    <th><?php esc_html_e('Field', 'dpxl-shield'); ?></th>
                    <th><?php esc_html_e('Pattern', 'dpxl-shield'); ?></th>
                    <th><?php esc_html_e('Match', 'dpxl-shield'); ?></th>
                    <th><?php esc_html_e('Action', 'dpxl-shield'); ?></th>
                    <th><?php esc_html_e('Reason', 'dpxl-shield'); ?></th>
                    <th></th>
                </tr></thead>
                <tbody id="patterns-tbody"><tr><td colspan="6" class="dpxl-loading-cell"><?php esc_html_e('Loading…', 'dpxl-shield'); ?></td></tr></tbody>
            </table>
        </div>
    </div>
    <?php endif; ?>
</div>
