<?php defined('ABSPATH') || exit; ?>
<div class="wrap dpxl-wrap" id="dpxl-dashboard">
    <?php \DPXL\Shield\Admin\AdminMenu::renderPageTitle('Painel do DPXL Shield'); ?>

    <!-- Protection status banner -->
    <div class="dpxl-banner dpxl-banner--loading" id="dpxl-protection-banner">
        <span class="dpxl-banner__text"><?php esc_html_e('Loading protection status…', 'dpxl-shield'); ?></span>
    </div>

    <!-- Gauges row -->
    <div class="dpxl-gauges-row">
        <div class="dpxl-gauge" id="gauge-firewall" data-module="firewall">
            <div class="dpxl-gauge__circle"><span class="dpxl-gauge__pct">—</span></div>
            <div class="dpxl-gauge__label"><?php esc_html_e('Firewall', 'dpxl-shield'); ?></div>
            <div class="dpxl-gauge__sub"><?php esc_html_e('Protection from known threats', 'dpxl-shield'); ?></div>
            <a class="dpxl-gauge__action" href="<?php echo esc_url(admin_url('admin.php?page=dpxl-shield-firewall')); ?>"><?php esc_html_e('Manage Firewall', 'dpxl-shield'); ?></a>
        </div>
        <div class="dpxl-gauge" id="gauge-scan" data-module="scan">
            <div class="dpxl-gauge__circle"><span class="dpxl-gauge__pct">—</span></div>
            <div class="dpxl-gauge__label"><?php esc_html_e('Scan', 'dpxl-shield'); ?></div>
            <div class="dpxl-gauge__sub"><?php esc_html_e('Detection of security issues', 'dpxl-shield'); ?></div>
            <a class="dpxl-gauge__action" href="<?php echo esc_url(admin_url('admin.php?page=dpxl-shield-scan')); ?>"><?php esc_html_e('Manage Scan', 'dpxl-shield'); ?></a>
        </div>
        <div class="dpxl-gauge" id="gauge-login" data-module="login">
            <div class="dpxl-gauge__circle"><span class="dpxl-gauge__pct">—</span></div>
            <div class="dpxl-gauge__label"><?php esc_html_e('Login Security', 'dpxl-shield'); ?></div>
            <div class="dpxl-gauge__sub"><?php esc_html_e('Brute Force + 2FA Active', 'dpxl-shield'); ?></div>
            <a class="dpxl-gauge__action" href="<?php echo esc_url(admin_url('admin.php?page=dpxl-shield-login')); ?>"><?php esc_html_e('Manage Login', 'dpxl-shield'); ?></a>
        </div>
    </div>

    <div class="dpxl-dashboard-grid">
        <!-- Notifications -->
        <div class="dpxl-card">
            <h2><?php esc_html_e('Notifications', 'dpxl-shield'); ?> <span class="dpxl-badge" id="notif-count">…</span></h2>
            <div id="dpxl-notifications" class="dpxl-skeleton-list">
                <div class="dpxl-skeleton"></div><div class="dpxl-skeleton"></div>
            </div>
        </div>

        <!-- Firewall summary -->
        <div class="dpxl-card">
            <h2><?php esc_html_e('Firewall Summary', 'dpxl-shield'); ?></h2>
            <table class="dpxl-summary-table">
                <thead><tr>
                    <th><?php esc_html_e('Block Type', 'dpxl-shield'); ?></th>
                    <th><?php esc_html_e('Today', 'dpxl-shield'); ?></th>
                    <th><?php esc_html_e('Week', 'dpxl-shield'); ?></th>
                    <th><?php esc_html_e('Month', 'dpxl-shield'); ?></th>
                </tr></thead>
                <tbody id="firewall-summary-tbody">
                    <tr><td colspan="4" class="dpxl-loading-cell"><?php esc_html_e('Loading…', 'dpxl-shield'); ?></td></tr>
                </tbody>
            </table>
        </div>

        <!-- Attack chart -->
        <div class="dpxl-card dpxl-card--full">
            <h2>
                <?php esc_html_e('Total Attacks Blocked', 'dpxl-shield'); ?>
                <span class="dpxl-card__meta" id="chart-last-updated"></span>
            </h2>
            <canvas id="attacks-chart" height="80"></canvas>
        </div>

        <!-- Top countries -->
        <div class="dpxl-card">
            <h2><?php esc_html_e('Top Countries (Last 7 Days)', 'dpxl-shield'); ?></h2>
            <ul class="dpxl-country-list" id="top-countries">
                <li class="dpxl-loading-cell"><?php esc_html_e('Loading…', 'dpxl-shield'); ?></li>
            </ul>
        </div>

        <!-- Recent logins -->
        <div class="dpxl-card">
            <h2>
                <?php esc_html_e('Recent Login Attempts', 'dpxl-shield'); ?>
                <span class="dpxl-tab-bar">
                    <button class="dpxl-tab active" data-filter="success"><?php esc_html_e('Successful', 'dpxl-shield'); ?></button>
                    <button class="dpxl-tab" data-filter="failure"><?php esc_html_e('Failed', 'dpxl-shield'); ?></button>
                </span>
            </h2>
            <table class="dpxl-mini-table">
                <thead><tr>
                    <th><?php esc_html_e('User', 'dpxl-shield'); ?></th>
                    <th><?php esc_html_e('IP', 'dpxl-shield'); ?></th>
                    <th><?php esc_html_e('Date', 'dpxl-shield'); ?></th>
                </tr></thead>
                <tbody id="recent-logins-tbody">
                    <tr><td colspan="3" class="dpxl-loading-cell"><?php esc_html_e('Loading…', 'dpxl-shield'); ?></td></tr>
                </tbody>
            </table>
        </div>
    </div>
</div>
