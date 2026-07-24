<?php defined('ABSPATH') || exit; ?>
<div class="wrap dpxl-wrap" id="dpxl-all-options">
    <?php \DPXL\Shield\Admin\AdminMenu::renderPageTitle('Todas as Opções do DPXL Shield', '<div class="dpxl-page-actions"><button class="dpxl-btn dpxl-btn--sm" id="btn-restore-defaults">' . esc_html__('Restaurar padrões', 'dpxl-shield') . '</button><button class="dpxl-btn dpxl-btn--sm" id="btn-cancel-all">' . esc_html__('Cancelar', 'dpxl-shield') . '</button><button class="dpxl-btn dpxl-btn--primary" id="btn-save-all">' . esc_html__('Salvar tudo', 'dpxl-shield') . '</button></div>'); ?>

    <div class="dpxl-search-bar">
        <input type="search" class="dpxl-input dpxl-input--search" id="options-search"
               placeholder="<?php esc_attr_e('Search All Options…', 'dpxl-shield'); ?>">
        <button class="dpxl-btn" id="btn-expand-all"><?php esc_html_e('Expand All', 'dpxl-shield'); ?></button>
    </div>

    <div class="dpxl-notice dpxl-notice--success dpxl-hidden" id="all-options-saved"><?php esc_html_e('Settings saved.', 'dpxl-shield'); ?></div>

    <form id="all-options-form">
    <?php
    $sections = [
        'global' => [
            'title'   => __('Global Options', 'dpxl-shield'),
            'groups'  => [
                'general' => [
                    'title'   => __('General Options', 'dpxl-shield'),
                    'options' => [
                        'firewall_enabled'     => ['type' => 'toggle', 'label' => __('Enable Firewall', 'dpxl-shield'),           'default' => true],
                        'traffic_log_enabled'  => ['type' => 'toggle', 'label' => __('Enable Traffic Logging', 'dpxl-shield'),     'default' => true],
                        'honeypot_enabled'     => ['type' => 'toggle', 'label' => __('Enable Honeypots', 'dpxl-shield'),          'default' => true],
                    ],
                ],
                'alerts' => [
                    'title'   => __('Email Alert Preferences', 'dpxl-shield'),
                    'options' => [
                        'email_alerts_enabled'         => ['type' => 'toggle', 'label' => __('Enable Email Alerts', 'dpxl-shield'),          'default' => true],
                        'alert_email'                  => ['type' => 'email',  'label' => __('Alert Email Address', 'dpxl-shield'),          'default' => get_option('admin_email')],
                        'activity_report_enabled'      => ['type' => 'toggle', 'label' => __('Enable Activity Reports', 'dpxl-shield'),       'default' => true],
                        'activity_report_frequency'    => ['type' => 'select', 'label' => __('Report Frequency', 'dpxl-shield'),             'default' => 'weekly', 'options' => ['daily' => __('Diário', 'dpxl-shield'), 'weekly' => __('Semanal', 'dpxl-shield'), 'monthly' => __('Mensal', 'dpxl-shield')]],
                    ],
                ],
            ],
        ],
        'firewall' => [
            'title'  => __('Firewall Options', 'dpxl-shield'),
            'groups' => [
                'basic_firewall' => [
                    'title'   => __('Basic Firewall Options', 'dpxl-shield'),
                    'options' => [
                        'waf_sqli_enabled'  => ['type' => 'toggle', 'label' => __('SQL Injection Protection', 'dpxl-shield'),   'default' => true],
                        'waf_xss_enabled'   => ['type' => 'toggle', 'label' => __('XSS Protection', 'dpxl-shield'),            'default' => true],
                        'waf_lfi_enabled'   => ['type' => 'toggle', 'label' => __('Path Traversal (LFI) Protection', 'dpxl-shield'), 'default' => true],
                        'waf_rfi_enabled'   => ['type' => 'toggle', 'label' => __('Remote File Inclusion Protection', 'dpxl-shield'), 'default' => true],
                    ],
                ],
                'brute_force' => [
                    'title'   => __('Brute Force Protection', 'dpxl-shield'),
                    'options' => [
                        'brute_force_enabled'          => ['type' => 'toggle', 'label' => __('Enable Brute Force Protection', 'dpxl-shield'), 'default' => true],
                        'brute_force_threshold'        => ['type' => 'number', 'label' => __('Limite de tentativas de login', 'dpxl-shield'),      'default' => 20, 'min' => 3, 'max' => 100],
                        'brute_force_window_minutes'   => ['type' => 'number', 'label' => __('Janela (minutos)', 'dpxl-shield'),             'default' => 5, 'min' => 1, 'max' => 60],
                    ],
                ],
                'rate_limiting' => [
                    'title'   => __('Limitação de taxa', 'dpxl-shield'),
                    'options' => [
                        'rate_limit_login'   => ['type' => 'number', 'label' => __('Login page limit (req/min)', 'dpxl-shield'), 'default' => 5],
                        'rate_limit_xmlrpc'  => ['type' => 'number', 'label' => __('XML-RPC limit (req/min)', 'dpxl-shield'),   'default' => 3],
                        'rate_limit_rest'    => ['type' => 'number', 'label' => __('REST API limit (req/min)', 'dpxl-shield'),  'default' => 60],
                    ],
                ],
            ],
        ],
        'scan' => [
            'title'  => __('Scan Options', 'dpxl-shield'),
            'groups' => [
                'schedule' => [
                    'title'   => __('Scan Scheduling', 'dpxl-shield'),
                    'options' => [
                        'scan_time_hour'  => ['type' => 'number', 'label' => __('Hora da varredura completa (0–23 UTC)', 'dpxl-shield'), 'default' => 3, 'min' => 0, 'max' => 23],
                        'scan_on_demand'  => ['type' => 'toggle', 'label' => __('Permitir varreduras sob demanda', 'dpxl-shield'),    'default' => true],
                    ],
                ],
                'scan_content' => [
                    'title'   => __('Scan Content', 'dpxl-shield'),
                    'options' => [
                        'scan_core_files'      => ['type' => 'toggle', 'label' => __('Scan WordPress core files', 'dpxl-shield'), 'default' => true],
                        'scan_plugins'         => ['type' => 'toggle', 'label' => __('Scan plugin files', 'dpxl-shield'),         'default' => true],
                        'scan_themes'          => ['type' => 'toggle', 'label' => __('Scan theme files', 'dpxl-shield'),          'default' => true],
                        'scan_uploads'         => ['type' => 'toggle', 'label' => __('Scan uploads directory', 'dpxl-shield'),    'default' => true],
                        'scan_content_safety'  => ['type' => 'toggle', 'label' => __('Scan post content for malicious links', 'dpxl-shield'), 'default' => true],
                    ],
                ],
            ],
        ],
        'tools' => [
            'title'  => __('Tool Options', 'dpxl-shield'),
            'groups' => [
                'traffic' => [
                    'title'   => __('Opções de tráfego ao vivo', 'dpxl-shield'),
                    'options' => [
                        'traffic_log_retention_hours' => ['type' => 'number', 'label' => __('Retenção de logs (horas)', 'dpxl-shield'), 'default' => 24, 'min' => 1, 'max' => 720],
                    ],
                ],
                'audit_log' => [
                    'title'   => __('Opções do log de auditoria', 'dpxl-shield'),
                    'options' => [
                        'audit_mode' => ['type' => 'select', 'label' => __('Modo de registro', 'dpxl-shield'), 'default' => 'significant_events',
                            'options' => ['disabled' => __('Desativado', 'dpxl-shield'), 'preview' => __('Pré-visualização', 'dpxl-shield'), 'significant_events' => __('Eventos significativos', 'dpxl-shield'), 'all_events' => __('Todos os eventos', 'dpxl-shield')]],
                    ],
                ],
                'login_security' => [
                    'title'   => __('Opções de segurança de login', 'dpxl-shield'),
                    'options' => [
                        'password_audit_enabled' => ['type' => 'toggle', 'label' => __('Auditoria de senhas HIBP', 'dpxl-shield'),    'default' => true],
                        'generic_login_errors'   => ['type' => 'toggle', 'label' => __('Mensagens genéricas de erro de login', 'dpxl-shield'), 'default' => false],
                    ],
                ],
            ],
        ],
    ];

    foreach ($sections as $sectionId => $section) :
    ?>
    <div class="dpxl-options-section" id="section-<?php echo esc_attr($sectionId); ?>">
        <h2 class="dpxl-section-title"><?php echo esc_html($section['title']); ?></h2>
        <?php foreach ($section['groups'] as $groupId => $group) : ?>
        <div class="dpxl-option-group" id="group-<?php echo esc_attr($groupId); ?>">
            <button type="button" class="dpxl-option-group__toggle">
                <span class="dpxl-toggle-arrow"><?php \DPXL\Shield\Admin\Icons::render('chevron-right'); ?></span> <?php echo esc_html($group['title']); ?>
            </button>
            <div class="dpxl-option-group__body dpxl-hidden">
                <?php foreach ($group['options'] as $key => $opt) :
                    $val = \DPXL\Shield\Core\Options::get($key, $opt['default'] ?? null);
                ?>
                <div class="dpxl-option-row" data-search-text="<?php echo esc_attr(strtolower($opt['label'])); ?>">
                    <label for="opt-<?php echo esc_attr($key); ?>"><?php echo esc_html($opt['label']); ?></label>
                    <?php if ($opt['type'] === 'toggle') : ?>
                        <label class="dpxl-toggle">
                            <input type="checkbox" id="opt-<?php echo esc_attr($key); ?>" name="<?php echo esc_attr($key); ?>" value="1" <?php checked((bool) $val); ?>>
                            <span></span>
                        </label>
                    <?php elseif ($opt['type'] === 'select') : ?>
                        <select class="dpxl-select" id="opt-<?php echo esc_attr($key); ?>" name="<?php echo esc_attr($key); ?>">
                            <?php foreach (($opt['options'] ?? []) as $optVal => $optLabel) : ?>
                                <option value="<?php echo esc_attr($optVal); ?>" <?php selected((string) $val, (string) $optVal); ?>><?php echo esc_html($optLabel); ?></option>
                            <?php endforeach; ?>
                        </select>
                    <?php elseif ($opt['type'] === 'email') : ?>
                        <input type="email" class="dpxl-input" id="opt-<?php echo esc_attr($key); ?>" name="<?php echo esc_attr($key); ?>"
                               value="<?php echo esc_attr((string) $val); ?>">
                    <?php else : ?>
                        <input type="number" class="dpxl-input dpxl-input--sm" id="opt-<?php echo esc_attr($key); ?>" name="<?php echo esc_attr($key); ?>"
                               value="<?php echo esc_attr((string) $val); ?>"
                               <?php if (isset($opt['min'])) echo 'min="' . (int) $opt['min'] . '"'; ?>
                               <?php if (isset($opt['max'])) echo 'max="' . (int) $opt['max'] . '"'; ?>>
                    <?php endif; ?>
                </div>
                <?php endforeach; ?>
                <div class="dpxl-option-group__footer">
                    <button type="button" class="dpxl-btn dpxl-btn--sm dpxl-btn--save-group" data-group="<?php echo esc_attr($groupId); ?>">
                        <?php esc_html_e('Save Changes', 'dpxl-shield'); ?>
                    </button>
                </div>
            </div>
        </div>
        <?php endforeach; ?>
    </div>
    <?php endforeach; ?>
    </form>
</div>
