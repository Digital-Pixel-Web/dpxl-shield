<?php defined('ABSPATH') || exit; ?>
<div class="wrap dpxl-wrap" id="dpxl-all-options">
    <?php \DPXL\Shield\Admin\AdminMenu::renderPageTitle('Todas as Opções do DPXL Shield', '<div class="dpxl-page-actions"><button class="dpxl-btn dpxl-btn--sm" id="btn-restore-defaults">' . esc_html__('Restaurar padrões', 'dpxl-shield') . '</button><button class="dpxl-btn dpxl-btn--sm" id="btn-cancel-all">' . esc_html__('Cancelar', 'dpxl-shield') . '</button><button class="dpxl-btn dpxl-btn--primary" id="btn-save-all">' . esc_html__('Salvar tudo', 'dpxl-shield') . '</button></div>'); ?>

    <div class="dpxl-search-bar">
        <input type="search" class="dpxl-input dpxl-input--search" id="options-search"
               placeholder="<?php esc_attr_e('Search All Options…', 'dpxl-shield'); ?>">
        <button class="dpxl-btn" id="btn-expand-all"><?php esc_html_e('Expand All', 'dpxl-shield'); ?></button>
    </div>

    <div class="dpxl-notice dpxl-notice--success dpxl-hidden" id="all-options-saved"><?php esc_html_e('Settings saved.', 'dpxl-shield'); ?></div>

    <?php
    if (isset($_GET['dpxl_feed_checked'])) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only: picks which tab or notice to show.
        $dpxlFeedStatus = get_transient('dpxl_shield_feed_check_' . get_current_user_id());
        delete_transient('dpxl_shield_feed_check_' . get_current_user_id());

        // Back-compat: an old single-string result is treated as the rules status.
        if (is_string($dpxlFeedStatus)) {
            $dpxlFeedStatus = ['rules' => $dpxlFeedStatus];
        }

        if (is_array($dpxlFeedStatus)) {
            $dpxlRulesVersion = (string) \DPXL\Shield\Core\Options::get('threat_feed_version', '');
            $dpxlGeoVersion   = (string) \DPXL\Shield\Core\Options::get('geo_db_version', '');

            $dpxlRulesMessages = [
                /* translators: %s: rules version. */
                'ok'        => ['success', sprintf(__('WAF rules updated to version %s.', 'dpxl-shield'), $dpxlRulesVersion)],
                'no_change' => ['success', __('WAF rules are already up to date.', 'dpxl-shield')],
                'net_fail'  => ['warning', __('Could not reach the feed for WAF rules.', 'dpxl-shield')],
                'sig_fail'  => ['error',   __('WAF rules verification failed — rejected.', 'dpxl-shield')],
                'hash_fail' => ['error',   __('WAF rules verification failed — rejected.', 'dpxl-shield')],
                'no_pubkey' => ['warning', __('Feed cannot be verified on this server (missing key or sodium).', 'dpxl-shield')],
                'disabled'  => ['warning', __('The threat feed is disabled.', 'dpxl-shield')],
            ];

            $dpxlGeoMessages = [
                /* translators: %s: database version. */
                'ok'        => ['success', sprintf(__('Country database installed/updated (%s).', 'dpxl-shield'), $dpxlGeoVersion)],
                'no_change' => ['success', __('Country database is already up to date.', 'dpxl-shield')],
                'net_fail'  => ['warning', __('Could not download the country database.', 'dpxl-shield')],
                'sig_fail'  => ['error',   __('Country database verification failed — rejected.', 'dpxl-shield')],
                'hash_fail' => ['error',   __('Country database verification failed — rejected.', 'dpxl-shield')],
                'no_geo'    => ['warning', __('No country database is available in the feed yet.', 'dpxl-shield')],
                'disabled'  => ['warning', __('Country database auto-update is disabled.', 'dpxl-shield')],
            ];

            $dpxlRulesMsg = $dpxlRulesMessages[$dpxlFeedStatus['rules'] ?? ''] ?? null;
            $dpxlGeoMsg   = $dpxlGeoMessages[$dpxlFeedStatus['geo'] ?? ''] ?? null;

            foreach ([$dpxlRulesMsg, $dpxlGeoMsg] as $m) {
                if ($m !== null) {
                    printf('<div class="dpxl-notice dpxl-notice--%s">%s</div>', esc_attr($m[0]), esc_html($m[1]));
                }
            }
        }
    }
    ?>

    <form id="all-options-form">
    <?php
    $dpxlSections = [
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
                        'smtp_monitor_enabled'         => ['type' => 'toggle', 'label' => __('Monitorar o envio de e-mails', 'dpxl-shield'), 'default' => true,
                            'help' => __('Avisa quando o site para de conseguir enviar e-mails. Como nessa hora o aviso por e-mail também não sai, ele aparece como alerta dentro do painel e vai para as integrações (Slack, Discord, PagerDuty, SIEM). Quando o envio volta, um resumo é enviado por e-mail dizendo quanto tempo durou.', 'dpxl-shield')],
                        'smtp_failure_threshold'       => ['type' => 'number', 'label' => __('Falhas seguidas antes de avisar', 'dpxl-shield'), 'default' => 2, 'min' => 1, 'max' => 20,
                            'help' => __('Uma falha isolada costuma ser um destinatário recusado ou um tempo limite passageiro. Duas seguidas significam que a próxima mensagem também não vai sair.', 'dpxl-shield')],
                        'alert_admin_login_enabled'    => ['type' => 'toggle', 'label' => __('Avisar a cada entrada de administrador', 'dpxl-shield'), 'default' => true,
                            'help' => __('Envia um e-mail sempre que uma conta de administrador entra no site, inclusive nas suas entradas. É assim que uma entrada que não foi você se destaca no meio das que foram. Desligar isto não afeta o aviso de entrada a partir de uma rede nova, que continua sendo enviado.', 'dpxl-shield')],
                        'alert_email'                  => ['type' => 'email',  'label' => __('Alert Email Address', 'dpxl-shield'),          'default' => get_option('admin_email')],
                        'activity_report_enabled'      => ['type' => 'toggle', 'label' => __('Enable Activity Reports', 'dpxl-shield'),       'default' => true],
                        'activity_report_frequency'    => ['type' => 'select', 'label' => __('Report Frequency', 'dpxl-shield'),             'default' => 'weekly', 'options' => ['daily' => __('Diário', 'dpxl-shield'), 'weekly' => __('Semanal', 'dpxl-shield'), 'monthly' => __('Mensal', 'dpxl-shield')]],
                        'activity_report_pdf_enabled'  => ['type' => 'toggle', 'label' => __('Attach PDF report to email', 'dpxl-shield'),  'default' => true],
                        'activity_report_pdf_download' => ['type' => 'link',   'label' => __('Download report now', 'dpxl-shield'),
                            'button' => __('Download PDF', 'dpxl-shield'),
                            'href'   => wp_nonce_url(admin_url('admin-post.php?action=dpxl_shield_download_report_pdf'), 'dpxl_shield_download_report_pdf')],
                    ],
                ],
                'reputation' => [
                    'title'   => __('Blocklist Checks', 'dpxl-shield'),
                    'options' => [
                        'spamhaus_dqs_key' => [
                            'type'        => 'text',
                            'label'       => __('Spamhaus DQS key', 'dpxl-shield'),
                            'default'     => '',
                            'placeholder' => __('26 characters', 'dpxl-shield'),
                            'help'        => __('Spamhaus refuses lookups that reach it through a public DNS resolver, which is what most shared hosting uses — without a key the blocklist checks cannot run and will report as unavailable. A key from spamhaus.com gives this site its own query zone — Spamhaus offers a free tier for non-commercial use with low volumes. The key is left out of settings exports, since sharing one key across sites exhausts its quota.', 'dpxl-shield'),
                        ],
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
                        'rate_limit_xmlrpc'  => ['type' => 'number', 'label' => __('XML-RPC limit (req/min)', 'dpxl-shield'),   'default' => 10],
                        'rate_limit_rest'    => ['type' => 'number', 'label' => __('REST API limit (req/min)', 'dpxl-shield'),  'default' => 60],
                    ],
                ],
                'threat_feed' => [
                    'title'   => __('Threat Feed', 'dpxl-shield'),
                    'options' => [
                        'threat_feed_enabled' => ['type' => 'toggle', 'label' => __('Auto-update WAF rules from the threat feed', 'dpxl-shield'), 'default' => true],
                        'threat_feed_check'   => ['type' => 'link', 'label' => __('Check for rule updates now', 'dpxl-shield'),
                            'button' => __('Check now', 'dpxl-shield'),
                            'newtab' => false,
                            'href'   => wp_nonce_url(admin_url('admin-post.php?action=dpxl_shield_check_feed'), 'dpxl_shield_check_feed')],
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

    foreach ($dpxlSections as $dpxlSectionId => $dpxlSection) :
    ?>
    <div class="dpxl-options-section" id="section-<?php echo esc_attr($dpxlSectionId); ?>">
        <h2 class="dpxl-section-title"><?php echo esc_html($dpxlSection['title']); ?></h2>
        <?php foreach ($dpxlSection['groups'] as $dpxlGroupId => $dpxlGroup) : ?>
        <div class="dpxl-option-group" id="group-<?php echo esc_attr($dpxlGroupId); ?>">
            <button type="button" class="dpxl-option-group__toggle">
                <span class="dpxl-toggle-arrow"><?php \DPXL\Shield\Admin\Icons::render('chevron-right'); ?></span> <?php echo esc_html($dpxlGroup['title']); ?>
            </button>
            <div class="dpxl-option-group__body dpxl-hidden">
                <?php foreach ($dpxlGroup['options'] as $dpxlKey => $dpxlOpt) :
                    $dpxlVal = \DPXL\Shield\Core\Options::get($dpxlKey, $dpxlOpt['default'] ?? null);
                ?>
                <div class="dpxl-option-row" data-search-text="<?php echo esc_attr(strtolower($dpxlOpt['label'])); ?>">
                    <label for="opt-<?php echo esc_attr($dpxlKey); ?>"><?php echo esc_html($dpxlOpt['label']); ?></label>
                    <?php if ($dpxlOpt['type'] === 'toggle') : ?>
                        <label class="dpxl-toggle">
                            <input type="checkbox" id="opt-<?php echo esc_attr($dpxlKey); ?>" name="<?php echo esc_attr($dpxlKey); ?>" value="1" <?php checked((bool) $dpxlVal); ?>>
                            <span></span>
                        </label>
                    <?php elseif ($dpxlOpt['type'] === 'select') : ?>
                        <select class="dpxl-select" id="opt-<?php echo esc_attr($dpxlKey); ?>" name="<?php echo esc_attr($dpxlKey); ?>">
                            <?php foreach (($dpxlOpt['options'] ?? []) as $dpxlOptVal => $dpxlOptLabel) : ?>
                                <option value="<?php echo esc_attr($dpxlOptVal); ?>" <?php selected((string) $dpxlVal, (string) $dpxlOptVal); ?>><?php echo esc_html($dpxlOptLabel); ?></option>
                            <?php endforeach; ?>
                        </select>
                    <?php elseif ($dpxlOpt['type'] === 'email') : ?>
                        <input type="email" class="dpxl-input" id="opt-<?php echo esc_attr($dpxlKey); ?>" name="<?php echo esc_attr($dpxlKey); ?>"
                               value="<?php echo esc_attr((string) $dpxlVal); ?>">
                    <?php elseif ($dpxlOpt['type'] === 'text') : ?>
                        <input type="text" class="dpxl-input" id="opt-<?php echo esc_attr($dpxlKey); ?>" name="<?php echo esc_attr($dpxlKey); ?>"
                               value="<?php echo esc_attr((string) $dpxlVal); ?>"
                               <?php if (!empty($dpxlOpt['placeholder'])) : ?>placeholder="<?php echo esc_attr((string) $dpxlOpt['placeholder']); ?>"<?php endif; ?>
                               spellcheck="false" autocomplete="off">
                    <?php elseif ($dpxlOpt['type'] === 'link') : ?>
                        <?php $dpxlNewtab = ($dpxlOpt['newtab'] ?? true) !== false; ?>
                        <a class="dpxl-btn dpxl-btn--sm" href="<?php echo esc_url((string) ($dpxlOpt['href'] ?? '#')); ?>"<?php echo $dpxlNewtab ? ' target="_blank" rel="noopener"' : ''; ?>>
                            <?php echo esc_html((string) ($dpxlOpt['button'] ?? $dpxlOpt['label'])); ?>
                        </a>
                    <?php else : ?>
                        <input type="number" class="dpxl-input dpxl-input--sm" id="opt-<?php echo esc_attr($dpxlKey); ?>" name="<?php echo esc_attr($dpxlKey); ?>"
                               value="<?php echo esc_attr((string) $dpxlVal); ?>"
                               <?php if (isset($dpxlOpt['min'])) echo 'min="' . (int) $dpxlOpt['min'] . '"'; ?>
                               <?php if (isset($dpxlOpt['max'])) echo 'max="' . (int) $dpxlOpt['max'] . '"'; ?>>
                    <?php endif; ?>
                    <?php if (!empty($dpxlOpt['help'])) : ?>
                        <p class="dpxl-option-row__help"><?php echo esc_html((string) $dpxlOpt['help']); ?></p>
                    <?php endif; ?>
                </div>
                <?php endforeach; ?>
                <div class="dpxl-option-group__footer">
                    <button type="button" class="dpxl-btn dpxl-btn--sm dpxl-btn--save-group" data-group="<?php echo esc_attr($dpxlGroupId); ?>">
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
