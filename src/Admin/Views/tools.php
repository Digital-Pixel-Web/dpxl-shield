<?php defined('ABSPATH') || exit; ?>
<div class="wrap dpxl-wrap" id="dpxl-tools">
    <?php \DPXL\Shield\Admin\AdminMenu::renderPageTitle('Ferramentas do DPXL Shield'); ?>

    <nav class="dpxl-tab-nav">
        <?php
        $currentTab = $tab ?? sanitize_key($_GET['tab'] ?? 'live-traffic');
        $toolTabs = [
            'live-traffic'  => __('Tráfego ao vivo', 'dpxl-shield'),
            'audit-log'     => __('Log de auditoria', 'dpxl-shield'),
            'whois'         => __('Consulta Whois', 'dpxl-shield'),
            'import-export' => __('Importação/Exportação', 'dpxl-shield'),
            'diagnostics'   => __('Diagnóstico', 'dpxl-shield'),
        ];
        foreach ($toolTabs as $slug => $label) : ?>
            <a class="dpxl-tab-nav__item <?php echo $currentTab === $slug ? 'is-active' : ''; ?>"
               href="<?php echo esc_url(admin_url('admin.php?page=dpxl-shield-tools&tab=' . $slug)); ?>">
                <?php echo esc_html($label); ?>
            </a>
        <?php endforeach; ?>
    </nav>

    <?php
    $partial = __DIR__ . '/tools/' . $currentTab . '.php';
    if (file_exists($partial)) {
        include $partial;
    } else {
        echo '<div class="dpxl-card"><p>' . esc_html__('View not found:', 'dpxl-shield') . ' ' . esc_html($currentTab) . '</p></div>';
    }
    ?>
</div>
