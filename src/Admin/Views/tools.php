<?php defined('ABSPATH') || exit; ?>
<div class="wrap dpxl-wrap" id="dpxl-tools">
    <?php \DPXL\Shield\Admin\AdminMenu::renderPageTitle('Ferramentas do DPXL Shield'); ?>

    <nav class="dpxl-tab-nav">
        <?php
        $dpxlCurrentTab = $tab ?? sanitize_key($_GET['tab'] ?? 'live-traffic'); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only: picks which tab or notice to show.
        $dpxlToolTabs = [
            'live-traffic'  => __('Tráfego ao vivo', 'dpxl-shield'),
            'audit-log'     => __('Log de auditoria', 'dpxl-shield'),
            'whois'         => __('Consulta Whois', 'dpxl-shield'),
            'integrations'  => __('Integrações', 'dpxl-shield'),
            'import-export' => __('Importação/Exportação', 'dpxl-shield'),
            'diagnostics'   => __('Diagnóstico', 'dpxl-shield'),
        ];
        foreach ($dpxlToolTabs as $dpxlSlug => $dpxlLabel) : ?>
            <a class="dpxl-tab-nav__item <?php echo $dpxlCurrentTab === $dpxlSlug ? 'is-active' : ''; ?>"
               href="<?php echo esc_url(admin_url('admin.php?page=dpxl-shield-tools&tab=' . $dpxlSlug)); ?>">
                <?php echo esc_html($dpxlLabel); ?>
            </a>
        <?php endforeach; ?>
    </nav>

    <?php
    $dpxlPartial = __DIR__ . '/tools/' . $dpxlCurrentTab . '.php';
    if (file_exists($dpxlPartial)) {
        include $dpxlPartial;
    } else {
        echo '<div class="dpxl-card"><p>' . esc_html__('View not found:', 'dpxl-shield') . ' ' . esc_html($dpxlCurrentTab) . '</p></div>';
    }
    ?>
</div>
