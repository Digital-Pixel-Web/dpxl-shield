<?php defined('ABSPATH') || exit; ?>
<div class="dpxl-tab-pane" id="tab-diagnostics">
    <div class="dpxl-card">
        <h2>
            <?php \DPXL\Shield\Admin\Icons::render('settings'); ?> <?php esc_html_e('Diagnostics', 'dpxl-shield'); ?>
            <button class="dpxl-btn dpxl-btn--sm dpxl-float-right" id="btn-copy-diagnostics">
                <?php esc_html_e('Copy Diagnostics', 'dpxl-shield'); ?>
            </button>
        </h2>
        <p class="dpxl-muted dpxl-diagnostics-intro">
            <?php esc_html_e('O que este servidor oferece ao DPXL Shield, e o que falta. Serve para conferir antes de abrir um chamado: um item em vermelho aqui costuma explicar uma proteção que não liga ou uma checagem que não roda.', 'dpxl-shield'); ?>
        </p>
        <button class="dpxl-btn dpxl-btn--sm" id="btn-run-diagnostics">
            <?php \DPXL\Shield\Admin\Icons::render('refresh-cw'); ?> <?php esc_html_e('Verificar de novo', 'dpxl-shield'); ?>
        </button>
        <div id="diagnostics-container" class="dpxl-diagnostics-container">
            <div class="dpxl-loading-cell"><div class="dpxl-spinner"></div> <?php esc_html_e('Executando diagnóstico…', 'dpxl-shield'); ?></div>
        </div>

        <?php
        // Required attribution: DPXL Shield redistributes the GeoLite2 database
        // through its update feed, which makes MaxMind's attribution clause apply
        // to us. Must stay visible wherever the geo data is used.
        ?>
        <p class="dpxl-attribution">
            <?php
            printf(
                /* translators: %s: MaxMind website link. */
                esc_html__('This product includes GeoLite2 data created by MaxMind, available from %s.', 'dpxl-shield'),
                '<a href="https://www.maxmind.com" target="_blank" rel="noopener noreferrer">https://www.maxmind.com</a>'
            );
            ?>
        </p>
    </div>
</div>
