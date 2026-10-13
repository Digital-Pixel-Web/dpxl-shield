<?php defined('ABSPATH') || exit;
$tab  = sanitize_key($_GET['tab'] ?? '2fa');
$tabs = ['2fa', 'settings'];
$tab  = in_array($tab, $tabs, true) ? $tab : '2fa';
?>
<div class="wrap dpxl-wrap" id="dpxl-login">
    <?php \DPXL\Shield\Admin\AdminMenu::renderPageTitle('Segurança de Login do DPXL Shield'); ?>

    <nav class="dpxl-tab-nav">
        <a class="dpxl-tab-nav__item <?php echo $tab === '2fa' ? 'is-active' : ''; ?>"
           href="<?php echo esc_url(admin_url('admin.php?page=dpxl-shield-login&tab=2fa')); ?>">
            <?php esc_html_e('Two-Factor Authentication', 'dpxl-shield'); ?>
        </a>
        <a class="dpxl-tab-nav__item <?php echo $tab === 'settings' ? 'is-active' : ''; ?>"
           href="<?php echo esc_url(admin_url('admin.php?page=dpxl-shield-login&tab=settings')); ?>">
            <?php esc_html_e('Settings', 'dpxl-shield'); ?>
        </a>
    </nav>

    <?php if ($tab === '2fa') : ?>
    <div class="dpxl-tab-pane" id="tab-2fa">
        <?php
        $userId    = get_current_user_id();
        $user      = wp_get_current_user();
        $has2fa    = !empty(get_user_meta($userId, '_dpxl_shield_totp_secret', true));
        ?>
        <?php
        // The screen only ever answered "is 2FA on for me". The question the
        // dashboard gauge actually asks — and the one that decides whether the
        // site is covered — is how many administrators have finished setting it
        // up. On the staging install that was zero while the gauge read 100%.
        $admins    = get_users(['role' => 'administrator', 'fields' => 'ID', 'number' => 100]);
        $adminCt   = is_array($admins) ? count($admins) : 0;
        $covered   = 0;

        foreach ((array) $admins as $adminId) {
            if (get_user_meta((int) $adminId, 'dpxl_shield_totp_enabled', true)) {
                $covered++;
            }
        }
        ?>
        <div class="dpxl-card dpxl-2fa-coverage dpxl-2fa-coverage--<?php echo $covered > 0 ? 'ok' : 'warn'; ?>">
            <?php \DPXL\Shield\Admin\Icons::render($covered > 0 ? 'check-circle' : 'alert-triangle', $covered > 0 ? 'dpxl-icon--ok' : 'dpxl-icon--medium'); ?>
            <div>
                <strong><?php
                    printf(
                        /* translators: 1: administrators with 2FA, 2: total administrators */
                        esc_html(_n(
                            '%1$d de %2$d administrador com verificação em duas etapas ativa',
                            '%1$d de %2$d administradores com verificação em duas etapas ativa',
                            $adminCt,
                            'dpxl-shield'
                        )),
                        $covered,
                        $adminCt
                    );
                ?></strong>
                <p class="dpxl-muted"><?php
                    echo $covered > 0
                        ? esc_html__('Uma conta de administrador sem segunda etapa continua sendo uma senha só. Vale cobrir todas.', 'dpxl-shield')
                        : esc_html__('Enquanto for zero, a senha é a única coisa entre um invasor e o painel deste site.', 'dpxl-shield');
                ?></p>
            </div>
        </div>

        <div class="dpxl-card">
            <h2><?php \DPXL\Shield\Admin\Icons::render('lock'); ?> <?php esc_html_e('Two-Factor Authentication', 'dpxl-shield'); ?> <a href="#" class="dpxl-learn-more"><?php esc_html_e('Learn more', 'dpxl-shield'); ?> <?php \DPXL\Shield\Admin\Icons::render('external-link', '', 13); ?></a></h2>
            <p><?php printf(esc_html__('Editing user: %s (you)', 'dpxl-shield'), esc_html($user->user_login)); ?></p>

            <?php if ($has2fa) : ?>
                <div class="dpxl-notice dpxl-notice--success">
                    <?php \DPXL\Shield\Admin\Icons::render('check-circle', 'dpxl-icon--ok'); ?> <?php esc_html_e('Two-Factor Authentication is ACTIVE for this account.', 'dpxl-shield'); ?>
                </div>
                <div class="dpxl-2fa-actions">
                    <a href="<?php echo esc_url(wp_nonce_url(admin_url('admin.php?page=dpxl-shield-login&action=deactivate_2fa&tab=2fa'), 'deactivate_2fa')); ?>" class="dpxl-btn dpxl-btn--danger">
                        <?php esc_html_e('Deactivate 2FA', 'dpxl-shield'); ?>
                    </a>
                    <button class="dpxl-btn" id="btn-regen-codes"><?php esc_html_e('Regenerate Recovery Codes', 'dpxl-shield'); ?></button>
                </div>
            <?php else : ?>
                <div class="dpxl-2fa-setup">
                    <div class="dpxl-2fa-qr">
                        <h3><?php esc_html_e('1. Scan Code or Enter Key', 'dpxl-shield'); ?></h3>
                        <div id="dpxl-qr-container" class="dpxl-qr-placeholder">
                            <p><?php esc_html_e('Loading QR code…', 'dpxl-shield'); ?></p>
                        </div>
                        <input type="text" class="dpxl-input dpxl-input--mono" id="totp-manual-key" readonly placeholder="<?php esc_attr_e('Loading…', 'dpxl-shield'); ?>">
                    </div>
                    <div class="dpxl-2fa-verify">
                        <h3><?php esc_html_e('2. Enter Code from App', 'dpxl-shield'); ?></h3>
                        <div class="dpxl-backup-codes" id="backup-codes-container">
                            <p><?php esc_html_e('Loading recovery codes…', 'dpxl-shield'); ?></p>
                        </div>
                        <button class="dpxl-btn dpxl-btn--sm" id="btn-download-codes"><?php \DPXL\Shield\Admin\Icons::render('download'); ?> <?php esc_html_e('Download Codes', 'dpxl-shield'); ?></button>
                        <div class="dpxl-2fa-activate">
                            <input type="text" class="dpxl-input dpxl-input--otp" id="totp-code" placeholder="123456" maxlength="6" autocomplete="one-time-code">
                            <button class="dpxl-btn dpxl-btn--primary" id="btn-activate-2fa"><?php esc_html_e('Activate', 'dpxl-shield'); ?></button>
                        </div>
                    </div>
                </div>
                <div class="dpxl-2fa-info">
                    <span><?php esc_html_e('Server Time:', 'dpxl-shield'); ?> <?php echo esc_html(gmdate('H:i:s T')); ?></span>
                    <span><?php esc_html_e('Detected IP:', 'dpxl-shield'); ?> <code><?php echo esc_html(sanitize_text_field($_SERVER['REMOTE_ADDR'] ?? '')); ?></code></span>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <?php else : ?>
    <div class="dpxl-tab-pane" id="tab-login-settings">
        <form id="login-settings-form">
        <div class="dpxl-card">
            <h2><?php esc_html_e('Brute Force Protection', 'dpxl-shield'); ?></h2>
            <div class="dpxl-option-row">
                <label><?php esc_html_e('Lock out after X failed login attempts', 'dpxl-shield'); ?></label>
                <input type="number" class="dpxl-input dpxl-input--sm" name="brute_force_threshold" value="20" min="3" max="100">
            </div>
            <div class="dpxl-option-row">
                <label><?php esc_html_e('Count failures over X minutes', 'dpxl-shield'); ?></label>
                <input type="number" class="dpxl-input dpxl-input--sm" name="brute_force_window_minutes" value="5" min="1" max="60">
            </div>
            <div class="dpxl-option-row">
                <label><?php esc_html_e('Notify by email when locked out', 'dpxl-shield'); ?></label>
                <label class="dpxl-toggle"><input type="checkbox" name="brute_force_notify_email" value="1"> <span></span></label>
            </div>
        </div>
        <div class="dpxl-card">
            <h2><?php esc_html_e('Enforce 2FA by Role', 'dpxl-shield'); ?></h2>
            <?php foreach (['administrator' => 'Administrator', 'editor' => 'Editor', 'author' => 'Author', 'contributor' => 'Contributor'] as $role => $label) : ?>
                <label class="dpxl-checkbox-label">
                    <input type="checkbox" name="2fa_required_roles[]" value="<?php echo esc_attr($role); ?>" <?php echo $role === 'administrator' ? 'checked' : ''; ?>>
                    <?php echo esc_html($label); ?>
                </label>
            <?php endforeach; ?>
        </div>
        <div class="dpxl-card">
            <h2><?php esc_html_e('Additional Options', 'dpxl-shield'); ?></h2>
            <?php
            $opts = [
                'password_audit_enabled'  => __('Check passwords against breach database (HaveIBeenPwned)', 'dpxl-shield'),
                'generic_login_errors'    => __('Hide WordPress login errors (generic message)', 'dpxl-shield'),
                'disable_xmlrpc_auth'     => __('Disable XML-RPC authentication', 'dpxl-shield'),
            ];
            foreach ($opts as $name => $label) : ?>
                <div class="dpxl-option-row">
                    <label><?php echo esc_html($label); ?></label>
                    <label class="dpxl-toggle"><input type="checkbox" name="<?php echo esc_attr($name); ?>" value="1"> <span></span></label>
                </div>
            <?php endforeach; ?>
        </div>
        <div class="dpxl-form-footer">
            <button type="submit" class="dpxl-btn dpxl-btn--primary"><?php esc_html_e('Save Changes', 'dpxl-shield'); ?></button>
            <span class="dpxl-save-indicator" id="settings-saved"></span>
        </div>
        </form>
    </div>
    <?php endif; ?>
</div>
