<?php
declare(strict_types=1);

namespace DPXL\Shield\LoginSecurity;

use DPXL\Shield\Core\Options;
use DPXL\Shield\Core\Logger;
use OTPHP\TOTP;

/**
 * TOTP-based Two-Factor Authentication (RFC 6238).
 *
 * Compatible with Google Authenticator, Authy, 1Password, and any
 * standards-compliant TOTP app.
 *
 * Flow:
 *   1. wp_authenticate_user filter (priority 20) intercepts successful credential auth.
 *   2. If user has 2FA enabled, stores pending user in a short-lived transient
 *      keyed by a random token, sets a cookie with the token, returns WP_Error.
 *   3. WordPress renders login page with action=dpxl_2fa.
 *   4. login_form_dpxl_2fa renders the TOTP entry form.
 *   5. On POST, verifies code → sets auth cookie → redirects.
 */
class TwoFactorAuth {

    private const SECRET_META      = 'dpxl_shield_totp_secret';
    private const ENABLED_META     = 'dpxl_shield_totp_enabled';
    private const PENDING_TRANSIENT = 'dpxl_2fa_pending_';   // + token
    private const PENDING_COOKIE   = 'dpxl_shield_2fa_token';
    private const PENDING_TTL      = 300;                    // 5 minutes to complete 2FA
    private const TOTP_WINDOW      = 1;                      // ±1 step = ±30 s tolerance

    private LoginAudit $audit;

    public function __construct(LoginAudit $audit) {
        $this->audit = $audit;
    }

    // ── Hook Registration ──────────────────────────────────────────────────

    public function registerHooks(): void {
        // Intercept login after credential check, before session creation.
        add_filter('wp_authenticate_user', [$this, 'interceptLogin'], 20);

        // Custom login action to render + handle the 2FA form.
        add_action('login_form_dpxl_2fa', [$this, 'handleTwoFactorPage']);

        // Add 2FA fields to user profile page.
        add_action('show_user_profile', [$this, 'renderProfileSection']);
        add_action('edit_user_profile', [$this, 'renderProfileSection']);
        add_action('personal_options_update', [$this, 'handleProfileSave']);
        add_action('edit_user_profile_update', [$this, 'handleProfileSave']);
    }

    // ── Login Intercept ────────────────────────────────────────────────────

    /**
     * Runs on `wp_authenticate_user` (priority 20).
     * If 2FA is configured AND enabled for this user, initiates the challenge flow.
     * Users whose role requires 2FA but who haven't configured it yet are allowed
     * in and prompted to set it up from their profile — they are never hard-blocked.
     */
    public function interceptLogin(\WP_User|\WP_Error $user): \WP_User|\WP_Error {
        if (is_wp_error($user)) {
            return $user;
        }

        // Only intercept when the user has actually configured 2FA.
        // Role-based enforcement (isRequired) is advisory; blocking login
        // before setup is done would permanently lock out administrators.
        if (!$this->isEnabled($user->ID)) {
            return $user;
        }

        // Store pending user in a transient keyed by a random token.
        $token = bin2hex(random_bytes(32));

        set_transient(self::PENDING_TRANSIENT . $token, $user->ID, self::PENDING_TTL);

        // Set cookie so the 2FA form can retrieve the pending user.
        setcookie(self::PENDING_COOKIE, $token, [
            'expires'  => time() + self::PENDING_TTL,
            'path'     => COOKIEPATH,
            'domain'   => COOKIE_DOMAIN,
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Strict',
        ]);

        $this->audit->record2faRequired($user->user_login, $this->currentIp());

        return new \WP_Error(
            'dpxl_2fa_required',
            __('Two-factor authentication required.', 'dpxl-shield')
        );
    }

    // ── 2FA Page Handler ───────────────────────────────────────────────────

    /**
     * Runs on `login_form_dpxl_2fa` action (i.e. wp-login.php?action=dpxl_2fa).
     * Handles both rendering the form and processing the POST submission.
     */
    public function handleTwoFactorPage(): void {
        $token  = $_COOKIE[self::PENDING_COOKIE] ?? '';
        $userId = $token !== '' ? (int) get_transient(self::PENDING_TRANSIENT . $token) : 0;

        if ($userId === 0) {
            // No valid pending 2FA session — redirect to login.
            wp_safe_redirect(wp_login_url());
            exit;
        }

        $user = get_user_by('id', $userId);

        if (!$user) {
            wp_safe_redirect(wp_login_url());
            exit;
        }

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $this->processSubmission($user, $token);
            return;
        }

        $this->renderForm($user);
    }

    private function processSubmission(\WP_User $user, string $token): void {
        check_admin_referer('dpxl_2fa_verify');

        $code = sanitize_text_field($_POST['dpxl_2fa_code'] ?? '');
        $code = preg_replace('/\s+/', '', $code);

        $valid = $this->verifyCode($user->ID, $code)
            || BackupCodes::verify($user->ID, $code);

        if (!$valid) {
            $this->audit->record2faFailed($user->user_login, $this->currentIp());

            $this->renderForm($user, __('Invalid authentication code. Please try again.', 'dpxl-shield'));
            return;
        }

        // Code is valid — consume the pending session and complete the login.
        delete_transient(self::PENDING_TRANSIENT . $token);
        setcookie(self::PENDING_COOKIE, '', time() - 3600, COOKIEPATH, COOKIE_DOMAIN);

        wp_set_auth_cookie($user->ID, !empty($_POST['rememberme']));
        do_action('wp_login', $user->user_login, $user);

        $redirect = isset($_POST['redirect_to'])
            ? wp_sanitize_redirect(wp_unslash($_POST['redirect_to']))
            : admin_url();

        wp_safe_redirect($redirect);
        exit;
    }

    private function renderForm(\WP_User $user, string $error = ''): never {
        login_header(__('Two-Factor Authentication', 'dpxl-shield'));

        if ($error !== '') {
            echo '<div id="login_error">' . esc_html($error) . '</div>';
        }
        ?>
        <form name="dpxl_2fa_form" id="dpxl-2fa-form" method="POST">
            <?php wp_nonce_field('dpxl_2fa_verify'); ?>

            <p>
                <label for="dpxl_2fa_code">
                    <?php esc_html_e('Enter the 6-digit code from your authenticator app, or a backup code:', 'dpxl-shield'); ?>
                </label>
                <input
                    type="text"
                    name="dpxl_2fa_code"
                    id="dpxl_2fa_code"
                    class="input"
                    inputmode="numeric"
                    autocomplete="one-time-code"
                    required
                    autofocus
                    size="30"
                    placeholder="123 456"
                />
            </p>

            <?php if (!empty($_POST['redirect_to'])): ?>
                <input type="hidden" name="redirect_to" value="<?php echo esc_attr($_POST['redirect_to']); ?>" />
            <?php endif; ?>

            <p class="submit">
                <input
                    type="submit"
                    name="wp-submit"
                    id="wp-submit"
                    class="button button-primary button-large"
                    value="<?php esc_attr_e('Verify', 'dpxl-shield'); ?>"
                />
            </p>

            <p>
                <small>
                    <?php
                    printf(
                        /* translators: %d = number of remaining codes */
                        esc_html__('Backup codes remaining: %d', 'dpxl-shield'),
                        BackupCodes::remainingCount($user->ID)
                    );
                    ?>
                </small>
            </p>
        </form>
        <?php
        login_footer();
        exit;
    }

    // ── Profile Section ────────────────────────────────────────────────────

    public function renderProfileSection(\WP_User $user): void {
        if (!current_user_can('edit_user', $user->ID)) {
            return;
        }

        $enabled = (bool) get_user_meta($user->ID, self::ENABLED_META, true);
        ?>
        <h2><?php esc_html_e('Two-Factor Authentication (DPXL Shield)', 'dpxl-shield'); ?></h2>
        <table class="form-table" role="presentation">
            <tr>
                <th>
                    <label><?php esc_html_e('Authenticator App', 'dpxl-shield'); ?></label>
                </th>
                <td>
                    <?php if ($enabled): ?>
                        <strong style="color:#00a32a">
                            <?php esc_html_e('2FA is ACTIVE for this account.', 'dpxl-shield'); ?>
                        </strong>
                        <br>
                        <a href="<?php echo esc_url(admin_url('profile.php?dpxl_2fa_setup=1')); ?>">
                            <?php esc_html_e('Reconfigure / Regenerate backup codes', 'dpxl-shield'); ?>
                        </a>
                        &nbsp;|&nbsp;
                        <input
                            type="hidden"
                            name="dpxl_2fa_action"
                            value=""
                        />
                        <button type="button" name="dpxl_2fa_action" value="disable"
                            onclick="document.querySelector('[name=dpxl_2fa_action]').value='disable';
                                     document.getElementById('your-profile').submit();"
                            class="button button-secondary">
                            <?php esc_html_e('Deactivate 2FA', 'dpxl-shield'); ?>
                        </button>
                    <?php else: ?>
                        <strong style="color:#d63638">
                            <?php esc_html_e('2FA is not active.', 'dpxl-shield'); ?>
                        </strong>
                        <br>
                        <a href="<?php echo esc_url(admin_url('profile.php?dpxl_2fa_setup=1')); ?>"
                           class="button button-primary">
                            <?php esc_html_e('Set Up Two-Factor Authentication', 'dpxl-shield'); ?>
                        </a>
                    <?php endif; ?>
                </td>
            </tr>
        </table>
        <?php
    }

    public function handleProfileSave(int $userId): void {
        if (!isset($_POST['dpxl_2fa_action'])) {
            return;
        }

        $action = sanitize_key($_POST['dpxl_2fa_action']);

        if ($action === 'disable' && current_user_can('edit_user', $userId)) {
            $this->disable($userId);
        }
    }

    // ── Setup API ──────────────────────────────────────────────────────────

    /**
     * Generates a new TOTP secret for a user.
     * Returns the TOTP instance — caller is responsible for showing QR code.
     */
    public function generateSecret(\WP_User $user): TOTP {
        $totp = TOTP::generate();
        $totp->setLabel($user->user_login);
        $totp->setIssuer(get_bloginfo('name') . ' (DPXL Shield)');

        // Store provisionally — only committed when the user verifies the code.
        update_user_meta($user->ID, self::SECRET_META . '_pending', $totp->getSecret());

        return $totp;
    }

    /**
     * Verifies the first-time code and enables 2FA if correct.
     * Returns plain-text backup codes on success, empty array on failure.
     *
     * @return string[]
     */
    public function activate(int $userId, string $code): array {
        $pendingSecret = get_user_meta($userId, self::SECRET_META . '_pending', true);

        if (empty($pendingSecret)) {
            return [];
        }

        $totp = TOTP::createFromSecret($pendingSecret);

        if (!$totp->verify(preg_replace('/\s+/', '', $code), null, self::TOTP_WINDOW)) {
            return [];
        }

        // Commit the secret and mark 2FA as enabled.
        update_user_meta($userId, self::SECRET_META, $pendingSecret);
        update_user_meta($userId, self::ENABLED_META, true);
        delete_user_meta($userId, self::SECRET_META . '_pending');

        $backupCodes = BackupCodes::generate($userId);

        do_action('dpxl_shield_alert', [
            'level'       => 'info',
            'event_type'  => '2fa_activated',
            'description' => "Two-factor authentication activated for user ID {$userId}.",
        ]);

        return $backupCodes;
    }

    public function disable(int $userId): void {
        delete_user_meta($userId, self::SECRET_META);
        delete_user_meta($userId, self::ENABLED_META);
        delete_user_meta($userId, self::SECRET_META . '_pending');
        BackupCodes::delete($userId);

        do_action('dpxl_shield_alert', [
            'level'       => 'high',
            'event_type'  => '2fa_deactivated',
            'description' => "Two-factor authentication deactivated for user ID {$userId}.",
        ]);
    }

    // ── Verification ───────────────────────────────────────────────────────

    public function verifyCode(int $userId, string $code): bool {
        $secret = get_user_meta($userId, self::SECRET_META, true);

        if (empty($secret)) {
            return false;
        }

        $code = preg_replace('/\s+/', '', $code);

        if (!ctype_digit($code) || strlen($code) !== 6) {
            return false;
        }

        $totp = TOTP::createFromSecret($secret);

        return $totp->verify($code, null, self::TOTP_WINDOW);
    }

    // ── Status Checks ──────────────────────────────────────────────────────

    public function isEnabled(int $userId): bool {
        return (bool) get_user_meta($userId, self::ENABLED_META, true);
    }

    /**
     * Returns true if 2FA is required for this user based on role configuration.
     */
    public function isRequired(\WP_User $user): bool {
        if ($this->isEnabled($user->ID)) {
            return true;
        }

        $requiredRoles = (array) Options::get('two_factor_required_roles', ['administrator']);

        foreach ($requiredRoles as $role) {
            if (in_array($role, (array) $user->roles, true)) {
                return true;
            }
        }

        return false;
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private function currentIp(): string {
        $headers = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'];

        foreach ($headers as $h) {
            $value = $_SERVER[$h] ?? '';
            $ip    = trim(explode(',', $value)[0]);

            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }

        return '0.0.0.0';
    }
}
