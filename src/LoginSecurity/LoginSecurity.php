<?php
declare(strict_types=1);

namespace DPXL\Shield\LoginSecurity;

use DPXL\Shield\Core\Options;

/**
 * LoginSecurity module entry point.
 * Instantiates sub-modules and registers all hooks.
 */
class LoginSecurity {

    private BruteForceProtection $bruteForce;
    private TwoFactorAuth        $twoFactor;
    private LoginAudit           $audit;

    public function __construct() {
        $this->audit      = new LoginAudit();
        $this->bruteForce = new BruteForceProtection($this->audit);
        $this->twoFactor  = new TwoFactorAuth($this->audit);
    }

    public function registerHooks(): void {
        if (Options::get('brute_force_enabled', true)) {
            $this->bruteForce->registerHooks();
        }

        $this->twoFactor->registerHooks();
        $this->audit->registerHooks();

        // Generic login hardening options.
        if (Options::get('login_hide_errors', true)) {
            add_filter('login_errors', [$this, 'genericLoginError']);
        }

        if (Options::get('xmlrpc_disabled', false)) {
            add_filter('xmlrpc_enabled', '__return_false');
        }

        // 2FA intercept: if WP_Error reason is dpxl_2fa_required, redirect to 2FA page
        // instead of showing the standard "incorrect password" message.
        add_filter('login_redirect', [$this, 'maybe2faRedirect'], 10, 3);
    }

    /**
     * After a `dpxl_2fa_required` WP_Error, redirect to the 2FA entry page.
     */
    public function maybe2faRedirect(string $redirect, string $requestedRedirect, \WP_User|\WP_Error $user): string {
        if (!is_wp_error($user) || !$user->has_errors() || !array_key_exists('dpxl_2fa_required', $user->errors)) {
            return $redirect;
        }

        return wp_login_url() . '?action=dpxl_2fa'
            . ($requestedRedirect !== '' ? '&redirect_to=' . rawurlencode($requestedRedirect) : '');
    }

    public function genericLoginError(): string {
        return esc_html__('The username or password you entered is incorrect.', 'dpxl-shield');
    }

    // ── Accessors (for REST API / admin UI) ────────────────────────────────

    public function getBruteForce(): BruteForceProtection {
        return $this->bruteForce;
    }

    public function getTwoFactorAuth(): TwoFactorAuth {
        return $this->twoFactor;
    }

    public function getAudit(): LoginAudit {
        return $this->audit;
    }
}
