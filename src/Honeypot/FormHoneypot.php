<?php
declare(strict_types=1);

namespace DPXL\Shield\Honeypot;

use DPXL\Shield\Firewall\IpBlocklist;

/**
 * Injects a CSS-hidden field into WordPress forms.
 *
 * Real users never see or fill this field (it's visually hidden via CSS
 * and has tabindex="-1"). Bots that auto-fill forms will populate it,
 * triggering an immediate IP block.
 *
 * Covered forms: login, registration, comments.
 */
class FormHoneypot {

    private const FIELD_NAME = 'dpxl_website_url';   // Looks like a natural "website" field to bots
    private const CSS_CLASS  = 'dpxl-ohnohoney';

    public function registerHooks(): void {
        // Inject field
        add_action('login_form', [$this, 'renderField']);
        add_action('register_form', [$this, 'renderField']);
        add_action('comment_form_before', [$this, 'renderField']);

        // Inject hide CSS (login page has its own head, front-end uses wp_head)
        add_action('login_head', [$this, 'renderCss']);
        add_action('wp_head', [$this, 'renderCss']);

        // Validate on submission — priority 5 runs before BruteForceProtection
        add_filter('authenticate', [$this, 'checkLogin'], 5, 3);
        add_filter('preprocess_comment', [$this, 'checkComment']);
        add_filter('registration_errors', [$this, 'checkRegistration'], 5, 3);
    }

    // ── Rendering ──────────────────────────────────────────────────────────

    public function renderField(): void {
        ?>
        <div class="<?php echo esc_attr(self::CSS_CLASS); ?>" aria-hidden="true">
            <label for="<?php echo esc_attr(self::FIELD_NAME); ?>">Website</label>
            <input
                type="text"
                id="<?php echo esc_attr(self::FIELD_NAME); ?>"
                name="<?php echo esc_attr(self::FIELD_NAME); ?>"
                value=""
                autocomplete="nope"
                tabindex="-1"
            />
        </div>
        <?php
    }

    public function renderCss(): void {
        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        printf(
            '<style>.%s{position:absolute!important;left:-9999px!important;width:0!important;height:0!important;overflow:hidden!important;}</style>' . "\n",
            esc_attr(self::CSS_CLASS)
        );
    }

    // ── Validation ─────────────────────────────────────────────────────────

    public function checkLogin(mixed $user, string $username, string $password): mixed {
        if ($this->isFilled()) {
            $this->blockBotIp('login form honeypot');
            return new \WP_Error('honeypot', __('An error occurred. Please try again.', 'dpxl-shield'));
        }

        return $user;
    }

    public function checkComment(array $commentData): array {
        if ($this->isFilled()) {
            $this->blockBotIp('comment form honeypot');
            wp_die(
                esc_html__('An error occurred submitting your comment.', 'dpxl-shield'),
                '',
                ['response' => 403]
            );
        }

        return $commentData;
    }

    public function checkRegistration(\WP_Error $errors, string $login, string $email): \WP_Error {
        if ($this->isFilled()) {
            $this->blockBotIp('registration form honeypot');
            $errors->add('honeypot', __('Registration could not be completed.', 'dpxl-shield'));
        }

        return $errors;
    }

    // ── Internal ───────────────────────────────────────────────────────────

    private function isFilled(): bool {
        // The field must exist in POST AND be non-empty to trigger.
        return isset($_POST[self::FIELD_NAME]) && $_POST[self::FIELD_NAME] !== '';
    }

    private function blockBotIp(string $context): void {
        $ip  = $this->resolveIp();
        $uri = $_SERVER['REQUEST_URI'] ?? '';

        IpBlocklist::blockIp($ip, "Bot detected via {$context}", 'auto_honeypot', HOUR_IN_SECONDS);

        do_action('dpxl_shield_alert', [
            'level'       => 'high',
            'event_type'  => 'honeypot_triggered',
            'description' => "Bot detected via form honeypot from {$ip} ({$context}): {$uri}",
            'context'     => ['ip' => $ip, 'uri' => $uri, 'context' => $context],
        ]);
    }

    private function resolveIp(): string {
        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $h) {
            $ip = trim(explode(',', $_SERVER[$h] ?? '')[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }

        return '0.0.0.0';
    }
}
