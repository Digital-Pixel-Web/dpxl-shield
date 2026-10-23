<?php
declare(strict_types=1);

namespace DPXL\Shield\Alerts;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

/**
 * Shared HTML shell for every email DPXL Shield sends.
 *
 * Table-based layout, inline styles, no external images or webfonts — the
 * lowest common denominator that still renders in Outlook, Gmail and Apple
 * Mail. Callers supply the inner content; the header, severity rule and
 * footer stay identical across alerts and reports so the emails read as one
 * product.
 */
class EmailTemplate {

    /**
     * Full document. `$content` is dropped into a single padded cell — the
     * caller manages its own inner spacing.
     */
    public static function render(
        string $title,
        string $accent,
        string $content,
        string $footerNote = ''
    ): string {
        $siteUrl     = (string) get_option('siteurl');
        $settingsUrl = $siteUrl . '/wp-admin/admin.php?page=dpxl-shield';
        $host        = esc_html(self::siteHost());
        $safeTitle   = esc_html($title);

        $footerNote = $footerNote !== ''
            ? '<br><span style="color:#a7aaad;">' . $footerNote . '</span>'
            : '';

        // The footer is part of the shared shell, so it must localise like the
        // rest of the email. Routed through __() (not baked into the heredoc)
        // so the ReportI18n filter reaches it in cron, where the admin-only
        // gettext filter never runs.
        $link = 'style="color:#2271b1;text-decoration:none;"';

        $sentBy = sprintf(
            /* translators: 1: product name, 2: site host (linked). */
            __('Sent by %1$s on %2$s.', 'dpxl-shield'),
            '<strong style="color:#50575e;">DPXL Shield</strong>',
            '<a href="' . esc_url($siteUrl) . '" ' . $link . '>' . $host . '</a>'
        );

        $manage = sprintf(
            /* translators: %s: link to the plugin settings screen. */
            __('Manage what triggers an email in %s.', 'dpxl-shield'),
            '<a href="' . esc_url($settingsUrl) . '" ' . $link . '>'
                . esc_html__('DPXL Shield settings', 'dpxl-shield') . '</a>'
        );

        return <<<HTML
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <meta name="color-scheme" content="light">
          <title>{$safeTitle}</title>
        </head>
        <body style="margin:0;padding:0;background:#f0f0f1;-webkit-font-smoothing:antialiased;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f0f0f1;">
            <tr>
              <td align="center" style="padding:32px 16px;">
                <table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:600px;background:#ffffff;border:1px solid #dcdcde;border-radius:10px;overflow:hidden;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">

                  <tr>
                    <td style="background:#1d2327;padding:18px 28px;">
                      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                        <tr>
                          <td style="font-size:14px;font-weight:700;letter-spacing:.16em;color:#ffffff;">DPXL <span style="color:#8c9196;font-weight:400;">SHIELD</span></td>
                          <td align="right" style="font-size:12px;color:#8c9196;">{$host}</td>
                        </tr>
                      </table>
                    </td>
                  </tr>

                  <tr><td style="height:3px;line-height:3px;font-size:0;background:{$accent};">&nbsp;</td></tr>

                  <tr><td style="padding:28px;">{$content}</td></tr>

                  <tr>
                    <td style="padding:18px 28px;background:#f6f7f7;border-top:1px solid #f0f0f1;font-size:12px;line-height:1.7;color:#787c82;">
                      {$sentBy}
                      <br>{$manage}{$footerNote}
                    </td>
                  </tr>

                </table>
              </td>
            </tr>
          </table>
        </body>
        </html>
        HTML;
    }

    /** Bulletproof-ish CTA button. */
    public static function button(string $url, string $label): string {
        $url   = esc_url($url);
        $label = esc_html($label);

        return '<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin-top:24px;">'
            . '<tr><td style="background:#2271b1;border-radius:6px;">'
            . '<a href="' . $url . '" style="display:inline-block;padding:11px 22px;color:#ffffff;font-size:14px;font-weight:600;text-decoration:none;">' . $label . '</a>'
            . '</td></tr></table>';
    }

    /** Small uppercase severity chip. */
    public static function pill(string $label, string $accent, string $tint): string {
        return '<span style="display:inline-block;padding:4px 11px;border-radius:999px;background:' . $tint
            . ';color:' . $accent . ';font-size:11px;font-weight:700;letter-spacing:.09em;text-transform:uppercase;">'
            . esc_html($label) . '</span>';
    }

    /**
     * Key/value table with hairline separators.
     *
     * @param array<string,string> $rows
     */
    public static function detailTable(array $rows): string {
        if ($rows === []) {
            return '';
        }

        $html  = '';
        $first = true;

        foreach ($rows as $label => $value) {
            $border = $first ? '' : 'border-top:1px solid #f0f0f1;';
            $first  = false;

            $html .= '<tr>'
                . '<td style="padding:11px 14px;width:150px;color:#787c82;vertical-align:top;' . $border . '">' . esc_html((string) $label) . '</td>'
                . '<td style="padding:11px 14px;color:#1d2327;word-break:break-word;' . $border . '">' . esc_html($value) . '</td>'
                . '</tr>';
        }

        return '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top:20px;border:1px solid #f0f0f1;border-radius:8px;font-size:14px;">'
            . $html . '</table>';
    }

    /**
     * "Quem / de onde" block: the context that turns a bare address into a
     * fact a human can judge.
     *
     * Each row is ['label' => string, 'value' => string, 'note' => string],
     * where `note` is an optional second line in grey. Rows whose value is
     * empty are dropped by the caller, not hidden here — an empty row would
     * claim the field was checked and found blank.
     *
     * No inline SVG: Outlook strips it and several clients block it outright,
     * so this block is text only. The icon system in §4.5 of the UI spec is
     * for the admin screens.
     *
     * @param list<array{label: string, value: string, note?: string}> $rows
     */
    public static function identityBlock(array $rows): string {
        if ($rows === []) {
            return '';
        }

        $html  = '';
        $first = true;

        foreach ($rows as $row) {
            $border = $first ? '' : 'border-top:1px solid #f0f0f1;';
            $first  = false;

            $note = isset($row['note']) && $row['note'] !== ''
                ? '<br><span style="color:#787c82;font-size:12.5px;">' . esc_html($row['note']) . '</span>'
                : '';

            $html .= '<tr>'
                . '<td style="padding:12px 14px;width:120px;color:#787c82;vertical-align:top;' . $border . '">'
                . esc_html($row['label']) . '</td>'
                . '<td style="padding:12px 14px;color:#1d2327;word-break:break-word;' . $border . '">'
                . esc_html($row['value']) . $note . '</td>'
                . '</tr>';
        }

        return '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top:20px;border:1px solid #f0f0f1;border-radius:8px;font-size:14px;">'
            . $html . '</table>';
    }

    /**
     * The "O que fazer" block: a heading and one imperative line per item.
     *
     * Bullets are drawn in their own cell rather than with a <ul>, because
     * Outlook's list indentation is unpredictable and the block has to line up
     * with the tables above it.
     *
     * @param list<string> $items
     */
    public static function actionList(string $heading, array $items): string {
        if ($items === []) {
            return '';
        }

        $rows = '';

        foreach ($items as $item) {
            $rows .= '<tr>'
                . '<td style="padding:4px 10px 4px 0;color:#787c82;vertical-align:top;line-height:1.6;">&bull;</td>'
                . '<td style="padding:4px 0;font-size:14.5px;line-height:1.6;color:#3c434a;">' . esc_html($item) . '</td>'
                . '</tr>';
        }

        return '<div style="margin-top:22px;">'
            . '<p style="margin:0 0 8px;font-size:12px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:#787c82;">'
            . esc_html($heading) . '</p>'
            . '<table role="presentation" cellpadding="0" cellspacing="0" border="0">' . $rows . '</table>'
            . '</div>';
    }

    /**
     * The raw fields, muted and last.
     *
     * Same data the detail table used to carry at the top of the email. It is
     * still here for whoever needs it, below the part a human reads.
     *
     * @param array<string,string> $rows
     */
    public static function techDetails(string $heading, array $rows): string {
        if ($rows === []) {
            return '';
        }

        $html = '';

        foreach ($rows as $label => $value) {
            $html .= '<tr>'
                . '<td style="padding:7px 14px 7px 0;width:160px;color:#a7aaad;vertical-align:top;">' . esc_html((string) $label) . '</td>'
                . '<td style="padding:7px 0;color:#787c82;word-break:break-word;">' . esc_html($value) . '</td>'
                . '</tr>';
        }

        return '<div style="margin-top:26px;padding-top:18px;border-top:1px solid #f0f0f1;">'
            . '<p style="margin:0 0 6px;font-size:11px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:#a7aaad;">'
            . esc_html($heading) . '</p>'
            . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="font-size:13px;">'
            . $html . '</table></div>';
    }

    /**
     * Tinted callout with a left accent rule — used for "needs attention"
     * lines that should stand out without turning the whole email red.
     */
    public static function callout(string $text, string $accent, string $tint): string {
        return '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top:20px;background:' . $tint
            . ';border-left:3px solid ' . $accent . ';border-radius:4px;">'
            . '<tr><td style="padding:13px 16px;font-size:14px;line-height:1.5;color:#1d2327;">' . esc_html($text) . '</td></tr></table>';
    }

    /**
     * Muted severity palette — the accent is a 3px rule and a pill, never a
     * full-width red banner. A routine notice must not look like a breach.
     *
     * @return array{accent: string, tint: string, label: string}
     */
    public static function palette(string $level): array {
        $palettes = [
            'critical' => ['accent' => '#b32d2e', 'tint' => '#fcf0f0', 'label' => __('Critical', 'dpxl-shield')],
            'high'     => ['accent' => '#bd5b00', 'tint' => '#fcf5ed', 'label' => __('High', 'dpxl-shield')],
            'medium'   => ['accent' => '#9a6700', 'tint' => '#fcf9e8', 'label' => __('Notice', 'dpxl-shield')],
        ];

        return $palettes[$level]
            ?? ['accent' => '#2271b1', 'tint' => '#f0f6fc', 'label' => __('Info', 'dpxl-shield')];
    }

    /** Site host without scheme — shorter and clearer than the full URL. */
    public static function siteHost(): string {
        $host = wp_parse_url((string) get_option('siteurl'), PHP_URL_HOST);

        return is_string($host) && $host !== '' ? $host : (string) get_option('siteurl');
    }

    /** Timestamp in the site's own timezone, using the site's date format. */
    public static function localTime(?int $timestamp = null, bool $withTime = true): string {
        $format = (string) get_option('date_format', 'Y-m-d');

        if ($withTime) {
            $format = trim($format . ' ' . (string) get_option('time_format', 'H:i'));
        }

        if (function_exists('wp_date')) {
            $formatted = wp_date($format, $timestamp);

            if (is_string($formatted)) {
                return $formatted;
            }
        }

        return gmdate($withTime ? 'Y-m-d H:i' : 'Y-m-d', $timestamp ?? time()) . ($withTime ? ' UTC' : '');
    }
}
