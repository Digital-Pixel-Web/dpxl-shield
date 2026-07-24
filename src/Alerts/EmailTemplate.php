<?php
declare(strict_types=1);

namespace DPXL\Shield\Alerts;

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
                      Sent by <strong style="color:#50575e;">DPXL Shield</strong> on <a href="{$siteUrl}" style="color:#2271b1;text-decoration:none;">{$host}</a>.
                      <br>Manage what triggers an email in <a href="{$settingsUrl}" style="color:#2271b1;text-decoration:none;">DPXL Shield settings</a>.{$footerNote}
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
        return match ($level) {
            'critical' => ['accent' => '#b32d2e', 'tint' => '#fcf0f0', 'label' => __('Critical', 'dpxl-shield')],
            'high'     => ['accent' => '#bd5b00', 'tint' => '#fcf5ed', 'label' => __('High', 'dpxl-shield')],
            'medium'   => ['accent' => '#9a6700', 'tint' => '#fcf9e8', 'label' => __('Notice', 'dpxl-shield')],
            default    => ['accent' => '#2271b1', 'tint' => '#f0f6fc', 'label' => __('Info', 'dpxl-shield')],
        };
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
