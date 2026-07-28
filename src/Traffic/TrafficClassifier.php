<?php
declare(strict_types=1);

namespace DPXL\Shield\Traffic;

/**
 * Classifies a request as human / bot / blocked / suspicious.
 *
 * Used by TrafficLogger to set is_bot and by the admin UI to colour-code rows.
 *
 * Traffic types:
 *   human     — real browser, normal behaviour
 *   bot       — known crawler user-agent (Googlebot, Bingbot, etc.)
 *   blocked   — WAF action = block
 *   suspicious— flagged but not blocked (rate anomaly, unusual pattern, no UA)
 *   unknown   — insufficient signal to classify
 */
class TrafficClassifier {

    public function classify(
        string $wafAction,
        string $userAgent,
        string $ip,
        int    $statusCode
    ): string {
        if ($wafAction === 'block') {
            return 'blocked';
        }

        if ($this->isKnownBot($userAgent)) {
            return 'bot';
        }

        // An absent User-Agent is anomalous, not a known crawler: every browser
        // and every well-behaved bot identifies itself. Attack tooling is what
        // omits it, so it belongs with the flagged traffic — not filed away
        // next to Googlebot.
        if (trim($userAgent) === '') {
            return 'suspicious';
        }

        if ($wafAction === 'log_only' || $statusCode === 403) {
            return 'suspicious';
        }

        if ($this->looksHuman($userAgent)) {
            return 'human';
        }

        return 'unknown';
    }

    public function isBot(string $userAgent, string $ip = ''): bool {
        return $this->isKnownBot($userAgent) || $this->isHeadlessBrowser($userAgent);
    }

    // ── Internal ───────────────────────────────────────────────────────────

    private function isKnownBot(string $ua): bool {
        $botSignatures = [
            'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider',
            'yandexbot', 'sogou', 'exabot', 'facebot', 'ia_archiver',
            'msnbot', 'ahrefsbot', 'semrushbot', 'dotbot', 'petalbot',
            'rogerbot', 'linkedinbot', 'twitterbot', 'facebookexternalhit',
            'applebot', 'gptbot', 'ccbot', 'claudebot', 'bytespider',
            'wget', 'curl/', 'libwww', 'python-requests', 'go-http-client',
            'java/', 'okhttp', 'scrapy', 'httpclient',
        ];

        $lower = strtolower($ua);

        foreach ($botSignatures as $sig) {
            if (str_contains($lower, $sig)) {
                return true;
            }
        }

        return false;
    }

    private function isHeadlessBrowser(string $ua): bool {
        $headless = ['headlesschrome', 'phantomjs', 'selenium', 'webdriver', 'puppeteer'];
        $lower    = strtolower($ua);

        foreach ($headless as $sig) {
            if (str_contains($lower, $sig)) {
                return true;
            }
        }

        return false;
    }

    private function looksHuman(string $ua): bool {
        $browsers = ['mozilla/5.0', 'chrome/', 'firefox/', 'safari/', 'edge/', 'opera/'];
        $lower    = strtolower($ua);

        foreach ($browsers as $sig) {
            if (str_contains($lower, $sig)) {
                return true;
            }
        }

        return false;
    }
}
