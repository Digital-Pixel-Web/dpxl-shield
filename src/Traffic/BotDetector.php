<?php
declare(strict_types=1);

namespace DPXL\Shield\Traffic;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

/**
 * Enhanced bot detection: user-agent fingerprint + behavioural signals.
 *
 * Combines:
 *  - TrafficClassifier::isBot() for UA matching
 *  - Missing/unusual Accept headers
 *  - No cookie support across requests (tracked via APCu)
 *  - Request speed anomalies (handled by AnomalyDetector)
 *
 * Used by the scan orchestrator to flag scan results and by TrafficLogger.
 */
class BotDetector {

    private TrafficClassifier $classifier;

    public function __construct() {
        $this->classifier = new TrafficClassifier();
    }

    /**
     * @return array{is_bot: bool, confidence: int, signals: string[]}
     */
    public function analyse(string $userAgent, string $ip): array {
        $signals    = [];
        $confidence = 0;

        // UA-based detection.
        if ($this->classifier->isBot($userAgent, $ip)) {
            $signals[]   = 'known_bot_ua';
            $confidence += 80;
        }

        // Missing UA.
        if (empty($userAgent)) {
            $signals[]   = 'missing_ua';
            $confidence += 60;
        }

        // No Accept header (most browsers send it).
        $accept = $_SERVER['HTTP_ACCEPT'] ?? '';

        if (empty($accept)) {
            $signals[]   = 'no_accept_header';
            $confidence += 20;
        }

        // No Accept-Language header.
        $lang = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';

        if (empty($lang)) {
            $signals[]   = 'no_accept_language';
            $confidence += 15;
        }

        // Non-standard HTTP method.
        $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

        if (!in_array($method, ['GET', 'POST', 'HEAD'], true)) {
            $signals[]   = 'unusual_method';
            $confidence += 10;
        }

        // Cookie absence on repeat visits (APCu only).
        if (function_exists('apcu_fetch') && !isset($_COOKIE)) {
            $key = 'dpxl_visited_' . md5($ip);

            if (apcu_fetch($key)) {
                $signals[]   = 'no_cookies_on_repeat';
                $confidence += 25;
            }

            apcu_store($key, 1, 3600);
        }

        $confidence = min(100, $confidence);
        $isBot      = $confidence >= 60;

        return ['is_bot' => $isBot, 'confidence' => $confidence, 'signals' => $signals];
    }
}
