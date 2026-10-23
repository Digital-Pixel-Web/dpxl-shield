<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

use DPXL\Shield\Firewall\Rules\RuleEngine;

/**
 * Central firewall orchestrator.
 *
 * Pipeline:
 *   1. Whitelist check       → PASS immediately (trusted IPs / URLs)
 *   2. IP Blocklist check    → BLOCK immediately (no rule evaluation)
 *   3. Country Blocker       → BLOCK if geo-blocked country
 *   4. Rate Limiter check    → BLOCK if threshold exceeded
 *   5. Custom Pattern Blocker→ BLOCK / LOG_ONLY on admin-defined patterns
 *   6. Rule Engine           → evaluate WAF rules by priority
 *   7. PASS
 */
class FirewallEngine {

    private RuleEngine $ruleEngine;

    /** @var string[] Trusted IPs that bypass all checks */
    private array $trustedIps = [];

    /** @var string[] URI patterns that bypass WAF (regex or exact) */
    private array $allowlistedUris = [];

    /** @var string */
    private $configFile;

    /** @var string */
    private $blockedIpsFile;

    public function __construct(
        string $configFile,
        string $blockedIpsFile
    ) {
        $this->configFile     = $configFile;
        $this->blockedIpsFile = $blockedIpsFile;

        $this->ruleEngine = new RuleEngine();
        $this->loadConfig();
    }

    public function evaluate(Request $request): RuleResult {
        // 1. Whitelist
        if ($this->isTrustedIp($request->ip)) {
            return RuleResult::pass();
        }

        if ($this->isAllowlistedUri($request->uri)) {
            return RuleResult::pass();
        }

        // 2. IP Blocklist
        if (IpBlocklist::isBlocked($request->ip)) {
            return RuleResult::block('ip-blocklist', 'IP is in the blocklist', 'high');
        }

        // 3. Country Blocker (only when WordPress is loaded)
        if (function_exists('get_option')) {
            $countryResult = CountryBlocker::check($request->ip);

            if ($countryResult->decision === Decision::BLOCK) {
                return $countryResult;
            }
        }

        // 4. Rate Limiter
        if (RateLimiter::isExceeded($request->ip, $request->uri)) {
            // Auto-add to blocklist for 10 minutes on rate limit hit.
            IpBlocklist::blockIp($request->ip, 'Rate limit exceeded', 'auto_rate', 600);

            return RuleResult::block('rate-limit', 'Rate limit exceeded', 'medium');
        }

        // 5. Custom Pattern Blocker (only when WordPress is loaded)
        if (function_exists('get_option')) {
            $patternResult = CustomPatternBlocker::check($request);

            if ($patternResult->decision !== Decision::PASS) {
                return $patternResult;
            }
        }

        // 6. Rule Engine
        $result = $this->ruleEngine->evaluate($request);

        if ($result->decision === Decision::BLOCK) {
            // Never auto-add admin IPs to the blocklist.
            //
            // Two contexts:
            // A) Extended Protection (pre-WordPress, auto_prepend_file):
            //    current_user_can() doesn't exist yet. Admin requests are already
            //    bypassed in Loader::handleEarlyRequest() via URI check, so any
            //    request reaching here is not from /wp-admin. IpBlocklist::blockIp()
            //    has its own $wpdb null-guard as a safety net.
            //
            // B) Basic WAF (inside WordPress, plugins_loaded):
            //    current_user_can() is available. Use it to protect admins whose
            //    cookie session is active (e.g. REST / admin-ajax calls not bypassed
            //    by the cookie check).
            $isAdmin = function_exists('current_user_can') && current_user_can('manage_options');

            if (!$isAdmin) {
                IpBlocklist::blockIp($request->ip, $result->reason, 'auto_waf', 3600);
            }
        }

        return $result;
    }

    /**
     * The checks that need WordPress (database blocklist, country blocking,
     * custom patterns), for a request whose rules and rate limits the
     * pre-WordPress layer already evaluated. Running the full pipeline twice
     * would count every request twice against the rate limits.
     */
    public function evaluateDatabaseChecks(Request $request): RuleResult {
        if ($this->isTrustedIp($request->ip) || $this->isAllowlistedUri($request->uri)) {
            return RuleResult::pass();
        }

        if (IpBlocklist::isBlocked($request->ip)) {
            return RuleResult::block('ip-blocklist', 'IP is in the blocklist', 'high');
        }

        $countryResult = CountryBlocker::check($request->ip);

        if ($countryResult->decision === Decision::BLOCK) {
            return $countryResult;
        }

        $patternResult = CustomPatternBlocker::check($request);

        if ($patternResult->decision !== Decision::PASS) {
            return $patternResult;
        }

        return RuleResult::pass();
    }

    private function isTrustedIp(string $ip): bool {
        if (in_array($ip, $this->trustedIps, true)) {
            return true;
        }

        // Always trust the server's own loopback.
        return in_array($ip, ['127.0.0.1', '::1'], true);
    }

    private function isAllowlistedUri(string $uri): bool {
        // Early-config flat-file patterns.
        foreach ($this->allowlistedUris as $pattern) {
            if (str_starts_with($pattern, '/') && str_ends_with($pattern, '/')) {
                if (@preg_match($pattern, $uri) === 1) {
                    return true;
                }
            } elseif ($uri === $pattern || str_starts_with($uri, $pattern)) {
                return true;
            }
        }

        // DB-backed patterns (available once WordPress is loaded).
        if (function_exists('get_option') && AllowlistManager::isAllowlisted($uri)) {
            return true;
        }

        return false;
    }

    private function loadConfig(): void {
        if (!file_exists($this->configFile)) {
            return;
        }

        $config = @include $this->configFile;

        if (!is_array($config)) {
            return;
        }

        if (!empty($config['trusted_ips']) && is_array($config['trusted_ips'])) {
            $this->trustedIps = $config['trusted_ips'];
        }

        if (!empty($config['allowlisted_uris']) && is_array($config['allowlisted_uris'])) {
            $this->allowlistedUris = $config['allowlisted_uris'];
        }

        if (!empty($config['rate_limits']) && is_array($config['rate_limits'])) {
            foreach ($config['rate_limits'] as $endpoint => $limit) {
                RateLimiter::updateLimit((string) $endpoint, (int) $limit);
            }
        }
    }

    public function getRuleEngine(): RuleEngine {
        return $this->ruleEngine;
    }
}
