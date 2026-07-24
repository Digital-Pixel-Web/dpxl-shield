<?php
declare(strict_types=1);

namespace DPXL\Shield\Scanner;

use DPXL\Shield\Core\Logger;

/**
 * Fetches official MD5 checksums for the current WordPress core from api.wordpress.org.
 * WP.org returns MD5 (not SHA-256) — we use these for change detection, not storage.
 */
class WpOrgChecksumApi {

    private const API_BASE    = 'https://api.wordpress.org/core/checksums/1.0/';
    private const CACHE_TTL   = DAY_IN_SECONDS;

    /** @return array<string, string>  relative_path => md5_hash */
    public function getCoreChecksums(): array {
        global $wp_version;

        // Version-scoped cache key: a WordPress core update naturally busts the
        // cache instead of comparing against a stale manifest for a full day.
        $transient = self::cacheKey($wp_version);
        $cached    = get_transient($transient);

        if (is_array($cached) && !empty($cached)) {
            return $cached;
        }

        // Always compare against the en_US manifest. Core integrity is
        // locale-independent: WordPress ships localization as separate language
        // packs (.mo files), not as modified core files. A localized install
        // (e.g. pt_BR) that received automatic updates has en_US core files on
        // disk, so querying with get_locale() makes dozens of untouched core
        // files look "modified" — the classic mass false positive.
        $url = add_query_arg([
            'version' => $wp_version,
            'locale'  => 'en_US',
        ], self::API_BASE);

        $response = wp_remote_get($url, [
            'timeout'    => 30,
            'user-agent' => 'DPXL-Shield/' . DPXL_SHIELD_VERSION . '; ' . get_bloginfo('url'),
        ]);

        if (is_wp_error($response)) {
            Logger::error('WP.org checksum API error: ' . $response->get_error_message());
            return [];
        }

        $code = wp_remote_retrieve_response_code($response);

        if ($code !== 200) {
            Logger::error("WP.org checksum API returned HTTP {$code}");
            return [];
        }

        $data = json_decode(wp_remote_retrieve_body($response), true);

        if (empty($data['checksums']) || !is_array($data['checksums'])) {
            Logger::error('WP.org checksum API returned unexpected payload.');
            return [];
        }

        $checksums = $data['checksums'];

        set_transient($transient, $checksums, self::CACHE_TTL);

        return $checksums;
    }

    public static function invalidateCache(): void {
        global $wp_version;
        delete_transient(self::cacheKey($wp_version));
    }

    private static function cacheKey(string $version): string {
        return 'dpxl_shield_wp_core_checksums_' . md5($version . '|en_US');
    }
}
