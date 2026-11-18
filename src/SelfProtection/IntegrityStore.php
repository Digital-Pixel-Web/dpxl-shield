<?php
declare(strict_types=1);

namespace DPXL\Shield\SelfProtection;

use DPXL\Shield\Core\EarlyConfig;
use DPXL\Shield\Core\Fs;
use DPXL\Shield\Core\Logger;

/**
 * Redundant integrity store — writes to and reads from 3 independent locations.
 *
 * Locations:
 *   1. wp_options  (dpxl_shield_integrity_store, AES-256-CBC encrypted value)
 *   2. the data folder: uploads/dpxl-shield/integrity.dat (outside the plugin)
 *   3. the system temp folder: dpxl-shield-{site_hash}.integrity
 *
 * Reading uses majority vote (2/3). An attacker who modifies the plugin
 * directory cannot forge the result without also compromising the database
 * and the temp directory.
 *
 * Before 1.12.1 the copies lived under unprefixed names (the option
 * `_site_check_timeout_shwp`, `wp-content/.shieldwp-integrity`). They are
 * deleted on the next save and by uninstall.
 */
class IntegrityStore {

    private const OPTION_KEY     = 'dpxl_shield_integrity_store';
    private const ENC_KEY_OPT    = 'dpxl_shield_integrity_key';
    private const INTEGRITY_FILE = 'integrity.dat';

    /** Names used before 1.12.1. @var array{option:string,key:string,file:string} */
    public const LEGACY = [
        'option' => '_site_check_timeout_shwp',
        'key'    => '_site_check_enc_key',
        'file'   => '.shieldwp-integrity',
    ];

    // ── Write ──────────────────────────────────────────────────────────────

    /** @param array<string,string> $checksums  relative_path => sha256 */
    public function save(array $checksums): void {
        $payload = $this->encrypt($checksums);

        $this->saveToOptions($payload);
        $this->saveToContentFile($payload);
        $this->saveToTempFile($payload);

        self::deleteLegacy();
    }

    /** Removes the copies written under the pre-1.12.1 names. */
    public static function deleteLegacy(): void {
        delete_option(self::LEGACY['option']);
        delete_option(self::LEGACY['key']);

        if (defined('WP_CONTENT_DIR') && is_file(WP_CONTENT_DIR . '/' . self::LEGACY['file'])) {
            Fs::delete(WP_CONTENT_DIR . '/' . self::LEGACY['file']);
        }

        $oldTemp = sys_get_temp_dir() . '/shwp-' . md5(ABSPATH) . '.lock';
        if (is_file($oldTemp)) {
            Fs::delete($oldTemp);
        }
    }

    // ── Read (majority vote) ───────────────────────────────────────────────

    /** @return array<string,string>|null */
    public function load(): ?array {
        $candidates = array_filter([
            $this->loadFromOptions(),
            $this->loadFromContentFile(),
            $this->loadFromTempFile(),
        ]);

        if (empty($candidates)) {
            return null;
        }

        // All agree — fast path. Compared as JSON: the candidates are plain
        // arrays of strings, decoded from JSON in the first place.
        $encoded = array_map(static function (array $candidate): string {
            return (string) wp_json_encode($candidate);
        }, $candidates);

        if (count(array_unique($encoded)) === 1) {
            return reset($candidates);
        }

        // Majority vote — 2/3 agreement required.
        $counts  = array_count_values($encoded);
        arsort($counts);
        $winner  = (string) array_key_first($counts);
        $topCount = $counts[$winner];

        if ($topCount >= 2) {
            Logger::error('IntegrityStore: mismatch between storage locations — possible tampering.');
            $decoded = json_decode($winner, true);
            return is_array($decoded) ? $decoded : null;
        }

        // All 3 differ — cannot determine truth.
        Logger::error('IntegrityStore: all 3 locations disagree — critical integrity failure.');

        do_action('dpxl_shield_alert', [
            'level'       => 'critical',
            'event_type'  => 'integrity_store_conflict',
            'description' => 'DPXL Shield integrity stores all disagree — possible advanced tampering.',
        ]);

        return null;
    }

    // ── Storage backends ───────────────────────────────────────────────────

    private function saveToOptions(string $payload): void {
        update_option(self::OPTION_KEY, $payload, false);
    }

    private function loadFromOptions(): ?array {
        $raw = get_option(self::OPTION_KEY, null);
        return $raw !== null ? $this->decrypt((string) $raw) : null;
    }

    private function saveToContentFile(string $payload): void {
        if (!EarlyConfig::ensureDataDir()) {
            return;
        }

        @file_put_contents(self::contentFilePath(), $payload);
    }

    public static function contentFilePath(): string {
        return EarlyConfig::dataDir() . '/' . self::INTEGRITY_FILE;
    }

    private function loadFromContentFile(): ?array {
        $path = self::contentFilePath();

        if (!file_exists($path)) {
            return null;
        }

        $raw = @file_get_contents($path);
        return $raw !== false ? $this->decrypt($raw) : null;
    }

    private function saveToTempFile(string $payload): void {
        @file_put_contents(self::tempFilePath(), $payload);
    }

    private function loadFromTempFile(): ?array {
        $path = self::tempFilePath();

        if (!file_exists($path)) {
            return null;
        }

        $raw = @file_get_contents($path);
        return $raw !== false ? $this->decrypt($raw) : null;
    }

    public static function tempFilePath(): string {
        return get_temp_dir() . 'dpxl-shield-' . md5(ABSPATH) . '.integrity';
    }

    // ── Encryption (AES-256-CBC) ───────────────────────────────────────────

    private function encrypt(array $data): string {
        $json = (string) json_encode($data);
        $key  = $this->encryptionKey();
        $iv   = random_bytes(16);

        $cipher = openssl_encrypt($json, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);

        if ($cipher === false) {
            // Fallback: base64 only (better than losing the data entirely).
            return base64_encode($json);
        }

        return base64_encode($iv . $cipher);
    }

    private function decrypt(string $encoded): ?array {
        $raw = @base64_decode($encoded, true);

        if ($raw === false) {
            return null;
        }

        $key = $this->encryptionKey();

        // Minimum: 16-byte IV + 1-byte cipher.
        if (strlen($raw) > 17) {
            $iv     = substr($raw, 0, 16);
            $cipher = substr($raw, 16);
            $json   = @openssl_decrypt($cipher, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
        } else {
            // Plain base64 fallback (written by the encrypt() fallback path).
            $json = $raw;
        }

        if (empty($json)) {
            return null;
        }

        $result = json_decode((string) $json, true);
        return is_array($result) ? $result : null;
    }

    private function encryptionKey(): string {
        $stored = get_option(self::ENC_KEY_OPT, null);

        if ($stored === null) {
            $hex = bin2hex(random_bytes(32));
            add_option(self::ENC_KEY_OPT, $hex, '', false);
            return hex2bin($hex);
        }

        return hex2bin((string) $stored);
    }
}
