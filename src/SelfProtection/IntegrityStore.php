<?php
declare(strict_types=1);

namespace DPXL\Shield\SelfProtection;

use DPXL\Shield\Core\Logger;

/**
 * Redundant integrity store — writes to and reads from 3 independent locations.
 *
 * Locations:
 *   1. wp_options  (obfuscated key, AES-256-CBC encrypted value)
 *   2. wp-content/.shieldwp-integrity  (outside the plugin directory)
 *   3. sys_get_temp_dir()/shwp-{site_hash}.lock
 *
 * Reading uses majority vote (2/3). An attacker who modifies the plugin
 * directory cannot forge the result without also compromising the database
 * and the temp directory.
 */
class IntegrityStore {

    // Obfuscated option name — doesn't obviously reveal what it stores.
    private const OPTION_KEY    = '_site_check_timeout_shwp';
    private const ENC_KEY_OPT   = '_site_check_enc_key';
    private const INTEGRITY_FILE = '.shieldwp-integrity';

    // ── Write ──────────────────────────────────────────────────────────────

    /** @param array<string,string> $checksums  relative_path => sha256 */
    public function save(array $checksums): void {
        $payload = $this->encrypt($checksums);

        $this->saveToOptions($payload);
        $this->saveToContentFile($payload);
        $this->saveToTempFile($payload);
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

        // All agree — fast path.
        $serialized = array_map('serialize', $candidates);

        if (count(array_unique($serialized)) === 1) {
            return reset($candidates);
        }

        // Majority vote — 2/3 agreement required.
        $counts  = array_count_values($serialized);
        arsort($counts);
        $winner  = (string) array_key_first($counts);
        $topCount = $counts[$winner];

        if ($topCount >= 2) {
            Logger::error('IntegrityStore: mismatch between storage locations — possible tampering.');
            return unserialize($winner);
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
        $path = WP_CONTENT_DIR . '/' . self::INTEGRITY_FILE;
        @file_put_contents($path, $payload);
        @chmod($path, 0600);
    }

    private function loadFromContentFile(): ?array {
        $path = WP_CONTENT_DIR . '/' . self::INTEGRITY_FILE;

        if (!file_exists($path)) {
            return null;
        }

        $raw = @file_get_contents($path);
        return $raw !== false ? $this->decrypt($raw) : null;
    }

    private function saveToTempFile(string $payload): void {
        @file_put_contents($this->tempFilePath(), $payload);
    }

    private function loadFromTempFile(): ?array {
        $path = $this->tempFilePath();

        if (!file_exists($path)) {
            return null;
        }

        $raw = @file_get_contents($path);
        return $raw !== false ? $this->decrypt($raw) : null;
    }

    private function tempFilePath(): string {
        return sys_get_temp_dir() . '/shwp-' . md5(ABSPATH) . '.lock';
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
