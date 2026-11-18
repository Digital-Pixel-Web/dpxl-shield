<?php
declare(strict_types=1);

namespace DPXL\Shield\LoginSecurity;

/**
 * Generates, stores and verifies 2FA backup codes.
 *
 * Each code is 8 hex characters displayed as "xxxx xxxx" (e.g. "a3f7 19bc").
 * Codes are stored as bcrypt hashes — one-time use; consumed on verification.
 */
class BackupCodes {

    private const META_KEY    = 'dpxl_shield_backup_codes';
    private const CODE_COUNT  = 8;

    /**
     * Generates fresh backup codes for a user, replacing any existing ones.
     *
     * @return string[]  Plain-text codes to show to the user (stored as hashes)
     */
    public static function generate(int $userId): array {
        $plainCodes = [];
        $hashedCodes = [];

        for ($i = 0; $i < self::CODE_COUNT; $i++) {
            $raw      = bin2hex(random_bytes(4));             // 8 hex chars
            $display  = substr($raw, 0, 4) . ' ' . substr($raw, 4); // "abcd ef01"
            $plainCodes[]  = $display;
            $hashedCodes[] = password_hash($raw, PASSWORD_BCRYPT, ['cost' => 10]);
        }

        update_user_meta($userId, self::META_KEY, $hashedCodes);

        return $plainCodes;
    }

    /**
     * Verifies a backup code and removes it from the store on success.
     *
     * @param string $input  User-typed code (spaces allowed)
     */
    public static function verify(int $userId, string $input): bool {
        $normalized = strtolower(str_replace([' ', '-'], '', $input));

        if (strlen($normalized) !== 8 || !ctype_xdigit($normalized)) {
            return false;
        }

        $stored = get_user_meta($userId, self::META_KEY, true);

        if (!is_array($stored) || empty($stored)) {
            return false;
        }

        foreach ($stored as $index => $hash) {
            if (password_verify($normalized, $hash)) {
                // Remove the used code (one-time use).
                unset($stored[$index]);
                update_user_meta($userId, self::META_KEY, array_values($stored));
                return true;
            }
        }

        return false;
    }

    /**
     * Returns the number of remaining unused backup codes.
     */
    public static function remainingCount(int $userId): int {
        $stored = get_user_meta($userId, self::META_KEY, true);
        return is_array($stored) ? count($stored) : 0;
    }

    /**
     * Deletes all backup codes for a user (e.g. when 2FA is deactivated).
     */
    public static function delete(int $userId): void {
        delete_user_meta($userId, self::META_KEY);
    }
}
