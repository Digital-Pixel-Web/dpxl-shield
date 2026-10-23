<?php
declare(strict_types=1);

namespace DPXL\Shield\Threat;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

/**
 * Trust primitives for the threat feed.
 *
 * The feed manifest is signed with an Ed25519 private key that never leaves the
 * build environment; the matching public key ships inside the plugin. Verifying
 * the manifest (which carries each artifact's SHA-256) transitively protects the
 * artifacts. Ed25519 via ext-sodium is core PHP since 7.2 — no new dependency.
 *
 * Every method is total: malformed input, wrong lengths, or a missing sodium
 * extension return false / safe values instead of throwing. A verifier that
 * throws in the wrong place could let a bad update through or fatal a cron run.
 */
class FeedVerifier {

    private const ED25519_PUBLICKEY_BYTES = 32;
    private const ED25519_SIGNATURE_BYTES = 64;

    /** True when the runtime can verify Ed25519 signatures. */
    public static function isAvailable(): bool {
        return function_exists('sodium_crypto_sign_verify_detached');
    }

    /** The public key embedded in the plugin (base64), or '' if not wired yet. */
    public static function defaultPublicKey(): string {
        return defined('DPXL_SHIELD_FEED_PUBKEY') ? (string) DPXL_SHIELD_FEED_PUBKEY : '';
    }

    /**
     * Verifies a detached Ed25519 signature over $message.
     *
     * @param string $message      Raw signed bytes (e.g. the canonical manifest).
     * @param string $signatureB64 Base64 of the 64-byte detached signature.
     * @param string $publicKeyB64 Base64 of the 32-byte public key.
     */
    public static function verify(string $message, string $signatureB64, string $publicKeyB64): bool {
        if (!self::isAvailable()) {
            return false;
        }

        $signature = self::b64($signatureB64);
        $publicKey = self::b64($publicKeyB64);

        if ($signature === null || $publicKey === null) {
            return false;
        }

        if (strlen($signature) !== self::ED25519_SIGNATURE_BYTES
            || strlen($publicKey) !== self::ED25519_PUBLICKEY_BYTES) {
            return false;
        }

        try {
            return sodium_crypto_sign_verify_detached($signature, $message, $publicKey);
        } catch (\Throwable $e) {
            return false;
        }
    }

    /** Lower-case hex SHA-256 of $content. */
    public static function sha256(string $content): string {
        return hash('sha256', $content);
    }

    /** Constant-time check that $content hashes to $expectedHex (SHA-256). */
    public static function sha256Matches(string $content, string $expectedHex): bool {
        if ($expectedHex === '') {
            return false;
        }

        return hash_equals(self::sha256($content), strtolower(trim($expectedHex)));
    }

    /**
     * True only if $candidate is a strictly newer feed version than $current.
     *
     * Versions are dotted numeric strings (`YYYY.MM.DD[.n]`). Compared segment by
     * segment as integers — so `2026.07.26.10` correctly outranks `2026.07.26.2`,
     * which a plain string compare gets wrong. Missing trailing segments count as 0.
     * This is the anti-rollback guard: never apply a feed that isn't newer.
     */
    public static function isNewerVersion(string $candidate, string $current): bool {
        $a = self::segments($candidate);
        $b = self::segments($current);
        $len = max(count($a), count($b));

        for ($i = 0; $i < $len; $i++) {
            $x = $a[$i] ?? 0;
            $y = $b[$i] ?? 0;

            if ($x !== $y) {
                return $x > $y;
            }
        }

        return false; // equal
    }

    // ── Internals ──────────────────────────────────────────────────────────

    /** @return list<int> */
    private static function segments(string $version): array {
        if ($version === '') {
            return [];
        }

        return array_map(static fn($s) => (int) $s, explode('.', trim($version)));
    }

    /** Strict base64 decode; null on failure. */
    private static function b64(string $value): ?string {
        $decoded = base64_decode(trim($value), true);

        return $decoded === false ? null : $decoded;
    }
}
