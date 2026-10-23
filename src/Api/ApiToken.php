<?php
declare(strict_types=1);

namespace DPXL\Shield\Api;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

/**
 * A read-only API credential.
 *
 * Generation and hashing live here so there is one definition of what a token
 * looks like and how it is stored.
 *
 * Hashing: plain SHA-256, deliberately — not bcrypt or Argon2. Those exist to
 * make guessing *low-entropy human passwords* expensive. A token here is 256
 * bits straight from the CSPRNG, so there is no dictionary to run and no
 * meaningful search space to slow down; a work factor would only add cost to
 * every single API request. What matters — that a database dump cannot be
 * replayed as a credential — is already true with SHA-256.
 */
final class ApiToken {

    /** Marks the string as ours in logs and pasted config. */
    public const PREFIX = 'dpxls_';

    /** Random bytes behind each token. */
    private const ENTROPY_BYTES = 32;

    /** Leading characters kept in clear, to look the row up and to show the admin which token is which. */
    public const LOOKUP_LENGTH = 14;

    private function __construct() {}

    /**
     * Mints a new token.
     *
     * The plaintext is returned once and never stored — the caller must show it
     * to the admin immediately, because nothing can recover it afterwards.
     *
     * @return array{plain:string,hash:string,lookup:string}
     */
    public static function generate(): array {
        $random = rtrim(strtr(base64_encode(random_bytes(self::ENTROPY_BYTES)), '+/', '-_'), '=');
        $plain  = self::PREFIX . $random;

        return [
            'plain'  => $plain,
            'hash'   => self::hash($plain),
            'lookup' => self::lookup($plain),
        ];
    }

    public static function hash(string $plain): string {
        return hash('sha256', $plain);
    }

    /** The clear-text fragment stored alongside the hash, used to find the row. */
    public static function lookup(string $plain): string {
        return substr($plain, 0, self::LOOKUP_LENGTH);
    }

    /**
     * Shape check before any database work.
     *
     * Rejects obvious junk cheaply so a flood of malformed Authorization headers
     * cannot turn into a flood of queries.
     */
    public static function looksValid(string $candidate): bool {
        if (strncmp($candidate, self::PREFIX, strlen(self::PREFIX)) !== 0) {
            return false;
        }

        $body = substr($candidate, strlen(self::PREFIX));

        // 32 bytes of base64url, unpadded.
        return strlen($body) === 43 && preg_match('/^[A-Za-z0-9_-]+$/', $body) === 1;
    }

    /** Display form: enough to identify the token, never enough to use it. */
    public static function mask(string $lookup): string {
        return $lookup . '…';
    }
}
