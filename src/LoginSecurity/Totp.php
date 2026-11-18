<?php
declare(strict_types=1);

namespace DPXL\Shield\LoginSecurity;

use ParagonIE\ConstantTime\Base32;

/**
 * TOTP one-time passwords (RFC 6238) over HOTP (RFC 4226).
 *
 * Replaces spomky-labs/otphp, which requires PHP 8.1 while the plugin supports
 * 7.4. The algorithm is small and frozen, and none of it is hand-rolled crypto:
 * the HMAC comes from PHP's own hash_hmac(), the secret from random_bytes(),
 * and Base32 from paragonie/constant_time_encoding — all existing, vetted code.
 * Correctness is pinned to the official RFC 6238 test vectors in TotpTest.
 *
 * Only the pieces DPXL Shield actually uses are implemented: generate a secret,
 * hand out a provisioning URI for the QR code, and verify a submitted code.
 * Notably absent is parsing an incoming provisioning URI — the one operation
 * that has historically produced CVEs in TOTP libraries, and one this plugin
 * has never needed.
 */
final class Totp {

    /** Time step, in seconds. 30 is the universal default authenticator apps assume. */
    public const PERIOD = 30;

    /** Code length. */
    public const DIGITS = 6;

    /** HMAC hash. SHA-1 is what RFC 6238 specifies and what every app implements. */
    public const ALGORITHM = 'sha1';

    /** Secret length in bytes. RFC 4226 requires >= 128 bits and recommends 160. */
    private const SECRET_BYTES = 20;

    /** @var string Base32-encoded shared secret, unpadded uppercase. */
    private $secret;

    /** @var string */
    private $label = '';

    /** @var string */
    private $issuer = '';

    /** @var int */
    private $digits;

    /** @var int */
    private $period;

    private function __construct(string $secret, int $digits, int $period) {
        $this->secret = $secret;
        $this->digits = $digits;
        $this->period = $period;
    }

    /** Creates an instance with a fresh cryptographically random secret. */
    public static function generate(): self {
        $secret = Base32::encodeUpperUnpadded(random_bytes(self::SECRET_BYTES));

        return new self($secret, self::DIGITS, self::PERIOD);
    }

    /**
     * Rebuilds an instance from a stored Base32 secret.
     *
     * @param string $secret Base32, with or without padding, any case.
     * @param int    $digits Code length — configurable only so the RFC test
     *                       vectors (which are 8 digits) can be exercised.
     */
    public static function fromSecret(string $secret, int $digits = self::DIGITS, int $period = self::PERIOD): self {
        return new self(strtoupper(trim($secret)), $digits, $period);
    }

    public function getSecret(): string {
        return $this->secret;
    }

    public function setLabel(string $label): void {
        $this->label = $label;
    }

    public function setIssuer(string $issuer): void {
        $this->issuer = $issuer;
    }

    /**
     * otpauth:// URI for the QR code.
     *
     * The issuer appears twice — as a path prefix and as a parameter — because
     * authenticator apps are split on which one they read.
     */
    public function getProvisioningUri(): string {
        $label = $this->issuer !== ''
            ? rawurlencode($this->issuer) . ':' . rawurlencode($this->label)
            : rawurlencode($this->label);

        $params = [
            'secret'    => $this->secret,
            'algorithm' => strtoupper(self::ALGORITHM),
            'digits'    => (string) $this->digits,
            'period'    => (string) $this->period,
        ];

        if ($this->issuer !== '') {
            $params['issuer'] = $this->issuer;
        }

        return 'otpauth://totp/' . $label . '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * Verifies a submitted code.
     *
     * @param string   $code      The digits the user typed.
     * @param int|null $timestamp Defaults to now.
     * @param int      $window    Steps of clock drift tolerated either side.
     */
    public function verify(string $code, ?int $timestamp = null, int $window = 1): bool {
        $code = trim($code);

        if ($code === '' || strlen($code) !== $this->digits || !ctype_digit($code)) {
            return false;
        }

        $timestamp = $timestamp !== null ? $timestamp : time();
        $window    = max(0, $window);
        $counter   = intdiv($timestamp, $this->period);

        $valid = false;

        // Every candidate in the window is checked, and the comparison is
        // constant-time, so neither the loop nor the compare leaks which step
        // matched (or how far into the window it was).
        for ($i = -$window; $i <= $window; $i++) {
            if (hash_equals($this->codeForCounter($counter + $i), $code)) {
                $valid = true;
            }
        }

        return $valid;
    }

    /** The code valid at a given moment. */
    public function at(int $timestamp): string {
        return $this->codeForCounter(intdiv($timestamp, $this->period));
    }

    // ── Internals ────────────────────────────────────────────────────────────

    /** HOTP (RFC 4226 §5.3): HMAC, dynamic truncation, modulo, zero-pad. */
    private function codeForCounter(int $counter): string {
        if ($counter < 0) {
            return str_repeat('-', $this->digits); // never equals a digit string
        }

        $hash = hash_hmac(self::ALGORITHM, $this->counterBytes($counter), $this->binarySecret(), true);

        $offset = ord($hash[strlen($hash) - 1]) & 0x0F;

        $binary = ((ord($hash[$offset]) & 0x7F) << 24)
            | ((ord($hash[$offset + 1]) & 0xFF) << 16)
            | ((ord($hash[$offset + 2]) & 0xFF) << 8)
            | (ord($hash[$offset + 3]) & 0xFF);

        $code = $binary % (10 ** $this->digits);

        return str_pad((string) $code, $this->digits, '0', STR_PAD_LEFT);
    }

    /**
     * The counter as 8 bytes, big-endian.
     *
     * Built byte by byte rather than with pack('J') so the result is identical
     * on 32-bit PHP builds, which shared hosting still occasionally runs.
     */
    private function counterBytes(int $counter): string {
        $bytes = '';

        for ($i = 7; $i >= 0; $i--) {
            $bytes .= chr(($counter >> ($i * 8)) & 0xFF);
        }

        return $bytes;
    }

    /** Decodes the Base32 secret to raw bytes. */
    private function binarySecret(): string {
        // Authenticator apps and QR readers routinely round-trip the secret with
        // padding or spaces; normalise before decoding rather than rejecting.
        $normalised = strtoupper(str_replace([' ', '-', '='], '', $this->secret));

        return Base32::decodeUpper($normalised);
    }
}
