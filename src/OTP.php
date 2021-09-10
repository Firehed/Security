<?php

declare(strict_types=1);

namespace Firehed\Security;

use LengthException;
use OutOfRangeException;

class OTP
{
    const ALG_SHA1 = 'sha1';
    const ALG_SHA256 = 'sha256';
    const ALG_SHA512 = 'sha512';

    /**
     * HMAC-Based One-Time Password Algorithm
     * @see RFC 4226
     * @param Secret $key shared secret, treated as binary
     * @param int $counter 8-byte counter
     * @param int $digits = 6 Length of the output code
     * @param self::ALG_* $algorithm = OTP::ALG_SHA1 HMAC algorithm
     * @return string n-character numeric code
     */
    public static function HOTP(
        Secret $key,
        int $counter,
        int $digits = 6,
        string $algorithm = self::ALG_SHA1
    ): string {
        if (!in_array($algorithm, ['sha1', 'sha256', 'sha512'])) {
            throw new OutOfRangeException('Unexpected algorithm');
        }
        if ($digits < 6 || $digits > 8) {
            // "Implementations MUST extract a 6-digit code at a minimum and
            // possibly 7 and 8-digit code."
            throw new LengthException(
                'RFC4226 requires a 6 to 8-digit output'
            );
        }
        if (strlen($key->reveal()) < 128 / 8) {
            throw new LengthException(
                'Key must be at least 128 bits long (160+ recommended)'
            );
        }

        $counter = pack('J', $counter); // Convert to 8-byte string

        $hash = hash_hmac($algorithm, $counter, $key->reveal(), true);
        // Determine the offset: get the last nibble of the hash output
        $offset = ord(substr($hash, -1)) & 0xF;
        // Index into the hash output by $offset bytes, take four bytes
        $dbc1 = unpack('N', substr($hash, $offset, 4))[1];
        // Mask out the high bit (per the spec, avoids signed/unsigned issues)
        $dbc2 = $dbc1 & 0x7FFFFFFF;
        // Use the last $digits by using modulo 10^digits
        $code = (string) ($dbc2 % pow(10, $digits));
        // Finally, prepend zeroes to match the string length
        return str_pad($code, $digits, '0', \STR_PAD_LEFT);
    }

    /**
     * Time-based One-Time Password Algorithm
     * @see RFC 6238
     *
     * @param Secret $key The shared secret, treated as binary (note: Google
     *                    Authenticator's keys are base32-encoded, and must be decoded
     *                    before being passed in)
     *
     * @param array{
     *   step?: int,
     *   offset?: int,
     *   digits?: int,
     *   algorithm?: 'sha1'|'sha256'|'sha512',
     * } $options
     *
     * Options values:
     *   step = 30: Time step in seconds (section 4.1)
     *   offset = 0: Unix time to start counting steps (section 4.1) (note: positive
     *               and negative $t0 in $step increments may be used to check the
     *               next and previous codes respectively, which can help address
     *               clock drift)
     *   digits = 6: Length of the output code
     *   algorithm = 'sha1': HMAC algorithm - sha1, sha256, and sha512 permitted
     *
     * @return string n-character numeric code
     */

    public static function TOTP(Secret $key, array $options = []): string
    {
        // Parse options
        $step      = 30;
        $offset    = 0;
        $digits    = 6;
        $algorithm = 'sha1';
        extract($options, \EXTR_IF_EXISTS);

        $counter = (int)floor(($_SERVER['REQUEST_TIME'] - $offset) / $step);

        return HOTP($key, $counter, $digits, $algorithm);
    }
}
