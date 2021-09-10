<?php

declare(strict_types=1);

namespace Firehed\Security;

use LengthException;
use OutOfRangeException;

if (!function_exists('Firehed\Security\HOTP')) {
    /**
     * HMAC-Based One-Time Password Algorithm
     *
     * @see RFC 4226
     *
     * @param Secret $key shared secret, treated as binary
     * @param int $counter 8-byte counter
     * @param int $digits = 6 Length of the output code
     * @param 'sha1'|'sha256'|'sha512' $algorithm = 'sha1' HMAC algorithm
     *
     * @return string n-character numeric code
     */
    function HOTP(
        Secret $key,
        int $counter,
        int $digits = 6,
        string $algorithm = 'sha1'
    ): string {
        // @phpstan-ignore-next-line (force-block type mismatch)
        if (!in_array($algorithm, ['sha1', 'sha256', 'sha512'], true)) {
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

        // 5.3 Step 1: Generate hash value
        $hash = hash_hmac($algorithm, $counter, $key->reveal(), true);

        // 5.3 Step 2: Dynamic truncation
        // Determine the offset: get the last nibble of the hash output
        $offset = ord(substr($hash, -1)) & 0xF;
        // Take four bytes from the hash starting at the given offset
        $bytes = substr($hash, $offset, 4);
        // Parse those bytes as an unsigned 32-bit integer into the "Dynamic
        // Binary Code"
        $parsed = unpack('N', $bytes);
        assert($parsed !== false);
        $dbc1 = $parsed[1];
        // Mask out the high bit (per the spec, avoids signed/unsigned issues)
        $dbc2 = $dbc1 & 0x7FFFFFFF;

        // 5.3 Step 3: Compute HOTP value
        // Use the last $digits by using modulo 10^digits
        $code = (string) ($dbc2 % pow(10, $digits));
        // Finally, prepend zeroes to match the string length
        return str_pad($code, $digits, '0', \STR_PAD_LEFT);
    }
}
