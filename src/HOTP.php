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
     * @param int<6, 8> $digits = 6 Length of the output code
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
        return (new OTP($key))->getHOTP($counter, $digits, $algorithm);
    }
}
