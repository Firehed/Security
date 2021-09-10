<?php

declare(strict_types=1);

namespace Firehed\Security;

use LengthException;
use OutOfRangeException;

if (!function_exists('Firehed\Security\HOTP')) {
    /**
     * Wrapper for `OTP::getHOTP()`. See that method for additional
     * documentation. This is not deprecated, but it is still recommended to
     * use the object-based interface instead.
     *
     * @param Secret $key shared secret, treated as binary
     * @param int $counter 8-byte counter
     * @param int<6, 8> $digits = 6 Length of the output code
     * @param 'sha1'|'sha256'|'sha512' $algorithm = 'sha1' HMAC algorithm
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
