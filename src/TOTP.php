<?php

declare(strict_types=1);

namespace Firehed\Security;

// Note: wrapped to prevent weird code coverage loading issue.
if (!function_exists('Firehed\Security\TOTP')) {
    /**
     * Wrapper for `OTP::getTOTP()`. See that method for additional
     * documentation. This is not deprecated, but it is still recommended to
     * use the object-based interface instead.
     *
     * @param Secret $key shared secret, treated as binary
     * @param array{
     *   step?: int,
     *   offset?: int,
     *   digits?: int<6, 8>,
     *   algorithm?: 'sha1'|'sha256'|'sha512',
     * } $options
     *
     * Options values correspond to the equivalently-named paramters of
     * `getTOTP()`; `$offset` is named `$t0` on the class method.
     */
    function TOTP(Secret $key, array $options = []): string
    {
        // Parse options
        $step      = 30;
        $offset    = 0;
        $digits    = 6;
        $algorithm = 'sha1';
        extract($options, \EXTR_IF_EXISTS);

        return (new OTP($key))->getTOTP($step, $offset, $digits, $algorithm);
    }
}
