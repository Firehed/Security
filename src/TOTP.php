<?php

declare(strict_types=1);

namespace Firehed\Security;

if (!function_exists('Firehed\Security\TOTP')) {
    /**
     * Time-based One-Time Password Algorithm
     *
     * @see RFC 6238
     *
     * @param Secret $key shared secret, treated as binary
     * [@param $step = 30] Time step in seconds (section 4.1; `X`)
     * [@param $offset = 0] Unix time to start counting steps (section 4.1; `T0`)
     * [@param $digits = 6] Length of the output code
     * [@param $algorithm = 'sha1'] HMAC algorithm - sha1, sha256, and sha512 permitted
     *
     * To address clock drift and slow inputs, the $offset option may be used to
     * check for the next and/or previous code. This will adjust the time by the
     * given number of seconds; as such, it's advisable to use values that are
     * a multiple of $step.
     *
     * Note: Google Authenticator's keys are base32-encoded, and must be decoded to
     * binary before being used as a Secret.
     *
     * @return string n-character numeric code
     */
    function TOTP(Secret $key, array $options = []): string
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
