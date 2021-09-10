<?php

declare(strict_types=1);

namespace Firehed\Security;

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
