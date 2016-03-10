<?php
declare(strict_types=1);

namespace Firehed\Security;
use Exception;


/**
 * HMAC-Based One-Time Password Algorithm
 * @see RFC 4226
 * @param $key shared secret, treated as binary
 * @param $counter 8-byte counter
 * [@param $digits = 6] Length of the output code
 * [@param $algorithm = 'sha1'] HMAC algorithm - sha1, sha256, and sha512 permitted
 * @return string n-character numeric code
 */
function HOTP(
    Secret $key,
    string $counter,
    array $options = []
): string {
    // Parse options
    $digits = 6;
    $algorithm = 'sha1';
    extract($options, \EXTR_IF_EXISTS);

    if ($digits < 6) {
        throw new Exception('RFC4226 requires a minimum of six-digit output');
    }
    if (strlen($counter) != 8) {
        throw new Exception('Counter must be 8 bytes long');
    }
    if (strlen($key->reveal()) < 128 / 8) {
        throw new Exception('Key must be at least 128 bits long (160+ recommended)');
    }

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

