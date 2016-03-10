<?php
declare(strict_types=1);

namespace Firehed\Security;

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
    $offset = ord(substr($hash, -1)) & 0xF;
    $noMSB = ((ord($hash[$offset + 0]) & 0x7F) << 24)
           | ((ord($hash[$offset + 1]) & 0xFF) << 16)
           | ((ord($hash[$offset + 2]) & 0xFF) << 8)
           | ((ord($hash[$offset + 3]) & 0xFF) << 0);
    $code = (string) ($noMSB % pow(10, $digits));
    return str_pad($code, $digits, '0', STR_PAD_LEFT);
}

