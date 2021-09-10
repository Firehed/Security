<?php

declare(strict_types=1);

namespace Firehed\Security;

use DomainException;
use LengthException;

use function assert;
use function hash_hmac;
use function ord;
use function pack;
use function pow;
use function str_pad;
use function strlen;
use function substr;
use function unpack;

class OTP
{
    public const ALGORITHM_SHA1 = 'sha1';
    public const ALGORITHM_SHA256 = 'sha256';
    public const ALGORITHM_SHA512 = 'sha512';

    /** @var Secret */
    private $secret;

    public function __construct(Secret $secret)
    {
        $this->secret = $secret;
    }

    /**
     * @param int<6, 8> $digits
     * @param self::ALGORITHM_* $algorithm
     */
    public function getHOTP(int $counter, int $digits = 6, string $algorithm = self::ALGORITHM_SHA1): string
    {
        /** @var string $algorithm (don't rely on build-time types) */
        if (
            $algorithm !== self::ALGORITHM_SHA1
            && $algorithm !== self::ALGORITHM_SHA256
            && $algorithm !== self::ALGORITHM_SHA512
        ) {
            throw new DomainException('Invalid algorithm');
        }

        /** @var int $digits (same as above) */
        if ($digits < 6 || $digits > 8) {
            // "Implementations MUST extract a 6-digit code at a minimum and
            // possibly 7 and 8-digit code."
            throw new LengthException(
                'RFC4226 requires a 6 to 8-digit output'
            );
        }

        if (strlen($this->secret->reveal()) < (128 / 8)) {
            throw new LengthException(
                'Key must be at least 128 bits long (160+ recommended)'
            );
        }

        $counter = pack('J', $counter); // Convert to 8-byte string

        // 5.3 Step 1: Generate hash value
        $hash = hash_hmac($algorithm, $counter, $this->secret->reveal(), true);

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
