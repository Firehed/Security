<?php

declare(strict_types=1);

namespace Firehed\Security;

use DomainException;
use LengthException;

use function assert;
use function floor;
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

        $dbc = self::dynamicTruncate($hash);
        // 5.3 Step 3: Compute HOTP value
        // Use the last $digits by using modulo 10^digits
        $code = (string) ($dbc % pow(10, $digits));
        // Finally, prepend zeroes to match the string length
        return str_pad($code, $digits, '0', \STR_PAD_LEFT);
    }

    /**
     * @param int<6, 8> $digits
     * @param self::ALGORITHM_* $algorithm
     */
    public function getTOTP(
        int $step = 30,
        int $t0 = 0,
        int $digits = 6,
        string $algorithm = self::ALGORITHM_SHA1
    ): string {
        $t = (int) floor(($_SERVER['REQUEST_TIME'] - $t0) / $step);
        return $this->getHOTP($t, $digits, $algorithm);
    }

    /**
     * Generate a 31-bit int using the dynamic truncation algorithm described
     * in RFC 4226 section 5.3
     */
    private static function dynamicTruncate(string $binaryHash): int
    {
        // SHA-1 generates a 160-bit (20-byte) hash; others are longer. That
        // length is necessary for the algorithm to work.
        assert(strlen($binaryHash) >= 20);

        $lastByte = substr($binaryHash, -1);
        $offset = ord($lastByte) & 0x0F; // Lower 4 bits determine offset

        // Take four bytes from the hash starting at the given offset
        $bytes = substr($binaryHash, $offset, 4);
        assert(strlen($bytes) === 4);
        // Parse those bytes as an unsigned 32-bit integer into the "Dynamic
        // Binary Code"
        $parsed = unpack('N', $bytes);
        assert($parsed !== false);
        $dbc1 = $parsed[1];
        // Mask out the high bit (per the spec, avoids signed/unsigned issues)
        $dbc2 = $dbc1 & 0x7FFFFFFF;

        return $dbc2;
    }
}
