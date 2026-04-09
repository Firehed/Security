<?php

declare(strict_types=1);

namespace Firehed\Security;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(OTP::class)]
class HOTPTest extends \PHPUnit\Framework\TestCase
{
    /**
     * Test vectors provided by RFC 4226, Appendix D
     *
     * @link https://tools.ietf.org/html/rfc4226#page-32
     *
     * @return array{Secret, int, string}[]
     */
    public static function vectors(): array
    {
        $secret = new Secret('12345678901234567890');
        return [
            [$secret, 0, '755224'],
            [$secret, 1, '287082'],
            [$secret, 2, '359152'],
            [$secret, 3, '969429'],
            [$secret, 4, '338314'],
            [$secret, 5, '254676'],
            [$secret, 6, '287922'],
            [$secret, 7, '162583'],
            [$secret, 8, '399871'],
            [$secret, 9, '520489'],
        ];
    }

    #[DataProvider('vectors')]
    public function testHOTP(Secret $secret, int $counter, string $out): void
    {
        $otp = new OTP($secret);
        self::assertSame(
            $out,
            $otp->getHOTP($counter),
            'Wrong HOTP output'
        );
    }

    public function testBadAlgorithm(): void
    {
        $this->expectException(\DomainException::class);
        $otp = new OTP(new Secret('abcdefgijklmnopqrstuvwxyz'));
        $otp->getHOTP(
            0x1234567890123456,
            6,
            // @phpstan-ignore argument.type (testing type mismatch)
            'notalg'
        );
    }

    public function testTooFewDigits(): void
    {
        $this->expectException(\LengthException::class);
        $otp = new OTP(new Secret('abcdefgijklmnopqrstuvwxyz'));
        $otp->getHOTP(
            0x1234567890123456,
            // @phpstan-ignore argument.type
            4
        );
    }

    public function testTooManyDigits(): void
    {
        $this->expectException(\LengthException::class);
        $otp = new OTP(new Secret('abcdefgijklmnopqrstuvwxyz'));
        $otp->getHOTP(
            0x1234567890123456,
            // @phpstan-ignore argument.type
            9
        );
    }

    public function testInvalidKeyLength(): void
    {
        $this->expectException(\LengthException::class);
        $otp = new OTP(new Secret('123456789012345'));
        $otp->getHOTP(0x1234567890123456);
    }
}
