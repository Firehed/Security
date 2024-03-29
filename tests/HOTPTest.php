<?php

declare(strict_types=1);

namespace Firehed\Security;

/**
 * @covers Firehed\Security\OTP
 * @covers Firehed\Security\HOTP
 */
class HOTPTest extends \PHPUnit\Framework\TestCase
{
    /**
     * Test vectors provided by RFC 4226, Appendix D
     *
     * @link https://tools.ietf.org/html/rfc4226#page-32
     *
     * @return array{Secret, int, string}[]
     */
    public function vectors(): array
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

    /**
     * @dataProvider vectors
     */
    public function testHOTP(Secret $secret, int $counter, string $out): void
    {
        self::assertSame(
            $out,
            HOTP($secret, $counter),
            'Wrong HOTP output'
        );
    }

    public function testBadAlgorithm(): void
    {
        $this->expectException(\LogicException::class);
        HOTP(
            new Secret('abcdefgijklmnopqrstuvwxyz'),
            0x1234567890123456,
            6,
            // @phpstan-ignore-next-line (testing type mismatch)
            'notalg'
        );
    }

    public function testTooFewDigits(): void
    {
        $this->expectException(\LengthException::class);
        HOTP(
            new Secret('abcdefgijklmnopqrstuvwxyz'),
            0x1234567890123456,
            // @phpstan-ignore-next-line validation check
            4
        );
    }

    public function testTooManyDigits(): void
    {
        $this->expectException(\LengthException::class);
        HOTP(
            new Secret('abcdefgijklmnopqrstuvwxyz'),
            0x1234567890123456,
            // @phpstan-ignore-next-line validation check
            9
        );
    }

    public function testInvalidKeyLength(): void
    {
        $this->expectException(\LengthException::class);
        HOTP(
            new Secret('123456789012345'),
            0x1234567890123456
        );
    }
}
