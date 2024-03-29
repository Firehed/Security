<?php

declare(strict_types=1);

namespace Firehed\Security;

/**
 * @covers Firehed\Security\Secret
 */
class SecretTest extends \PHPUnit\Framework\TestCase
{
    public function testConstruct(): void
    {
        $this->assertInstanceOf(
            Secret::class,
            new Secret('test')
        );
    }

    public function testOpenEnvelope(): void
    {
        $test_string = md5(random_bytes(10));
        $secret = new Secret($test_string);
        $this->assertSame(
            $test_string,
            $secret->reveal(),
            'The string was modified when the envelope opened'
        );
    }

    public function testToString(): void
    {
        $test_string = md5(random_bytes(10));
        $secret = new Secret($test_string);
        $cast_output = (string)$secret;
        $this->assertNotSame(
            $test_string,
            $cast_output,
            'The cast value was not masked correctly'
        );
    }

    public function testSecretIsHiddenFromPrintR(): void
    {
        $test_string = md5(random_bytes(10));
        $secret = new Secret($test_string);
        $dumped = print_r($secret, true);
        $this->assertStringNotContainsString(
            $test_string,
            $dumped,
            'print_r revealed the secret'
        );
    }

    public function testSecretIsHiddenFromVarDump(): void
    {
        $test_string = md5(random_bytes(10));
        $secret = new Secret($test_string);
        ob_start();
        var_dump($secret);
        $dumped = ob_get_clean();
        assert($dumped !== false);
        $this->assertStringNotContainsString(
            $test_string,
            $dumped,
            'var_dump revealed the secret'
        );
    }

    public function testMaskingStringLongerThanNoiseLength(): void
    {
        $noise = SecretKey::getKey();
        $noise_length = mb_strlen($noise, '8bit');
        $string = str_repeat('asdf', $noise_length);
        $secret = new Secret($string);
        $this->assertSame($string, $secret->reveal(), 'Secret was destroyed');
    }
}
