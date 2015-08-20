<?php

namespace Firehed\Security;

/**
 * @coversDefaultClass Firehed\Security\Secret
 * @covers ::<protected>
 * @covers ::<private>
 */
class SecretTest extends \PHPUnit_Framework_TestCase
{

    /**
     * @covers ::__construct
     */
    public function testConstruct()
    {
        $this->assertInstanceOf('Firehed\Security\Secret',
            new Secret('test'));
    } // testConstruct

    /**
     * @covers ::reveal
     */
    public function testOpenEnvelope()
    {
        $test_string = md5(time());
        $secret = new Secret($test_string);
        $this->assertSame($test_string, $secret->reveal(),
            'The string was modified when the envelope opened');
    } // testOpenEnvelope

    /**
     * @covers ::__toString
     */
    public function testToString()
    {
        $test_string = md5(time());
        $secret = new Secret($test_string);
        $cast_output = (string)$secret;
        $this->assertNotSame($test_string, $cast_output,
            'The cast value was not masked correctly');
    } // testToString

}
