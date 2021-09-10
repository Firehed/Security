<?php

namespace Firehed\Security;

/**
 * @coversDefaultClass Firehed\Security\SecretKey
 * @covers ::<protected>
 * @covers ::<private>
 */
class SecretKeyTest extends \PHPUnit\Framework\TestCase
{

    /**
     * @covers ::getKey
     */
    public function testGetKey()
    {
        $this->assertInternalType('string', SecretKey::getKey());
    }
}
