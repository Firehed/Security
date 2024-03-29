<?php

declare(strict_types=1);

namespace Firehed\Security;

/**
 * @covers Firehed\Security\SecretKey
 */
class SecretKeyTest extends \PHPUnit\Framework\TestCase
{
    public function testGetKey(): void
    {
        $this->assertIsString(SecretKey::getKey());
    }
}
