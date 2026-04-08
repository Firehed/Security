<?php

declare(strict_types=1);

namespace Firehed\Security;

use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(SecretKey::class)]
class SecretKeyTest extends \PHPUnit\Framework\TestCase
{
    public function testGetKey(): void
    {
        $key = SecretKey::getKey();
        $this->assertNotEmpty($key);
    }
}
