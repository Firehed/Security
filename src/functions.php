<?php

declare(strict_types=1);

namespace Firehed\Security;

function HOTP(): string
{
    return OTP::HOTP(...func_get_args());
}

function TOTP(): string
{
    return OTP::TOTP(...func_get_args());
}
