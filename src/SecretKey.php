<?php
declare(strict_types=1);

namespace Firehed\Security;

/**
 * Holds the key for Secret in a separate class and file to prevent appearance
 * in backtraces, etc. You should never need to use this class directly.
 */
final class SecretKey {

    private static $key;

    // Private constructor: only access is allowed through getKey()
    private function __construct() {}

    public static function getKey(): string {
        if (self::$key === null) {
            // NOTE: This is NOT intended to be cryptographically-secure; this
            // is obfuscation only. This just ensures garbage rather than
            // sensitive data appears in logs, and is NOT a replacement for
            // encryption.
            self::$key = '';
            for ($ii = 0; $ii < 8; $ii++) {
                self::$key .= md5((string)mt_rand(), $raw_output = true);
            }
        }
        return self::$key;
    }

}
