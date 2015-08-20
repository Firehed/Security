<?php

namespace Firehed\Security;

/**
 * Holds the key for Secret in a separate class and file to prevent appearance
 * in backtraces, etc. You should never need to use this class directly.
 */
final class SecretKey {

    private static $key;

    private function __construct() {
        // <private>
    }

    public static function getKey() {
        if (self::$key === null) {
            // NOTE: This is NOT intended to be cryptographically-secure; this
            // is obfuscation only. This just ensures garbage rather than
            // sensitive data appears in logs, and is NOT a replacement for
            // encryption.
            self::$key = '';
            for ($ii = 0; $ii < 8; $ii++) {
                self::$key .= md5(mt_rand(), $raw_output = true);
            }
        }
        return self::$key;
    }

}
