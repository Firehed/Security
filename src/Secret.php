<?php

namespace Firehed\Security;

/**
 * Opaque reference to a string (like a password) that won't put any sensitive
 * data in stack traces, var_dump(), print_r(), error logs, etc. Usage:
 *
 *    $secret = new Secret($password);
 *    do_stuff($envelope);
 *    // ...
 *    $password = $secret->reveal();
 *
 * Any time you're passing sensitive data into a stack, you should obscure it
 * with a Secret to prevent it leaking if something goes wrong.
 *
 * The key for the envelope is stored elsewhere, in SecretKey. This prevents it
 * from appearing in any sort of logs related to the envelope, even if the
 * logger is very aggressive.
 */
final class Secret {

    /**
     * Obfuscated value
     */
    private $value;

    /**
     * @param string The secret to obscure
     */
    public function __construct($string) {
        $this->value = $this->mask($string, SecretKey::getKey());
    }

    /**
     * @return string The original secret
     */
    public function reveal() {
        return $this->mask($this->value, SecretKey::getKey());
    }

    /**
     * @return string A hardcoded string, "<secret>", so that the actual secret
     * is not accidentally revealed.
     */
    public function __toString() {
        return '<secret>';
    }

    /**
     * @param string The string to obfuscate or deobfuscate
     * @param string The mask
     * @return string The obfuscated or deobfuscated string
     */
    private function mask($string, $noise) {
        $result = '';
        for ($ii = 0; $ii < strlen($string); $ii++) {
            $s = $string[$ii];
            $n = $noise[$ii % strlen($noise)];

            $result .= chr(ord($s) ^ ord($n));
        }
        return $result;
    }

}
