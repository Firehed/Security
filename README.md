# PHP Security Tools

## OTP: One-Time Pads

## PBKDF2: Password-Based Key Derivision Function v2

This is recommended *only* if you are using PHP5.4 or later, since PHP5.5
introduced a native implementation. Be aware that the APIs are not 1:1
compatible:

* PHP's `$length` parameter is the length of the resulting output in *bytes*,
  regardless of raw or hex output
* PBKDF2::generateKey()'s equivalent `$bits` is the number of bits in the *raw*
  output. Meaning to use PHP's version, you must divide by eight for raw
  output, and by four for hex-encoded output.

Namely, the following are equivalent:

    use Firehed\Security\PBKDF2;
    $native = hash_pbkdf2('sha256', 'mypassword', 'mysalt', 10000, 32, true);
    $user = PBKDF2::generateKey('sha256', 'mypassword', 'mysalt', 10000, 256, true);
    // binary string of length 32

and

    use Firehed\Security\PBKDF2;
    $native = hash_pbkdf2('sha256', 'mypassword', 'mysalt', 10000, 32, false);
    $user = PBKDF2::generateKey('sha256', 'mypassword', 'mysalt', 10000, 128, false);
    // string(32) "4d8de27f6f8f0869f21077d2b880dedc"

If the native implementation of `hash_pbkdf2()` is available, `PBKDF2::generateKey()` will automatically use it and adapt the length parameter accordingly. Just be aware that **switching to the native implementation is not just a find-and-replace operattion**.