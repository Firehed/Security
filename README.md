# PHP Security Tools

## Secret: Masked Strings

The Secret class exists to mask sensitive strings.
This helps avoid accidentally revealing data in backtraces, which are often written to logs (including remote logging services) or - if an environment is configured for development - revealed to the end-user.

The masked value is *not* encrypted; it's just `XOR`ed with a randomly-generated key that is discarded at the end of the request.
That means that Secrets may not be persisted across requests in any way; only their underlying values (which must be manually revealed).

The API is very simple:

```php
$masked_string = new Firehed\Security\Secret('string to mask');

$unmasked_string = $masked_string->reveal();
```

Any other method of getting at the underlying value will be either `"<secret>"` (where export detection is possible) or the masked value (likely binary garbage).

```php
require 'vendor/autoload.php';
$x = new Firehed\Security\Secret('asdf');
echo $x;
// <secret>

print_r($x);
// Firehed\Security\Secret Object
// (
//     [secret] => <secret>
// )

var_dump($x);
// class Firehed\Security\Secret#2 (1) {
//   public $secret =>
//   string(8) "<secret>"
// }

var_export($x);
// Firehed\Security\Secret::__set_state(array(
//    'value' => '�AZ�',
// ))

var_dump($x->reveal());
// string(4) "asdf"

try {
    doSomethingThatThrows($x);
} catch (Throwable $ex) {
    echo $ex;
}
// Stack trace:
// #0 /some/file.php(15): doSomethingThatThrows(Object(Firehed\Security\Secret))
// #1 {main}Exception: Some message in /some/file.php:9
```

### FAQ

#### Can this leak the hidden data?
Not directly, but at some point, you have to reveal the data to use it.
Example: `new PDO(...)` or `new mysqli(...)`.
If the function consuming the revealed secret throws an exception, the secret can still be revealed.
This cannot be solved in user space :(

#### Is this a replacement for encryption?
**NO**, it is not.
This obfuscates data, and does not encrypt it.

#### How and when should I use this?

This is a great wrapper for holding temporary sensitive data; e.g. a user's password from a POST request can be wrapped right up until the actual comparision.
More concretely:

```php
class User
{
    function isPasswordCorrect(string $password): bool
    {
        return password_verify($password, $this->pw_hash);
    }
}
// ...

if ($user->isPasswordCorrect($_POST['password'])) { ... }
```

becomes

```php
use Firehed\Security\Secret;

class User
{
    function isPasswordCorrect(Secret $password): bool
    {
        return password_verify($password->reveal(), $this->pw_hash);
    }
}
// ...
if ($user->isPasswordCorrect(new Secret($_POST['password']))) { ... }
```

It's also useful for holding API keys, connection passwords, etc:

```php
$container = new MyDIContainer();
$container['db_username'] = getenv('DB_USER');
$container['db_password'] = new Secret(getenv('DB_PASS'));
$container['database'] = function ($c) {
    return new PDO(
        'mysql:host=127.0.0.1;db=test',
        $c['db_username'],
        $c['db_password']->reveal(),
    );
};
```

(although if you're already using DI properly, the value is diminished)


#### What happens if I put a Secret in $_SESSION?
**Don't do this.**
It will work as expected for the rest of the request, but subsequent requests reading it will get garbage.

#### Why use this over passing around encrypted strings?
* No keys to manage
* No external dependencies (OpenSSL, libsodium, etc)
* Straightforward API
* Dead-simple, easy-to-follow implementation
* Encrypted strings still require storing key material somewhere

#### If the masked string is leaked, could it be reversed?
Yes and no.

It's vulnerable to known-plaintext attacks, so if an attacker gets the masked string for both a string they know/control and a string they are trying to capture *from the same request*, they could determine the mask (up to the first N bytes, where N is the length of the known plaintext) and then apply it to the targeted string.
Meaning if `strlen($known) >= strlen($target)`, then the target is revealed; if not, only the first N bytes are revealed.

Note that the mask is 128 characters long, and will be repeated if the string to be masked is longer.
So if an attacker figures out the first byte of the mask, they will know bytes 1, 129, 257, ... of the masked string.

The implementation makes every effort possible to make the masked value impossible to leak, but it can't catch every scenario due to PHP's user-land limitations (e.g. it's impossible to intercept `var_export`).

## OTP: One-Time Passwords

OTPs allow for a shared secret between a client and a server to perform authentication by hashing a known "counter" or "moving factor".
For HOTP, the counter is typically a monotonically-increasing value; TOTP is based on the current time.

### HOTP: HMAC-based One Time Password (RFC 4226)

You probably will not need to use this directly, since most user-facing OTP applications are based on the TOTP protocol (see below).
However, for reference, the API is as follows:

```php
// Preferred: Object-oriented

$otp = new \Firehed\Security\OTP(Secret $secret);
$code = $otp->getHOTP(int $counter, int $digits = 6, string $algorithm = OTP::ALGORITHM_SHA1);

// Legacy: function-based

$code = \Firehed\Security\HOTP(Secret $key, int $counter, int $digits = 6, string $algorithm = 'sha1');
```

Detailed parameter documentation is on the OTP class.

### TOTP: Time-based One Time Password (RFC 6238)

This builds off HOTPs by using time-based counters to make one-time passwords.
This was made popular by Google Authenticator, although a handful of TOTP clients now exist.

The API is extremely straightforward with the default values:

```php
// Preferred: Object-oriented

$otp = new \Firehed\Security\OTP(Secret $secret);
$code = $otp->getTOTP(int $step = 30, int $t0 = 0, int $digits = 6, string $algorithm = OTP::ALGORITHM_SHA1);

// Legacy: function-based
$code = \Firehed\Security\TOTP(Secret $key, array $options = []): string
```

Detailed parameter documentation is on the OTP class.
The default values for parameters align with a typical Google Authenticator-style TOTP setup.

Generating the one-time code is therefore very simple:

```php
// The string parameter to $secret should be user-specific, and kept protected at rest.
$secret = new \Firehed\Security\Secret('some shared secret');
$otp = new \Firehed\Security\OTP($secret);
$code = $otp->getTOTP();

// Or: $code = \Firehed\Security\TOTP($secret);
```

You should verify the expected value against the user's provided value with the
`hash_equals` function, in order to mitigate timing attacks:

```php
return hash_equals($user_input, $code);
```

Options allow for changing the number of output digits (default 6), hashing algorithm (sha1), or step (30 seconds).
Because most TOTP client apps don't fully support all of the options, it is recommended to only use the default values at this time.
See the docblocks in `src/OTP.php` and `src/TOTP.php` for additional information.

Note:

The secret provided to the `TOTP()` function must be the *raw value* - the one that a user adds to their app is normally sent to the user Base32-encoded.
If you provide the Base32-encoded secret to the function, you will get the wrong result.

### Shared Secrets

Both HOTP and TOTP are based on a secret shared between the client and server.
This secret must be generated by the server in a cryptographically-secure manner and stored encrypted;
providing the secret to the client must also be done in a secure way (likely using TLS) and should only be done once to avoid key cloning.

It is *highly recommended* to use the `random_bytes()` function in PHP to generate the shared secret.
