# PHP Security Tools

## Secret: Masked Strings

The Secret class exists to mask sensitive strings. This helps avoid accidentally revealing data in backtraces, which are often written to logs (including remote logging services) or - if an environment is configured for development - revealed to the end-user.

The masked value is *not* encrypted; it's just `XOR`ed with a randomly-generated key that is discarded at the end of the request. That means that Secrets may not be persisted across requests in any way; only their underlying values (which must be manually revealed).

The API is very simple:

    $masked_string = new Firehed\Security\Secret('string to mask');

    $unmaked_string = $masked_string->reveal();

Any other method of getting at the underlying value will be either `"<secret>"` (where export detection is possible) or the masked value (likely binary garbage).


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

### FAQ

#### Can this leak the hidden data?
Not directly, but at some point, you have to reveal the data to use it. Example: `new PDO(...)` or `new mysqli(...)`. If the function consuming the revealed secret throws an exception, the secret can still be revealed. This cannot be solved in user space :(

#### Is this a replacement for encryption?
**NO**, it is not. This obfuscates data, and does not encrypt it.

#### How and when should I use this?

This is a great wrapper for holding temporary sensitive data; e.g. a user's password from a POST request can be wrapped right up until the actual comparision. More concretely:

    class User {
      function isPasswordCorrect(string $password): bool {
        return password_verify($password, $this->pw_hash);
      }
    }
    ...
    if ($user->isPasswordCorrect($_POST['password'])) { ... }
becomes

    use Firehed\Security\Secret;
    class User {
      function isPasswordCorrect(Secret $password): bool {
        return password_verify($password->reveal(), $this->pw_hash);
      }
    }
    ...
    if ($user->isPasswordCorrect(new Secret($_POST['password']))) { ... }

It's also useful for holding API keys, connection passwords, etc:

    $container = new MyDIContainer();
    $container['db_username'] = 'my database user';
    $container['db_password'] = new Secret('my database password');
    $container['database'] = function($c) {
      return new PDO('mysql:host=127.0.0.1;db=test',
        $c['db_username'],
        $c['db_password']->reveal());
    };

(although if you're already using DI properly, the value is diminished)


#### What happens if I put a Secret in $_SESSION?
**Don't do this.** It will work as expected for the rest of the request, but subsequent requests reading it will get garbage.

#### Why use this over passing around encrypted strings?
* No keys to manage
* No external dependencies (OpenSSL, libsodium, etc)
* Straightforward API
* Dead-simple, easy-to-follow implementation
* Encrypted strings still require storing key material somewhere

#### If the masked string is leaked, could it be reversed?
Yes and no.

It's vulnerable to known-plaintext attacks, so if an attacker gets the masked string for both a string they know/control and a string they are trying to capture *from the same request*, they could determine the mask (up to the first N bytes, where N is the length of the known plaintext) and then apply it to the targeted string. Meaning if `strlen($known) >= strlen($target)`, then the target is revealed; if not, only the first N bytes are revealed.

Note that the mask is 128 characters long, and will be repeated if the string to be masked is longer. So if an attacker figures out the first byte of the mask, they will know bytes 1, 129, 257, ... of the masked string.

The implementation makes every effort possible to make the masked value impossible to leak, but it can't catch every scenario due to PHP's user-land limitations (e.g. it's impossible to intercept `var_export`).


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