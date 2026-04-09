# Changelog

## [Unreleased]

### Added

- `Algorithm` enum for OTP hashing algorithms
- `OTP` constructor now accepts `Secret|string` for convenience

### Changed

- `OTP::getHOTP()` and `OTP::getTOTP()` now accept `Algorithm` enum instead of string
- `OTP::ALGORITHM_*` constants are deprecated; use `Algorithm` enum directly
- Modernized codebase to use PHP 8.2+ features (readonly properties, typed properties, constructor property promotion)

### Removed

- **BREAKING**: `HOTP()` and `TOTP()` functions have been removed. Use the `OTP` class directly instead.

  Before:
  ```php
  $code = \Firehed\Security\HOTP($secret, $counter);
  $code = \Firehed\Security\TOTP($secret, ['digits' => 8, 'algorithm' => 'sha256']);
  ```

  After:
  ```php
  $otp = new \Firehed\Security\OTP($secret);
  $code = $otp->getHOTP($counter);
  $code = $otp->getTOTP(digits: 8, algorithm: Algorithm::SHA256);
  ```
