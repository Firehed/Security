# Changelog

## [Unreleased]

### Added

- `Algorithm` enum for OTP hashing algorithms (replaces string constants)
- `OTP` constructor now accepts `Secret|string` for convenience

### Changed

- **BREAKING**: `OTP::getHOTP()` and `OTP::getTOTP()` now require `Algorithm` enum instead of string for the algorithm parameter
- Modernized codebase to use PHP 8.2+ features (readonly properties, typed properties, constructor property promotion)

### Removed

- **BREAKING**: `HOTP()` and `TOTP()` functions have been removed. Use the `OTP` class directly instead.
- **BREAKING**: `OTP::ALGORITHM_*` string constants have been removed. Use the `Algorithm` enum instead.

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
