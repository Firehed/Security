# Changelog

## [Unreleased]

### Added

- `Algorithm` enum for OTP hashing algorithms

### Changed

- `OTP::getHOTP()` and `OTP::getTOTP()` now accept `Algorithm` enum instead of string
- `OTP::ALGORITHM_*` constants are deprecated; use `Algorithm` enum directly

### Removed

- **BREAKING**: `HOTP()` and `TOTP()` functions have been removed. Use the `OTP` class directly instead.

  Before:
  ```php
  $code = \Firehed\Security\HOTP($secret, $counter);
  $code = \Firehed\Security\TOTP($secret, ['digits' => 8]);
  ```

  After:
  ```php
  $otp = new \Firehed\Security\OTP($secret);
  $code = $otp->getHOTP($counter);
  $code = $otp->getTOTP(digits: 8);
  ```
