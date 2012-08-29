<?php

namespace Firehed\Security;

use Exception;

class OTP {
	/**
	 * Time-based One-Time Password Algorithm
	 * @see RFC 6238
	 * @param $key shared secret, in binary format (note: Google Authenticator's keys are base32-encoded, and must be decoded before being passed in)
	 * [@param $step = 30] Time step in seconds (section 4.1)
	 * [@param $t0 = 0] Unix time to start counting steps (section 4.1) (note: positive and negative $t0 in $step increments may be used to check the next and previous codes respectively, which can help address clock drift)
	 * [@param $digits = 6] Length of the output code
	 * @return string n-character numeric code
	 */
	public static function TOTP($key, $step = 30, $t0 = 0, $digits = 6) {
		$counterInt = floor(($_SERVER['REQUEST_TIME'] - $t0) / $step);
		$C = pack('N*', $counterInt & 0xFFFFFFFF00000000) 
		   . pack('N*', $counterInt & 0x00000000FFFFFFFF);
		return self::HOTP($key, $C, $digits);
	}
	/**
	 * HMAC-Based One-Time Password Algorithm
	 * @see RFC 4226
	 * @param $binaryKey binary-formatted key 
	 * @param $binaryCounter binary-formatted counter
	 * [@param $digits = 6] Length of the output code
	 * @return string n-character numeric code
	 */
	public static function HOTP($binaryKey, $binaryCounter, $digits = 6) {
		if ($digits < 6) {
			throw new Exception('RFC4226 requires a minimum of six-digit output');
		}
		$alg = 'sha1';

		$hash = hash_hmac($alg, $binaryCounter, $binaryKey, true);
		$offset = ord(substr($hash, -1)) & 0xF;
		$truncated = substr($hash, $offset, 4);
		extract(unpack('Nnum', $truncated));
		$noMSB = $num & 0x7FFFFFFF;
		$code = $noMSB % pow(10, $digits);
		return str_pad($code, $digits, '0', STR_PAD_LEFT);
	}
}
