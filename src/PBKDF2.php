<?php

namespace Firehed\Security;

use Exception;

class PBKDF2 {

	// If you touch this function, re-run the unit tests enabling the
	// 16777216-iteration test. It's too slow (by design) to run during
	// standard testing but is important to ensure the integrity of the
	// algoritm
	// 
	// While this goes against the "don't roll your own crypto" policy,
	// no standard library exists for this until PHP 5.4 (hash_pbkdf2)

	public static function generateKey($PRF, $password, $salt, $count, $bits, $raw = false) {
        if (function_exists('hash_pbkdf2')) {
            if ($raw) {
                $len = $bits / 8;
            } else {
                $len = $bits / 4;
            }
            return hash_pbkdf2($PRF, $password, $salt, $count, $len, $raw);
        }
		// Key length sanity check
		if (!$bits || ($bits % 8)) {
			throw new Exception("Key length in bits must be a multiple of 8");
		}

		// Hash function sanity check
		$PRF = strtolower($PRF);
		if (!in_array($PRF, hash_algos())) {
			throw new Exception("Algorithm $PRF unsupported");
		}

		$bytes = $bits / 8;

		// Base hash length
		$hLen = strlen(hash($PRF, '', true));

		// Number of passes of algorithm we need to make to generate a key of
		// the desired length
		$tMax = ceil($bytes / $hLen);

		$DK = '';
		for ($i = 1; $i <= $tMax; $i++) { 
			$iStr = pack('N', $i);
			// first iteration
			$F = $Uc = hash_hmac($PRF, $salt . $iStr, $password, true);
			// rest of iterations
			for ($j=1; $j < $count; $j++) { 
				$F ^= ($Uc = hash_hmac($PRF, $Uc, $password, true));
			}
			$DK .= $F;
		}
		$DK = substr($DK, 0, $bytes);
		return $raw ? $DK : bin2hex($DK);
	}

}
