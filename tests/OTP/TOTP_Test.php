<?php
use Firehed\Security\OTP;
require_once 'OTP.php';

class TOTP_Tests extends PHPUnit_Framework_TestCase {

	// Test vectors provided by RFC 6238, Appendix B
	function vectors() {
		// It's unclear that the token is of varying length based on the 
		// algoritm being used, but that's definitely the case
		$base = str_repeat('1234567890', 10);
		$tok_sha1   = substr($base, 0, 20);
		$tok_sha256 = substr($base, 0, 32);
		$tok_sha512 = substr($base, 0, 64);
		return array
		( array(         59, '94287082', 'sha1'  , $tok_sha1  )
		, array(         59, '46119246', 'sha256', $tok_sha256)
		, array(         59, '90693936', 'sha512', $tok_sha512)
		, array( 1111111109, '07081804', 'sha1'  , $tok_sha1  )
		, array( 1111111109, '68084774', 'sha256', $tok_sha256)
		, array( 1111111109, '25091201', 'sha512', $tok_sha512)
		, array( 1111111111, '14050471', 'sha1'  , $tok_sha1  )
		, array( 1111111111, '67062674', 'sha256', $tok_sha256)
		, array( 1111111111, '99943326', 'sha512', $tok_sha512)
		, array( 1234567890, '89005924', 'sha1'  , $tok_sha1  )
		, array( 1234567890, '91819424', 'sha256', $tok_sha256)
		, array( 1234567890, '93441116', 'sha512', $tok_sha512)
		, array( 2000000000, '69279037', 'sha1'  , $tok_sha1  )
		, array( 2000000000, '90698825', 'sha256', $tok_sha256)
		, array( 2000000000, '38618901', 'sha512', $tok_sha512)
		, array(20000000000, '65353130', 'sha1'  , $tok_sha1  )
		, array(20000000000, '77737706', 'sha256', $tok_sha256)
		, array(20000000000, '47863826', 'sha512', $tok_sha512)
		);
	}

	/**
	 * @dataProvider vectors
	 */
	function testVectors($ts, $expectedOut, $algo, $tok) {
		$_SERVER['REQUEST_TIME'] = $ts;
		$this->assertSame($expectedOut, OTP::TOTP($tok, array('digits' => strlen($expectedOut), 'algorithm' => $algo)));
	}

}
