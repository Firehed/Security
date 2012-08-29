<?php
use Firehed\Security\OTP;
require_once 'OTP.php';

class OTPTest extends PHPUnit_Framework_TestCase {

	// Test vectors provided by RFC 6238, Appendix B
	function vectors() {
		return array
		( array(         59, '94287082', 'sha1'  )
		, array(         59, '46119246', 'sha256')
		, array(         59, '90693936', 'sha512')
		, array( 1111111109, '07081804', 'sha1'  )
		, array( 1111111109, '68084774', 'sha256')
		, array( 1111111109, '25091201', 'sha512')
		, array( 1111111111, '14050471', 'sha1'  )
		, array( 1111111111, '67062674', 'sha256')
		, array( 1111111111, '99943326', 'sha512')
		, array( 1234567890, '89005924', 'sha1'  )
		, array( 1234567890, '91819424', 'sha256')
		, array( 1234567890, '93441116', 'sha512')
		, array( 2000000000, '69279037', 'sha1'  )
		, array( 2000000000, '90698825', 'sha256')
		, array( 2000000000, '38618901', 'sha512')
		, array(20000000000, '65353130', 'sha1'  )
		, array(20000000000, '77737706', 'sha256')
		, array(20000000000, '47863826', 'sha512')
		);
	}

	/**
	 * @dataProvider vectors
	 */
	function testOTP($ts, $expectedOut, $algo) {
		// Key is specified with test vectors 
		$tok = '12345678901234567890';
		$_SERVER['REQUEST_TIME'] = $ts;
		$this->assertSame($expectedOut, OTP::TOTP($tok, 30, 0, strlen($expectedOut)));
		// deal with algo
	}

}
