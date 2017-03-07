<?php


namespace BFITech\ZapOAuth;


/**
 * OAuthCommon class.
 */
class OAuthCommon {

	/**
	 * Nonce generator.
	 */
	public static function generate_nonce() {
		return mt_rand();
	}

	/**
	 * Timestamp generator.
	 */
	public static function generate_timestamp() {
		return time();
	}

}

