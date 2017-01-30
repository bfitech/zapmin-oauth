<?php


namespace BFITech\ZapOAuth;


class OAuthCommon {

	public static function generate_nonce() {
		return mt_rand();
	}

	public static function generate_timestamp() {
		return time();
	}

}

