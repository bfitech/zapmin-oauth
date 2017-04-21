<?php


namespace BFITech\ZapOAuth;


use BFITech\ZapCore\Common;


/**
 * OAuthCommon class.
 */
class OAuthCommon {

	/**
	 * Overloader.
	 */
	public function __call($method, $args) {
		return call_user_func_array($this->$method, $args);
	}

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

	/**
	 * HTTP client wrapper.
	 *
	 * Use $this->http_client_custom for custom HTTP client or for
	 * testing, with exact same arguments with Common::http_client.
	 */
	public function http_client($args) {
		if (
			isset($this->http_client_custom) &&
			is_callable($this->http_client_custom)
		)
			return $this->http_client_custom($args);
		// @codeCoverageIgnoreStart
		return Common::http_client($args);
		// @codeCoverageIgnoreEnd
	}
}

