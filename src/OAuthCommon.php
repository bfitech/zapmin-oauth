<?php declare(strict_types=1);


namespace BFITech\ZapOAuth;


use BFITech\ZapCore\Common;


/**
 * OAuthCommon class.
 */
class OAuthCommon {

	/**
	 * Overloader.
	 */
	public function __call(string $method, array $args) {
		return call_user_func_array($this->$method, $args);
	}

	/**
	 * Nonce generator.
	 *
	 * @return int A random integer value.
	 */
	public static function generate_nonce() {
		return mt_rand();
	}

	/**
	 * Timestamp generator.
	 *
	 * @return int Current Unix timestamp
	 */
	public static function generate_timestamp() {
		return time();
	}

	/**
	 * HTTP client wrapper.
	 *
	 * Create method OAuthCommon::http_client_custom for custom HTTP
	 * client, e.g. for testing, with exact same arguments with
	 * Common::http_client.
	 *
	 * @param array $kwargs Request parameters.
	 * @return array A list of the form `[HTTP code, response body]`.
	 *     HTTP code is -1 for invalid method, 0 for failing connection,
	 *     and any of standard code for successful connection.
	 * @see BFITech\\ZapCore\\Common::http_client.
	 */
	public function http_client(array $kwargs) {
		if (
			isset($this->http_client_custom) &&
			is_callable($this->http_client_custom)
		)
			return $this->http_client_custom($kwargs);
		// @codeCoverageIgnoreStart
		return Common::http_client($kwargs);
		// @codeCoverageIgnoreEnd
	}

}
