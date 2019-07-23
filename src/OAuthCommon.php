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
	 * Use $this->http_client_custom for custom HTTP client or for
	 * testing, with exact same arguments with Common::http_client.
	 * @return array A list of the form `[HTTP code, response body]`.
	 *     HTTP code is -1 for invalid method, 0 for failing connection,
	 *     and any of standard code for successful connection.
	 */
	public function http_client(array $args) {
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
