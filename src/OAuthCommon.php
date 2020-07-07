<?php declare(strict_types=1);


namespace BFITech\ZapOAuth;


use BFITech\ZapCore\Common;


/**
 * OAuthCommon class.
 *
 * Do not use this class and its subclasses directly. Use
 * BFITech.ZapAdmin.OAuthManage instead.
 */
class OAuthCommon {

	/**
	 * Allow monkey patching.
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
	 * HTTP client.
	 *
	 * This client is used by various OAuth internal operations.
	 * Overriding this doesn't make sense since this class and its
	 * subclasses OAuth*{Action,Permission} are never meant for
	 * userland.
	 *
	 * To override, e.g. for testing, create a method http_client_custom
	 * on the subclass of BFITech.ZapAdmin.OAuthManage, with the exact
	 * same args with those in Common::http_client.
	 *
	 * @param array $kwargs Request parameters.
	 * @return array A list of the form `[HTTP code, response body]`.
	 *     HTTP code is -1 for invalid method, 0 for failing connection,
	 *     and any of standard code for successful connection.
	 * @see Common::http_client
	 */
	final public function http_client(array $kwargs) {
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
