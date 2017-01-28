<?php


namespace BFITech\ZapOAuth;

use BFITech\OAuthCommon;


class OAuth10Permission extends OAuthCommon {

	private $consumer_key = null;
	private $consumer_secret = null;

	private $url_request_token = null;
	private $url_request_token_auth = null;
	private $url_access_token = null;

	private $url_callback = null;

	public function __construct(
		$consumer_key, $consumer_secret,
		$url_request_token, $url_request_token_auth,
		$url_access_token, $url_callback
	) {
		$this->consumer_key = $consumer_key;
		$this->consumer_secret = $consumer_secret;

		$this->url_request_token = $url_request_token;
		$this->url_request_token_auth = $url_request_token_auth;

		$this->url_access_token = $url_access_token;
		$this->url_callback = $url_callback;
	}

	/**
	 * Generate oauth_signature.
	 *
	 * @todo This deliberately disregards cross-referencing
	 *     nonce and timestamp.
	 */
	protected function generate_signature(
		$url, $method='GET', $extra_params=[],
		$with_token_secret=null
	) {
		$params = [
			'oauth_version' => '1.0',
			'oauth_nonce' => self::gen_nonce(),
			'oauth_timestamp' => self::gen_timestamp(),
			'oauth_consumer_key' => $this->consumer_key,
			'oauth_signature_method' => 'HMAC-SHA1',
		];
		// extra parameters, will override default params
		// if they collide
		foreach ($extra_params as $k => $v)
			$params[$k] = $v;

		$keys = array_map('rawurlencode', array_keys($params));
		$vals = array_map('rawurlencode', array_values($params));
		$params = array_combine($keys, $vals);
		ksort($params);

		/* base string */

		# method
		$bstr = $method . '&';
		# url
		$bstr .= rawurlencode($url) . '&';
		# params
		$pstr = [];
		foreach ($params as $k => $v)
			$pstr[] = $k . '=' . $v;
		$sparams = implode('&', $pstr);
		$bstr .= rawurlencode($sparams);

		/* signing */

		// signing key
		$skey = rawurlencode($this->consumer_secret) . '&';
		if ($with_token_secret)
			// blank for request token
			$skey .= rawurlencode($with_token_secret);

		// signature
		$signature = rawurlencode(base64_encode(
			hash_hmac('sha1', $bstr, $skey, true)));
		$params['oauth_signature'] = $signature;
		ksort($params);

		return $params;
	}

	/**
	 * Generate Authorization HTTP header.
	 */
	protected function generate_auth_header(
		$url, $method='GET', $extra_params=[],
		$with_token_secret=null
	) {
		$params = $this->generate_signature(
			$url, $method, $extra_params, $with_token_secret);
		$pstr = [];
		foreach ($params as $k => $v)
			$pstr[] = sprintf('%s="%s"', $k, $v);
		$astr = implode(', ', $pstr);
		return 'OAuth ' . $astr;
	}

	/**
	 * Get a request token from remote service.
	 *
	 * @return bool|array False on failure, otherwise dict with keys:
	 *   - oauth_token
	 *   - oauth_token_secret
	 *   - oauth_callback_confirmed which is set to string 'true'
	 */
	protected function request_token() {
		$auth_header = $this->generate_auth_header(
			$this->url_request_token, 'POST',
			['oauth_callback' => $this->url_callback]
		);
		$headers = [
			"Authorization: " . $auth_header,
			'Expect: ',
		];

		$resp = self::http_client(
			'POST', $this->url_request_token, $headers);
		if ($resp[0] !== 200)
			return false;

		parse_str($ret[1], $args);
		if (!self::check_dict([
			'oauth_token',
			'oauth_token_secret',
			'oauth_callback_confirmed'
		], $args))
			return false;
		if ($args['oauth_callback_confirmed'] != 'true')
			return false;

		return $args;
	}

	/**
	 * Get request token authentication URL.
	 *
	 * The URL will tell user to authorize the app in remote service. If user
	 * accepts, the URL will redirect to callback_url along with appropriate
	 * query string containing 'oauth_token' and 'oauth_verifier'.
	 *
	 * @param string $oauth_request_token The 'oauth_token' returned by
	 *     previous request_token().
	 */
	protected function authenticate_request_token($oauth_request_token) {
		return sprintf(
			'%s?oauth_token=%s',
			$this->url_request_token_auth,
			rawurlencode($oauth_request_token));
	}

	/**
	 * Get authentication URL.
	 *
	 * A chain of request_token() and authenticate_request_token().
	 * Use this in a route.
	 *
	 * @return string A URL that must be opened by client, typically in a
	 *     new window. After some UI actions, the window will load
	 *     url_callback that can be handled by site_callback().
	 */
	public function get_access_token_url() {
		$resp = $this->request_token();
		if (!$resp)
			return null;
		extract($resp, EXTR_SKIP);
		return $this->authenticate_request_token($oauth_token);
	}

	/**
	 *
	 * Site callback.
	 *
	 * Web only. Use this in a route.
	 *
	 * @param array $params Callback GET parameters sent by remote service,
	 *     must contain request token keys:
	 *         - oauth_token
	 *         - oauth_verifier
	 * @return array An array [errno, data], errno != 0 for failure. On
	 *     success, data must have access token keys:
	 *         - oauth_token
	 *         - oauth_token_secret
	 *     which should be saved for later use.
	 */
	public function site_callback($args) {

		$get = $args['get'];

		if (!self::check_dict([
			'oauth_token',
			'oauth_verifier'
		], $get))
			return [2];
		extract($get, EXTR_SKIP);

		$auth_header = $this->generate_auth_header(
			$this->url_access_token, 'POST',
			['oauth_token' => $oauth_token]
		);
		$headers = [
			#'Content-Type: application/x-www-form-urlencoded',
			'Authorization: ' . $auth_header,
			'Expect: ',
		];

		$post_data = http_build_query([
			'oauth_verifier' => $oauth_verifier,  # required by 1.0a
		]);
		$resp = self::http_client(
			'POST', $this->url_access_token,
			$headers, [], $post_data);

		if ($resp[0] !== 200)
			return [3];

		parse_str($resp[1], $args);
		if (false === $args = self::check_dict([
			'oauth_token',
			'oauth_token_secret',
		], $args))
			return [4];

		# save these two for later actions
		return [0, [
			'access_token' => $args['oauth_token'],
			'access_token_secret' => $args['oauth_token_secret'],
		]];
	}

}

class OAuth10Action extends OAuth10Permission {

	/**
	 * Generic authorized request wrapper.
	 *
	 * This is all we need to perform authorized operations. The URL,
	 * method and arguments depend on respective service.
	 *
	 * @param string $access_token User access token returned by
	 *     site_callback().
	 * @param string $access_token_secret User access token secret
	 *     returned by site_callback().
	 * @param string $method Request method.
	 * @param string $url The URL of the service.
	 * @param array $headers Custom header, e.g. user agent string
	 *     that's mandatory for certain services.
	 * @param array $get Query string dict.
	 * @param array $post Form data.
	 * @param bool $is_multipart Whether multipart MIME is to be sent.
	 * @param bool $expect_json Whether JSON response is to be
	 *     expected.
	 */
	public function request(
		$access_token, $access_token_secret, $method, $url,
		$headers=[], $get=[], $post=[],
		$is_multipart=false, $expect_json=false
	) {
		$auth_header = $this->generate_auth_header(
			$url, $method, ['oauth_token' => $access_token],
			$access_token_secret);
		$headers[] = "Authorization: " . $auth_header;
		$headers[] = "Expect: ";

		return self::http_client($method, $url, $headers, $get, $post,
			$is_multipart, $expect_json);
	}

}

