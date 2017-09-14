<?php

namespace BFITech\ZapOAuth;

use BFITech\ZapCore\Common;

/**
 * OAuth1.0 class.
 *
 * @manonly
 * @SuppressWarnings(PHPMD.LongVariable)
 * @endmanonly
 */
class OAuth10Permission extends OAuthCommon {

	/** Consumer key. */
	protected $consumer_key = null;
	/** Consumer secret. */
	protected $consumer_secret = null;

	private $url_request_token = null;
	private $url_request_token_auth = null;
	private $url_access_token = null;
	private $url_callback = null;

	/**
	 * Constructor.
	 */
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
			'oauth_nonce' => self::generate_nonce(),
			'oauth_timestamp' => self::generate_timestamp(),
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

		# signing key
		$skey = rawurlencode($this->consumer_secret) . '&';
		if ($with_token_secret !== null)
			// blank for request token
			$skey .= rawurlencode($with_token_secret);
		# signature
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
	 *   - oauth_callback_confirmed which, a string set to 'true'
	 *   - oauth_verifier, optional
	 */
	private function request_token() {
		$auth_header = $this->generate_auth_header(
			$this->url_request_token, 'POST',
			['oauth_callback' => $this->url_callback]
		);
		$headers = [
			"Authorization: " . $auth_header,
			'Expect: ',
		];

		$resp = $this->http_client([
			'url' => $this->url_request_token,
			'method' => 'POST',
			'headers' => $headers
		]);
		if ($resp[0] !== 200)
			return false;

		parse_str($resp[1], $args);
		if (!Common::check_idict($args, [
			'oauth_token',
			'oauth_token_secret',
			'oauth_callback_confirmed'
		]))
			return false;
		if ($args['oauth_callback_confirmed'] != 'true')
			return false;
		return $args;
	}

	/**
	 * Get request token authentication URL.
	 *
	 * The URL will tell user to authorize the app in remote service.
	 * If user accepts, the URL will redirect to callback_url along
	 * with appropriate query string containing 'oauth_token' and
	 * 'oauth_verifier'.
	 *
	 * @param string $oauth_token The 'oauth_token' returned by
	 *     previous request_token().
	 * @param string|null $oauth_verifier The 'oauth_verifier' returned
	 *     by previous request_token(), if exists.
	 */
	private function authenticate_request_token(
		$oauth_token, $oauth_verifier=null
	) {
		$url = sprintf(
			'%s?oauth_token=%s',
			$this->url_request_token_auth,
			rawurlencode($oauth_token)
		);
		if ($oauth_verifier)
			$url .= '&oauth_verifier=' . rawurlencode($oauth_verifier);
		return $url;
	}

	/**
	 * Get authentication URL.
	 *
	 * A chain of request_token() and authenticate_request_token().
	 * Use this in a route.
	 *
	 * @return string A URL that must be opened by client, typically in
	 *     a new window. After some UI actions, the window will load
	 *     url_callback that can be handled by site_callback().
	 */
	public function get_access_token_url() {
		$oauth_token = $oauth_verifier = null;
		$resp = $this->request_token();
		if (!$resp)
			return null;
		extract($resp);
		return $this->authenticate_request_token(
			$oauth_token, $oauth_verifier);
	}

	/**
	 * Site callback.
	 *
	 * Receive request tokens from query string after successful
	 * redirect to callback URL, then use tokens to obtain access
	 * tokens from provider.
	 *
	 * Use this in OAuthRoute::route_byway_callback only.
	 *
	 * @param array $get Callback GET parameters sent by remote service
	 *     with keys:
	 *         - oauth_token
	 *         - oauth_verifier, OAuth1.0a only
	 * @return array An array `[errno, data]`, with `errno != 0` for
	 *     failure. On success, save these keys for later use:
	 *         - oauth_token
	 *         - oauth_token_secret
	 */
	public function site_callback($get) {

		$oauth_token = $oauth_verifier = null;
		if (!Common::check_idict($get, ['oauth_token']))
			return [OAuthError::INCOMPLETE_DATA, []];
		extract($get);

		$auth_header = $this->generate_auth_header(
			$this->url_access_token, 'POST',
			['oauth_token' => $oauth_token]
		);
		$headers = [
			'Content-Type: application/x-www-form-urlencoded',
			'Authorization: ' . $auth_header,
			'Expect: ',
		];

		$post_data = [];
		if ($oauth_verifier)
			# required by 1.0a
			$post_data['oauth_verifier'] = $oauth_verifier;

		$resp = $this->http_client([
			'url' => $this->url_access_token,
			'method' => 'POST',
			'headers' => $headers,
			'post' => $post_data,
			'expect_json' => false,
		]);
		// @codeCoverageIgnoreStart
		if ($resp[0] !== 200)
			return [OAuthError::SERVICE_ERROR, []];
		// @codeCoverageIgnoreEnd

		parse_str($resp[1], $args);
		// @codeCoverageIgnoreStart
		if (false === $args = Common::check_idict($args, [
			'oauth_token',
			'oauth_token_secret',
		]))
			return [OAuthError::TOKEN_MISSING, []];
		// @codeCoverageIgnoreEnd

		# save these two for later actions
		return [0, [
			'access_token' => $args['oauth_token'],
			'access_token_secret' => $args['oauth_token_secret'],
		]];
	}

}


/**
 * OAuth10Action class.
 */
class OAuth10Action extends OAuth10Permission {

	/** Access token. */
	protected $access_token = null;
	/** Access token secret. */
	protected $access_token_secret = null;

	/**
	 * Constructor.
	 *
	 * @param string $consumer_key Consumer key.
	 * @param string $consumer_secret Consumer secret.
	 * @param string $access_token User access token returned by
	 *     site_callback() or retrieved from some storage.
	 * @param string $access_token_secret User access token secret
	 *     returned by site_callback() or retrieved from storage.
	 */
	public function __construct(
		$consumer_key, $consumer_secret,
		$access_token, $access_token_secret
	) {
		$this->consumer_key = $consumer_key;
		$this->consumer_secret = $consumer_secret;
		$this->access_token = $access_token;
		$this->access_token_secret = $access_token_secret;
	}

	/**
	 * Generic authorized request wrapper.
	 *
	 * This is all we need to perform authorized operations. The URL,
	 * method and arguments depend on respective service. If URL
	 * contains query string, it will be appended to GET and the
	 * URL is rebuild without query string.
	 *
	 * @param array $kwargs Common::http_client kwargs parameter.
	 * @return array Standard return value of Common::http_client.
	 */
	public function request($kwargs) {
		if (!isset($kwargs['get']))
			$kwargs['get'] = [];
		$kwargs['get']['oauth_token'] = $this->access_token;

		$scheme = $host = $path = $query = null;
		$purl = parse_url($kwargs['url']);
		if (!Common::check_idict($purl, ['scheme', 'host', 'path']))
			return [-1, []];
		extract($purl);

		if ($query) {
			parse_str($query, $parsed_get);
			if ($parsed_get)
				$kwargs['get'] = array_merge($kwargs['get'],
					$parsed_get);
			$kwargs['url'] = sprintf('%s://%s%s', $scheme, $host,
				$path);
		}

		$auth_header = $this->generate_auth_header(
			$kwargs['url'], $kwargs['method'], $kwargs['get'],
			$this->access_token_secret
		);
		if (!isset($kwargs['headers']))
			$kwargs['headers'] = [];
		$kwargs['headers'][] = "Authorization: " . $auth_header;
		$kwargs['headers'][] = "Expect: ";
		return $this->http_client($kwargs);
	}

}
