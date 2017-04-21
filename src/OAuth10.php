<?php


namespace BFITech\ZapOAuth;


use BFITech\ZapCore\Common;


/**
 * OAuth1.0 class.
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
	 * @param string|null $oauth_verifier The 'oauth_verifier' returned by
	 *     previous request_token(), if exists.
	 */
	protected function authenticate_request_token(
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
		$resp = $this->request_token();
		if (!$resp)
			return null;
		extract($resp, EXTR_SKIP);
		if (!isset($oauth_token))
			return null;
		if (!isset($oauth_verifier))
			$oauth_verifier = null;
		return $this->authenticate_request_token(
			$oauth_token, $oauth_verifier);
	}

	/**
	 *
	 * Site callback.
	 *
	 * Web only. Use this in a route.
	 *
	 * @param array $args Callback GET parameters sent by remote service,
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

		if (!Common::check_idict($get, ['oauth_token']))
			return [2];
		extract($get, EXTR_SKIP);

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
		if (isset($get['oauth_verifier'])) {
			# required by 1.0a
			$post_data['oauth_verifier'] = $oauth_verifier;
		}

		$resp = $this->http_client([
			'url' => $this->url_access_token,
			'method' => 'POST',
			'headers' => $headers,
			'post' => $post_data
		]);
		if ($resp[0] !== 200)
			return [3];

		parse_str($resp[1], $args);
		if (false === $args = Common::check_idict($args, [
			'oauth_token',
			'oauth_token_secret',
		]))
			return [4];

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
	 * method and arguments depend on respective service.
	 *
	 * @param array $kwargs http_client kwargs parameter. 
	 * @todo This won't stop $kwargs['url'] from having query
	 *     string. It must be isolated in $kwargs['get'] and fed
	 *     to extra params of $this->generate_auth_header() so
	 *     it will generate valid base string. URL with query
	 *     string will fail the signing.
	 */
	public function request($kwargs) {
		if (!Common::check_idict($kwargs, ['method', 'url']))
			return [-1, null];
		$bstr_raw = ['oauth_token' => $this->access_token];
		if (isset($kwargs['get']) && $kwargs['get'])
			$bstr_raw = array_merge($bstr_raw, $kwargs['get']);
		$auth_header = $this->generate_auth_header(
			$kwargs['url'], $kwargs['method'], $bstr_raw,
			$this->access_token_secret
		);
		if (!isset($kwargs['headers']))
			$kwargs['headers'] = [];
		$kwargs['headers'][] = "Authorization: " . $auth_header;
		$kwargs['headers'][] = "Expect: ";
		return $this->http_client($kwargs);
	}

}

