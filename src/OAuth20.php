<?php


namespace BFITech\ZapOAuth;


use BFITech\ZapCore\Common;


/**
 * OAuth2.0 class.
 */
class OAuth20Permission extends OAuthCommon {

	/** Client ID, equivalent to consumer key in OAuth1.0. */
	protected $client_id = null;
	/** Client secret, equivalent to consumer secret in OAuth 1.0. */
	protected $client_secret = null;

	/** Token URL. */
	private $url_request_token_auth = null;
	/** Access token URL. */
	private $url_access_token = null;
	/** Callback URL. */
	private $url_callback = null;
	/** Scope. */
	private $scope = null;

	/**
	 * Constructor.
	 */
	public function __construct(
		$client_id, $client_secret,
		$url_request_token_auth, $url_access_token,
		$callback_uri, $scope
	) {
		$this->client_id = $client_id;
		$this->client_secret = $client_secret;
		$this->url_request_token_auth = $url_request_token_auth;
		$this->url_access_token = $url_access_token;
		$this->callback_uri = $callback_uri;
		$this->scope = $scope;
	}

	/**
	 * Get authentication URL.
	 *
	 * @param array $extra_params Additional parameters for the GET
	 *     request, may also override default values.
	 * @return string Full URL that can be used by client.
	 */
	public function get_access_token_url($extra_params=[]) {
		# Redirect_uri must be underneath callback_uri on github, but can
		# be anything, even multiple or google; defaults to
		# $this->callback_uri

		$url = $this->url_request_token_auth;
		$params = [
			'client_id' => $this->client_id,
			'scope' => $this->scope,
			'state' => self::generate_nonce(),
			'redirect_uri' => $this->callback_uri,
			'response_type' => 'code',
		];
		foreach ($extra_params as $key => $val)
			$params[$key] = $val;
		$url .= strstr($url, '?') === false ? '?' : '&';
		$url .= http_build_query($params);
		return $url;
	}

	/**
	 * Site callback.
	 *
	 * @param array $args Route arguments.
	 * @return array [errno, body] where errno == 0 on success.
	 */
	public function site_callback($args) {
		$redirect_uri = $this->callback_uri;

		$get = $args['get'];
		if (!Common::check_idict($get, ['code', 'state']))
			# We only check 'state' existence. We don't actually
			# match it with previously-generated one in auth page.
			return [2];
		extract($get);

		$url = $this->url_access_token;

		$headers = [
			'Accept: application/json', # get JSON
			'Content-Type: application/x-www-form-urlencoded',
			'Expect: ',
		];

		# Auth Basic hack for yahoo, reddit, linkedin
		# @fixme: Only tested on LinkedIn long time ago.
		foreach(['yahoo', 'reddit', 'linkedin'] as $srv) {
			if (strstr(substr($url, 0, 20), $srv) < 12) {
				$headers[] = 'Authorization: Basic ' . base64_encode(
					$this->client_id . ':' . $this->client_secret);
			}
		}

		# OAuth2.0 must use application/x-www-form-urlencoded. Github
		# accepts multipart/form-data, but Google doesn't. Hence
		# CURLOPT_POSTFIELDS must use http_build_query() instead of
		# plain array.
		# See: http://stackoverflow.com/a/29570240

		$post = [
			'client_id' => $this->client_id,
			'client_secret' => $this->client_secret,
			'code' => $code,
			'redirect_uri' => $redirect_uri,
			'grant_type' => 'authorization_code',
			'state' => self::generate_nonce(),
		];

		$resp = $this->http_client([
			'url' => $url,
			'method' => 'POST',
			'headers' => $headers,
			'post' => $post,
			'expect_json' => true
		]);
		if ($resp[0] !== 200)
			return [3];

		# windows stops here, they don't need access token
		#if (strstr($url, 'microsoftonline') !== false)
		#	return [0, $ret];

		# OAuth2.0 may send 'refresh_token' key. Every services may
		# add various additional values, e.g. normalized scope for
		# Github. We'll only check 'access_token'.
		if (!Common::check_idict($resp[1], ['access_token']))
			return [4];

		# Store 'access_token' for later API calls.
		return [0, $resp[1]];
	}
}


/**
 * OAuth20Action class.
 */
class OAuth20Action extends OAuthCommon {

	private $access_token = null;
	private $refresh_token = null;

	private $url_request_token_auth = null;

	/**
	 * Constructor.
	 *
	 * OAuth2.0 only needs $access_token that's passed via query string.
	 * Theoretically the token is short-lived and must regularly be
	 * refreshed, which OAuth1.0 doesn't need to.
	 *
	 * @param string $consumer_key Consumer key.
	 * @param string $consumer_secret Consumer secret. 
	 * @param string $access_token User access token returned by
	 *     site_callback() or retrieved from some storage.
	 * @param string $refresh_token User refresh token returned by
	 *     site_callback() or retrieved from some storage. Only required
	 *     by refresh().
	 * @param string $url_access_token Access token authorization URL
	 *     as in Oauth20Permission. Only required by refresh().
	 */
	public function __construct(
		$consumer_key, $consumer_secret,
		$access_token, $refresh_token=null,
		$url_access_token=null
	) {
		$this->consumer_key = $consumer_key;
		$this->consumer_secret = $consumer_secret;
		$this->access_token = $access_token;
		$this->refresh_token = $access_token;
		$this->url_access_token = $url_access_token;
	}
	
	/**
	 * Generic authorized request wrapper.
	 *
	 * This completely lets a caller to do whatever it wants with
	 * access token since each service use it differently.
	 *
	 * @param array $kwargs http_client kwarg parameters. 
	 * @param bool $bearer If true, 'Authorization: Bearer TOKEN' is
	 *     sent. Some services allow TOKEN sent via GET.
	 */
	public function request($kwargs, $bearer=true) {
		if (!isset($kwargs['headers']))
			$kwargs['headers'] = [];
		if ($bearer)
			$kwargs['headers'][] = 'Authorization: Bearer ' .
				$this->access_token;
		if (isset($kwargs['expect_json']) && $kwargs['expect_json']) {
			$kwargs['headers'][] = 'Accept: application/json';
			$kwargs['headers'][] = 'Expect: ';
		}
		return $this->http_client($kwargs);
	}

	/**
	 * Refresh token.
	 *
	 * @param bool $expect_json Whether JSON response is to be
	 *     expected.
	 * @param bool $bearer If true, 'Authorization: Bearer TOKEN' is
	 *     sent. Some services allow TOKEN sent via GET.
	 * @todo Untested on live service.
	 */
	public function refresh($expect_json=true, $bearer=true) {
		if (!$this->refresh_token || !$this->url_access_token)
			return null;
		$headers = ['Content-Type: application/x-www-form-urlencoded'];
		if ($bearer)
			$headers[] = 'Authorization: Bearer ' . $this->access_token;
		if ($expect_json) {
			$headers[] = 'Accept: application/json';
			$headers[] = 'Expect: ';
		}
		return $this->http_client([
			'method' => "POST",
			'url' => $this->url_access_token,
			'headers' => $headers,
			'post' => [
				'client_id' => $this->consumer_key,
				'client_secret' => $this->consumer_secret,
				'refresh_token' => $this->refresh_token,
				'grant_type' => 'refresh_token',
			],
			'expect_json' => $expect_json,
		]);
	}

}

