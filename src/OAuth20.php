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
	 * Add `Authorization: Basic XXX` to site callback. Probably needed
	 * by Yahoo, Reddit, LinkedIn.
	 */
	public $auth_basic_for_site_callback = false;

	/**
	 * Extra parameters for OAuth20Permission::get_access_token_url.
	 */
	public $access_token_url_extra_params = [];

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
	 * @return string Full URL that can be opened to obtain access
	 *     token.
	 */
	public function get_access_token_url() {

		# redirect_uri must be underneath callback_uri on github, but can
		# be anything, even multiple on google. Defaults to
		# $this->callback_uri.

		$url = $this->url_request_token_auth;
		$params = [
			'client_id' => $this->client_id,
			'scope' => $this->scope,
			'state' => self::generate_nonce(),
			'redirect_uri' => $this->callback_uri,
			'response_type' => 'code',
		];
		foreach ($this->access_token_url_extra_params as $key => $val)
			$params[$key] = $val;
		$url .= strstr($url, '?') === false ? '?' : '&';
		$url .= http_build_query($params);
		return $url;
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
	 * @param array $get Callback GET parameters sent by remote service,
	 *     with keys: `code` and `state`.
	 * @return array An array `[errno, data]`, with `errno != 0` for
	 *     failure. On success, data at least has key `access_token`
	 *     which should be saved for later use. Keys:
	 *         - `access_token`
	 *         - `refresh_token`, optional
	 *         - `expires_in`, optional, in seconds
	 *         - `token_type`, optional, typically 'bearer'
	 *         - `scope`, optional
	 */
	public function site_callback($get) {
		$logger = $this->logger;
		$redirect_uri = $this->callback_uri;

		if (!Common::check_idict($get, ['code', 'state'])) {
			# We only check 'state' existence. We don't actually
			# match it with previously-generated one in auth page.
			$msg = sprintf("Missing parameters: %s", 
				json_encode($get));
			$logger->error("OAuth: $msg");
			return [OAuthError::INCOMPLETE_DATA, []];
		}
		extract($get);

		$url = $this->url_access_token;

		$headers = [
			'Accept: application/json',
			'Content-Type: application/x-www-form-urlencoded',
			'Expect: ',
		];

		# Add optional Auth Basic header.
		if ($this->auth_basic_for_site_callback)
			$headers[] = 'Authorization: Basic ' . base64_encode(
				$this->client_id . ':' . $this->client_secret);

		# OAuth2.0 must use application/x-www-form-urlencoded. Github
		# accepts multipart/form-data, but Google doesn't. Hence
		# CURLOPT_POSTFIELDS must use http_build_query() instead of
		# plain array.
		# See: https://archive.fo/irKN0#selection-4679.0-4699.34
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
		// @codeCoverageIgnoreStart
		if ($resp[0] !== 200) {
			$msg = sprintf("Failed to verify token: %s", 
				json_encode($resp));
			$logger->error("OAuth: $msg");
			return [OAuthError::SERVICE_ERROR, []];
		}
		// @codeCoverageIgnoreEnd

		# OAuth2.0 may send 'refresh_token' key. Services may add
		# various additional values, e.g. normalized scope for
		# Github. We'll only check 'access_token'.
		// @codeCoverageIgnoreStart
		if (!Common::check_idict($resp[1], ['access_token'])) {
			$msg = sprintf("Missing token: %s", 
				json_encode($resp));
			$logger->error("OAuth: $msg");
			return [OAuthError::TOKEN_MISSING, []];
		}
		// @codeCoverageIgnoreEnd

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
	 * OAuth2.0 only needs `$access_token` being passed via query
	 * string or custom request header. Theoretically, the token is
	 * short-lived and must regularly be refreshed, which OAuth1.0
	 * doesn't need to.
	 *
	 * @param string $consumer_key Consumer key.
	 * @param string $consumer_secret Consumer secret. 
	 * @param string $access_token User access token returned by
	 *     OAuth20Permission::site_callback or retrieved from some
	 *     storage.
	 * @param string|null $refresh_token User refresh token returned by
	 *     OAuth20Permission::site_callback or retrieved from some
	 *     storage. Only required by OAuth20Action::refresh.
	 * @param string|null $url_access_token Access token authorization
	 *     URL. Only required by OAuth20Action::refresh.
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
	 * This lets a caller to do whatever it wants with a service,
	 * according to respective service API.
	 *
	 * @param array $kwargs http_client kwarg parameters. 
	 * @param bool $bearer If true, "Authorization: Bearer TOKEN"
	 *     request header is sent. Some services allow TOKEN sent via
	 *     GET.
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
	 * This will request a new access token given a refresh token.
	 * Not all providers provice this facility.
	 *
	 * @param bool $expect_json Whether JSON response is to be
	 *     expected.
	 * @param bool $bearer If true, 'Authorization: Bearer TOKEN' is
	 *     sent. Some services allow TOKEN sent via GET.
	 * @return array Standard Common::http_client retval. Additional
	 *     custom HTTP code: -2 := refresh token.
	 * @todo Untested on live service.
	 */
	public function refresh($expect_json=true, $bearer=true) {
		// @codeCoverageIgnoreStart
		if (!$this->refresh_token || !$this->url_access_token)
			return [-2, []];
		// @codeCoverageIgnoreEnd
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

