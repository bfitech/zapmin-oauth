<?php declare(strict_types=1);


namespace BFITech\ZapOAuth;


use BFITech\ZapCore\Common;
use BFITech\ZapCore\Logger;


/**
 * OAuth2.0 permission class.
 *
 * @if TRUE
 * @SuppressWarnings(PHPMD.LongVariable)
 * @endif
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
	private $callback_uri = null;
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
		string $client_id, string $client_secret,
		string $url_request_token_auth, string $url_access_token,
		string $callback_uri=null, string $scope=null
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

		# redirect_uri must be underneath callback_uri on github, but
		# can be anything, even multiple on google. Defaults to
		# $this->callback_uri.

		$url = $this->url_request_token_auth;
		$params = [
			'client_id' => $this->client_id,
			'scope' => $this->scope,
			'state' => static::generate_nonce(),
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
	 * Use this in
	 * BFITech.ZapAdmin.OAuthRouteDefault::route_byway_callback only.
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
	public function site_callback(array $get) {
		$redirect_uri = $this->callback_uri;

		$code = null;
		if (!Common::check_idict($get, ['code', 'state']))
			# We only check 'state' existence. We don't actually
			# match it with previously-generated one in auth page.
			return [OAuthError::INCOMPLETE_DATA, []];
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
			'state' => static::generate_nonce(),
		];

		$resp = $this->http_client([
			'url' => $url,
			'method' => 'POST',
			'headers' => $headers,
			'post' => $post,
			'expect_json' => true
		]);
		// @codeCoverageIgnoreStart
		if ($resp[0] !== 200)
			return [OAuthError::SERVICE_ERROR, []];
		// @codeCoverageIgnoreEnd

		# OAuth2.0 may send 'refresh_token' key. Services may add
		# various additional values, e.g. normalized scope for
		# Github. We'll only check 'access_token'.
		// @codeCoverageIgnoreStart
		if (!Common::check_idict($resp[1], ['access_token']))
			return [OAuthError::TOKEN_MISSING, []];
		// @codeCoverageIgnoreEnd

		# Store 'access_token' for later API calls.
		return [0, $resp[1]];
	}

}
