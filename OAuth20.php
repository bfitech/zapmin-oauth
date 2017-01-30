<?php


namespace BFITech\ZapOAuth;

use BFITech\ZapCore as zc;


class OAuth20Permission extends OAuthCommon {

	private $client_id = null;        # consumer key in 1.0
	private $client_secret = null;    # consumer secret in 1.0

	private $url_request_token_auth = null;
	private $url_access_token = null;

	private $url_callback = null;

	private $scope = null;

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
	 * @params array $args Route arguments.
	 * @params string $redirect_uri Redirect URI, or $this->callback_uri
	 *     if left null.
	 * @return array [errno, body] where errno == 0 on success.
	 */
	public function site_callback($args) {
		$redirect_uri = $this->callback_uri;

		$get = $args['get'];
		if (!zc\Common::check_dict($get, ['code', 'state']))
			# We only check 'state' existence. We don't actually
			# match it with previously-generated one in auth page.
			return [2];
		extract($get, EXTR_SKIP);

		$url = $this->url_access_token;

		$headers = [
			'Accept: application/json', # get JSON
			'Content-Type: application/x-www-form-urlencoded',
			'Expect: ',
		];

		# Auth Basic hack for yahoo, reddit, linkedin
		foreach(['yahoo', 'reddit', 'linkedin'] as $srv) {
			if (strstr(substr($url, 0, 20), $srv) !== false) {
				$headers[] = 'Authorization: Basic ' . base64_encode(
					$this->client_id . ':' . $this->client_secret);
			}
		}

		# OAuth2.0 must use application/x-www-form-urlencoded. Github
		# accepts multipart/form-data, but Google doesn't. Hence
		# CURLOPT_POSTFIELDS must use http_build_query() instead of
		# plain array. Guzzle wrapper already handles this.
		# See: http://stackoverflow.com/a/29570240

		$post = [
			'client_id' => $this->client_id,
			'client_secret' => $this->client_secret,
			'code' => $code,
			'redirect_uri' => $redirect_uri,
			'grant_type' => 'authorization_code',
			'state' => self::generate_nonce(),
		];

		$resp = zc\Common::http_client([
			'url' => $url,
			'method' => 'POST',
			'headers' => $headers,
			'post' => $post,
			'expect_json' => true
		]);
		if ($resp[0] !== 200)
			return [3];

		# windows stops here, they don't need access token
		if (strstr($url, 'microsoftonline') !== false)
			return [0, $ret];

		# Services may add various additional values, e.g. normalized
		# scope for Github, expires_in on Google, etc. We'll only
		# check these.
		$checked = zc\Common::check_dict($resp[1], ['access_token']);
		if (!$checked)
			return [4];

		# Store 'access_token' for later API calls.
		return [0, $resp[1]];
	}
}

class OAuth20Action {

	/**
	 * Generic authorized request wrapper.
	 *
	 * @param string $access_token Previously-obtained access token.
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
	public static function request(
		$access_token, $method, $url, $headers=[], $get=[], $post=[],
		$expect_json=false
	) {
		$headers = [
			'Accept: application/json',
			'Expect: ',
		];
		# github style, only github accepts this
		// $headers[] = sprintf('Authorization: token %s', $access_token);
		$get[] = ['access_token' => $access_token];
		return zc\Common::http_client($url, $method, $headers,
			$get, $post, $expect_json);
	}
}

