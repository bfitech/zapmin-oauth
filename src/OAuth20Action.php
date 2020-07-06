<?php declare(strict_types=1);


namespace BFITech\ZapOAuth;


use BFITech\ZapCore\Common;
use BFITech\ZapCore\Logger;


/**
 * OAuth2.0 action class.
 */
class OAuth20Action extends OAuthCommon {

	private $access_token = null;
	private $refresh_token = null;

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
		string $consumer_key, string $consumer_secret,
		string $access_token, string $refresh_token=null,
		string $url_access_token=null
	) {
		$this->consumer_key = $consumer_key;
		$this->consumer_secret = $consumer_secret;
		$this->access_token = $access_token;
		$this->refresh_token = $refresh_token;
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
	public function request(array $kwargs, bool $bearer=true) {
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
	public function refresh(bool $expect_json=true, bool $bearer=true) {
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
