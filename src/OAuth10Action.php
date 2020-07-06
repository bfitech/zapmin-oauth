<?php declare(strict_types=1);


namespace BFITech\ZapOAuth;


use BFITech\ZapCore\Common;


/**
 * OAuth1.0 action class.
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
		string $consumer_key, string $consumer_secret,
		string $access_token, string $access_token_secret
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
	public function request(array $kwargs) {
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
