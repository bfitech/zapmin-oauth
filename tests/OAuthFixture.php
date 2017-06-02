<?php


class ServiceFixture {

	public static function is_in($needle, $haystack) {
		return strpos($haystack, $needle) !== false;
	}

	private static function send_profile() {
		return [
			'uname' => 'john',
			'fname' => 'John Smith',
			'email' => 'john@example.net',
			'site' => [],  # intentionally made invalid
		];
	}

	/**
	 * Simulate provider HTTP response.
	 */
	public static function oauth10($args) {
		extract($args);
		$purl = parse_url($url);
		extract($purl);
		$service = explode('.', $host)[0];

		if ($method == 'POST') {
			# 1) auth request; not available in OAuth2
			if ($path == '/10/auth_request') {
				# response is urlencoded text in HTML body
				if ($service == 'twitter')
					# pass twitter
					return [200, http_build_query([
						'oauth_token' => 'token-' . mt_rand(),
						'oauth_token_secret' => 'token-secret',
						'oauth_callback_confirmed' => 'true',
						'oauth_verifier' => 'optional-verifier',
					])];
				# response is urlencoded text in HTML body
				if ($service == 'trakt')
					# pass trakt without oauth_verifier
					return [200, http_build_query([
						'oauth_token' => 'token-' . mt_rand(),
						'oauth_token_secret' => 'token-secret',
						'oauth_callback_confirmed' => 'true',
					])];
				if ($service == 'tumblr')
					# fail tumblr on 'oauth_callback_confirmed'
					return [200, http_build_query([
						'oauth_token' => 'token-' . mt_rand(),
						'oauth_token_secret' => 'token-secret',
						'oauth_callback_confirmed' => 'invalid',
					])];
				if ($service == 'trello')
					# fail trello with missing 'oauth_token'
					return [200, http_build_query([
						'oauth_token_secret' => 'token-secret',
					])];
				# fail anything else as provider/network error
				return [503, http_build_query([
					'opps' => 'fail'])];
			}
			# 3) access
			if ($path == '/10/access') {
				# response is urlencoded text
				return [200, http_build_query([
					'oauth_token' => 'access-token-' . mt_rand(),
					'oauth_token_secret' => 'access-token-secret',
				])];
			}
		}
		if ($method == 'GET') {
			# 2) auth
			if ($path == '/10/auth') {
				# response is redirect URL to callback uri
				if ($service == 'twitter')
					## pass twitter
					return [200, 'http://localhost/?' .
					http_build_query([
						'oauth_token' => 'token-' . mt_rand(),
						'oauth_verifier' => 'token-verifier',
					])];
				## fail anything else
				return [404, 'http://localhost/?fail'];
			}
			# 4) profile
			if ($path == '/10/api/me') {
				$has_bearer = array_filter($headers, function($ele){
					## incomplete OAuth1.0 request header
					return strpos($ele, 'OAuth') !== false;
				});
				# response is in JSON
				if (!$has_bearer)
					return [403, json_encode([])];
				if ($service == 'tumblr')
					## fail tumblr
					return [200, json_encode(['oops' => 'tumblr'])];
				if ($service == 'twitter')
					## pass twitter
					return [200, json_encode(self::send_profile())];
				## not found for anything else
				return [404, json_encode([])];
			}
		}
	}

	public static function oauth20($args) {
		extract($args);
		$purl = parse_url($url);
		extract($purl);
		$service = explode('.', $host)[0];

		if ($method == 'POST') {
			# 2) access, also used by refresh
			if ($path == '/20/access') {
				# response is JSON, but site_callback() internally
				# decodes it
				return [200, [
					'access_token' => 'access-' . mt_rand(),
					# optional
					'expires_in' => time() + 3600,
					'token_type' => 'bearer',
					'scope' => null,
					'refresh_token' => 'refresh-' . mt_rand(),
				]];
			}
		}
		if ($method == 'GET') {
			# 1) auth
			if ($path == '/20/auth') {
				# response is redirect URL to callback uri
				return [200, 'http://localhost/?' . http_build_query([
					'code' => 'token-' . mt_rand(),
					'state' => 'token-verifier',
				])];
			}
			# 3) profile
			if ($path == '/20/api/me') {
				$has_bearer = array_filter($headers, function($ele){
					return strpos($ele, 'Bearer') !== false;
				});
				if (!$has_bearer)
					return [403, null];
				if ($service == 'linkedin')
					## fail linkedin
					return [200, json_encode(['oops' => 'linkedin'])];
				if ($service == 'reddit')
					## pass reddit
					return [200, json_encode(self::send_profile())];
				## not found for anything else
				return [404, json_encode([])];
			}
		}
	}

	/**
	 * Simulate server profile fetcher.
	 */
	public static function oauth_fetch_profile(
		$oauth_action, $service_type, $service_name, $kwargs=[]
	) {
		$url = sprintf('http://%s.example.org/%s/api/me',
			$service_name, $service_type);
		$fixture_request = [
			'method' => 'GET',
			'url' => $url,
			'expect_json' => true,
		];
		# response is exactly the same with Common::http_client
		$fixture_response = $oauth_action->request($fixture_request);
		if (
			$fixture_response[0] != 200 ||
			!isset($fixture_response[1])
		) {
			return [];
		}
		# @fixme: Add expect_json switch to CommonDev::http_client
		# to avoid decoding like this
		$profile = json_decode($fixture_response[1], true);
		return $profile;
	}

}
