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
			'site' => 'http://example.org',
		];
	}

	public static function oauth10($args) {
		extract($args);
		if ($method == 'POST') {
			# 1) auth request; not available in OAuth2
			if (self::is_in('/10/auth_request', $url)) {
				# response is urlencoded text
				return [200, http_build_query([
					'oauth_token' => 'token-' . mt_rand(),
					'oauth_token_secret' => 'token-secret',
					'oauth_callback_confirmed' => 'true',
				])];
			}
			# 3) access
			if (self::is_in('/10/access', $url)) {
				# response is urlencoded text
				return [200, http_build_query([
					'oauth_token' => 'access-token-' . mt_rand(),
					'oauth_token_secret' => 'access-token-secret',
				])];
			}
		}
		if ($method == 'GET') {
			# 2) auth
			if (self::is_in('/10/auth', $url)) {
				# response is redirect URL to callback uri
				return [200, 'http://localhost/?' . http_build_query([
					'oauth_token' => 'token-' . mt_rand(),
					'oauth_verifier' => 'token-verifier',
				])];
			}
			# 4) profile
			if (self::is_in('/10/api/me', $url)) {
				$has_bearer = array_filter($args['headers'], function($ele){
					return strpos($ele, 'OAuth') !== false;
				});
				if (!$has_bearer)
					return [403, null];
				# response is JSON
				return [200, json_encode(self::send_profile())];
			}
		}
	}

	public static function oauth20($args) {
		extract($args);
		if ($method == 'POST') {
			# 2) access, also used by refresh
			if (self::is_in('/20/access', $url)) {
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
			if (self::is_in('/20/auth', $url)) {
				# response is redirect URL to callback uri
				return [200, 'http://localhost/?' . http_build_query([
					'code' => 'token-' . mt_rand(),
					'state' => 'token-verifier',
				])];
			}
			# 3) profile
			if (self::is_in('/20/api/me', $url)) {
				$has_bearer = array_filter($args['headers'], function($ele){
					return strpos($ele, 'Bearer') !== false;
				});
				if (!$has_bearer)
					return [403, null];
				# response is JSON
				return [200, json_encode(self::send_profile())];
			}
		}
	}
}

