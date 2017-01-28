<?php


namespace BFITech\ZapOAuth;

use GuzzleHTTP\Client;


class OAuthCommon {

	public static function http_client(
		$method, $url, $headers=[], $get=[], $post=[],
		$is_multipart=false, $expect_json=false
	) {
		$client = new Client([
			'timeout' => 5,
		]);
		if ($method == 'GET') {
			$response = $client->requet('GET', $url, [
				'http_errors' => false,
				'headers' => $headers,
				'query' => $get,
			]);
		} elseif ($method == 'POST') {
			if ($get) {
				$url += strpos($url, '?') !== false ? '&' : '?';
				$url += http_build_query($get);
			}
			$post_key = $is_multipart ? 'multipart' : 'form_params';
			$response = $client->requet('POST', $url, [
				'http_errors' => false,
				'headers' => $headers,
				$post_key => $post,
			]);
		} else {
			return [-1, null];
		}
		return self::format_response($response);
	}

	public static function format_response(
		$response, $expect_json=true
	) {
		$code = $response->getStatusCode();
		$body = (string)$response->getBody(); 
		if ($expect_json)
			$body = json_decode($body, true);
		return [$code, $body];
	}

	public static function check_dict($array, $keys) {
		$checked = [];
		foreach ($keys as $key) {
			if (!isset($array[$key]))
				return false;
			$checked[$key] = $array[$key];
		}
		return $checked;
	}

	public static function generate_nonce() {
		return mt_rand();
	}

	public static function generate_timestamp() {
		return time();
	}

}

