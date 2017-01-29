<?php


namespace BFITech\ZapOAuth;


class OAuthCommon {

	public static function http_client(
		$method, $url, $headers=[], $get=[], $post=[], $expect_json=false
	) {
		$conn = curl_init();
		curl_setopt($conn, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($conn, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($conn, CURLOPT_CONNECTTIMEOUT, 16);
		curl_setopt($conn, CURLOPT_TIMEOUT, 16);
		curl_setopt($conn, CURLOPT_FOLLOWLOCATION, true);
		curl_setopt($conn, CURLOPT_MAXREDIRS, 8);
		curl_setopt($conn, CURLOPT_HEADER, false);
		curl_setopt($conn, CURLOPT_HTTPHEADER, $headers);

		if ($get) {
			$url .= strpos($url, '?') !== false ? '&' : '?';
			$url .= http_build_query($get);
		}
		curl_setopt($conn, CURLOPT_URL, $url);

		if ($method == 'GET') {
			# noop
		} elseif ($method == 'POST') {
			curl_setopt($conn, CURLOPT_CUSTOMREQUEST, 'POST');
			curl_setopt($conn, CURLOPT_POSTFIELDS, http_build_query($post));
		} else {
			# only GET and POST for now
			return [-1, null];
		}

		$body = curl_exec($conn);
		$info = curl_getinfo($conn);
		curl_close($conn);
		if ($expect_json)
			$body = @json_decode($body, true);
		return [$info['http_code'], $body];
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

