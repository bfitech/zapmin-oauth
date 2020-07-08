<?php


namespace Demo;


/**
 * OAuthManage with profile fetcher and permission finetuning for
 * certain provider.
 */
class OAuthManage extends \BFITech\ZapAdmin\OAuthManage {

	private function fetch_profile_google($oauth_action) {
		# make request
		$fields = 'email,id,link,name';
		$resp = $oauth_action->request([
			'method' => 'GET',
			'url' => 'https://www.googleapis.com/userinfo/v2/me',
			'get' => [
				'fields' => $fields,
			],
			'expect_json' => true,
		]);
		if($resp[0] !== 200)
			return [];
		$data = $resp[1];

		# uname must exists
		if (!isset($data['id']))
			return [];
		$profile = ['uname' => $data['id']];

		# additional data
		foreach([
			'email' => 'email',
			'name' => 'fname',
			'link' => 'site',
		] as $oauth_key => $zap_key) {
			if (isset($data[$oauth_key]) && $data[$oauth_key])
				$profile[$zap_key] = $data[$oauth_key];
		}
		return $profile;
	}

	/**
	 * Fetch Github profile.
	 *
	 * @SuppressWarnings(PHPMD.CyclomaticComplexity)
	 * @SuppressWarnings(PHPMD.NPathComplexity)
	 */
	private function fetch_profile_github($oauth_action) {
		# github needs UA
		$headers = ['User-Agent: curl/7.47.0'];
		$resp = $oauth_action->request([
			'method' => 'GET',
			'url' => 'https://api.github.com/user',
			'headers' => $headers,
			'expect_json' => true,
		]);
		if($resp[0] !== 200)
			return [];
		$data = $resp[1];

		# uname must exists
		$profile = ['uname' => $data['login']];
		if (!isset($data['login']))
			return [];

		# additional data
		foreach([
			'name' => 'fname',
			'html_url' => 'site',
		] as $oauth_key => $zap_key) {
			if (isset($data[$oauth_key]) && $data[$oauth_key])
				$profile[$zap_key] = $data[$oauth_key];
		}

		# make request for primary email, see 'scope' on your
		# configuration
		$resp = $oauth_action->request([
			'method' => 'GET',
			'url' => 'https://api.github.com/user/emails',
			'headers' => $headers,
			'expect_json' => true,
		]);
		if ($resp[0] !== 200 || !is_array($resp[1]))
			return $profile;
		$data = $resp[1];

		$email = null;
		foreach ($data as $em) {
			if (!isset($em['email']))
				continue;
			$email = $em['email'];
			if (isset($em['primary']))
				break;
		}
		if ($email)
			$profile['email'] = $email;
		return $profile;
	}

	private function fetch_profile_twitter($oauth_action) {
		# make request
		$resp = $oauth_action->request([
			'method' => 'GET',
			'url' => 'https://api.twitter.com' .
					 '/1.1/account/verify_credentials.json',
			'expect_json' => true,
		]);
		if ($resp[0] !== 200 || !isset($resp[1]['screen_name']))
			return null;
		$data = $resp[1];

		$profile = [
			'uname' => $data['screen_name'],
			'site' => 'https://twitter.com/' . $data['screen_name'],
		];
		# additional data
		foreach([
			'name' => 'fname',
		] as $oauth_key => $zap_key) {
			if (isset($data[$oauth_key]) && $data[$oauth_key])
				$profile[$zap_key] = $data[$oauth_key];
		}
		return $profile;
	}

	/**
	 * Profile fetcher implementation.
	 *
	 * @SuppressWarnings(PHPMD.UnusedFormalParameter)
	 */
	public function fetch_profile(
		$oauth_action, $service_type, $service_name, $kwargs=[]
	) {
		if ($service_name == 'google')
			return $this->fetch_profile_google($oauth_action);
		if ($service_name == 'github')
			return $this->fetch_profile_github($oauth_action);
		if ($service_name == 'twitter')
			return $this->fetch_profile_twitter($oauth_action);
		return [];
	}

	public function finetune_permission($args, $perm) {
		# To obtain google refresh token, we need to provide
		# `access_type=offline&prompt=consent`.
		# See: http://archive.fo/L3bXg#selection-1259.0-1279.18
		if ($args['params']['service_name'] == 'google') {
			$perm->access_token_url_extra_params = [
				'access_type' => 'offline',
				'prompt' => 'consent',
			];
		}
		return $perm;
	}

}
