<?php


require(__DIR__ . '/../../vendor/autoload.php');


use BFITech\ZapCore\Logger;
use BFITech\ZapCore\Router;
use BFITech\ZapStore\SQLite3;
use BFITech\ZapAdmin\Admin;
use BFITech\ZapAdmin\AuthCtrl;
use BFITech\ZapAdmin\AuthManage;
use BFITech\ZapAdmin\OAuthRoute;


function testdir() {
	$dir = __DIR__ . '/testdata';
	if (!is_dir($dir))
		mkdir($dir, 0755);
	return $dir;
}

class OAuthRouteHTTP extends OAuthRoute {

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

	public function oauth_finetune_permission($args, $perm) {
		# to obtain google refresh token, we needs to provide
		# `access_type=offline&prompt=consent`
		# see: http://archive.fo/L3bXg#selection-1259.0-1279.18
		if ($args['params']['service_name'] == 'google') {
			$perm->access_token_url_extra_params = [
				'access_type' => 'offline',
				'prompt' => 'consent',
			];
		}
		return $perm;
	}

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

	public function oauth_fetch_profile(
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

	public function route_home($args=null) {
		require('home.php');
		self::$core::halt();
	}

	public function route_status($args) {
		$core = $this->core;
		$udata = $this->adm_status();
		if (!$udata)
			return $core::pj([1, []], 403);
		return $core::pj([0, $udata]);
	}

	public function route_logout($args=null) {
		$core = $this->core;
		$udata = $this->adm_status();
		if (!$udata)
			return $core::pj([1, []], 403);
		$this->adm_logout();
		return $core::pj([0, []]);
	}

	public function route_refresh($args=null) {
		$core = $this->core;
		$udata = $this->adm_status();
		if (!$udata)
			return $core::pj([1, []], 403);
		$token = $udata['token'];
		$act = $this->oauth_get_action_from_session($token);
		$refresh_token = $act->refresh();

		// @todo: after refresh token?

		if (!$refresh_token)
			return $core::pj([1, []], 403);
		return $core::pj([0, $refresh_token]);
	}

	public function route_static($args) {
		return $this->core->static_file(
			__DIR__ . '/static/' . $args['params']['path']);
	}

}


class Web {

	public function __construct() {
		$adm = $this->prepare();

		foreach([
			['/', 'route_home'],
			['/status', 'route_status'],
			['/refresh', 'route_refresh', 'POST'],
			['/logout', 'route_logout', ['GET', 'POST']],
			['/byway/oauth/<service_type>/<service_name>/auth',
				'route_byway_auth', 'POST'],
			['/byway/oauth/<service_type>/<service_name>/callback',
				'route_byway_callback'],
			['/static/{path}', 'route_static']
		] as $route) {
			if (count($route) < 3)
				$route[] = 'GET';
			if (count($route) < 4)
				$route[] = false;
			$adm->route($route[0], [$adm, $route[1]],
				$route[2], $route[3]);
		}
	}

	private function prepare() {
		# environment

		$testdir = testdir();
		$logger = new Logger(
			Logger::DEBUG, $testdir . '/zapmin-oauth.log');
		$core = (new Router)->config('logger', $logger);
		$store = new SQLite3(
			['dbname' => $testdir . '/zapmin-oauth.sq3'], $logger);

		$admin = new Admin($store, $logger);
		$admin
			->config('expire', 3600)
			->config('token_name', 'testing')
			->config('check_tables', true);
		$ctrl = new AuthCtrl($admin, $logger);
		$manage = new AuthManage($admin, $logger);

		$adm = new OAuthRouteHTTP($core, $ctrl, $manage);

		# config

		$configfile = $testdir . '/config.json';
		if (!is_file($configfile)) {
			copy(__DIR__ . '/config.json-sample', $configfile);
			echo "<pre>";
			printf(
				"ERROR: Config not found.\n" .
				"       Default is copied to '%s'.\n" .
				"       Edit it to reflect your testing OAuth accounts.\n",
				$configfile);
			echo "<pre>";
			die();
		}
		$config = json_decode(file_get_contents($configfile));

		# add service

		# Make sure callback URLs in the configuration and on
		# remote server match.
		foreach ($config as $cfg)
			call_user_func_array([$adm, 'oauth_add_service'], $cfg);

		return $adm;
	}
}

new Web;
