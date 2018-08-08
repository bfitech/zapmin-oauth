<?php


require(__DIR__ . '/../../vendor/autoload.php');


use BFITech\ZapCommonDev\CommonDev;
use BFITech\ZapCore\Logger;
use BFITech\ZapCore\Router;
use BFITech\ZapStore\SQLite3;
use BFITech\ZapAdmin\OAuthRoute;


class OAuthRouteHTTP extends OAuthRoute {

	private function fetch_profile_google($oauth_action) {
		# make request
		$fields = 'id,displayName,emails,url';
		$resp = $oauth_action->request([
			'method' => 'GET',
			'url' => 'https://www.googleapis.com/plus/v1/people/me',
			'get' => [
				'fields' => $fields,
			],
			'expect_json' => true,
		]);
		if($resp[0] !== 200)
			return [];
		$data = $resp[1];

		# uname must exists
		$profile = ['uname' => $data['id']];
		if (!isset($data['id']))
			return [];

		# additional data
		if (isset($data['emails']) && is_array($data['emails'])) {
			foreach ($data['emails'] as $email) {
				if (!isset($email['value']))
					continue;
				$profile['email'] = $email['value'];
				break;
			}
		}
		foreach([
			'displayName' => 'fname',
			'url' => 'site',
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

$testdir = CommonDev::testdir(__DIR__);
$logger = new Logger(Logger::DEBUG, $testdir . '/zapmin-oauth.log');
$core = (new Router)->config('logger', $logger);
$store = new SQLite3(['dbname' => $testdir . '/zapmin-oauth.sq3'],
	$logger);
$adm = new OAuthRouteHTTP($store, $logger, null, $core);

# Make sure server config exists. Use sample for a quick start.

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

# NOTE: Make sure callback URLs in the configuration and on
# remote server match.

foreach ($config as $cfg)
	call_user_func_array([$adm, 'oauth_add_service'], $cfg);

$adm->route('/', function($args) use($adm) {
	require('home.php');
	die();
});
$adm->route('/status', [$adm, 'route_status'], 'GET');
$adm->route('/refresh', [$adm, 'route_refresh'], 'POST');
$adm->route('/logout', [$adm, 'route_logout'], ['GET', 'POST']);
$adm->route('/byway/oauth/<service_type>/<service_name>/auth',
	[$adm, 'route_byway_auth'], 'POST');
$adm->route('/byway/oauth/<service_type>/<service_name>/callback',
	[$adm, 'route_byway_callback'], 'GET');
$adm->route('/static/{path}', [$adm, 'route_static']);
