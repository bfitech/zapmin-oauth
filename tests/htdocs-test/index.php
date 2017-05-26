<?php


require(__DIR__ . '/../../vendor/autoload.php');


use BFITech\ZapCore\Logger;
use BFITech\ZapCore\Router;
use BFITech\ZapStore\SQLite3;
use BFITech\ZapAdmin\OAuthRoute;


class OAuthRouteHTTP extends OAuthRoute {
	public function oauth_fetch_profile(
		$oauth_action, $service_type, $service_name, $kwargs=[]
	) {
		if ($service_name == 'github') {
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

		if ($service_name == 'twitter') {
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
}

$logger = new Logger(Logger::DEBUG, __DIR__ . '/zapmin-oauth.log');
$core = (new Router)->config('logger', $logger);
$store = new SQLite3(['dbname' => __DIR__ . '/zapmin-oauth.sq3'], $logger);
$adm = new OAuthRouteHTTP($store, $logger, null, $core);

# Make sure server config exists. Use sample for a quick start.

$configfile = __DIR__ . '/config.json';
if (!is_file($configfile))
	die("Config not found.");
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
$adm->route('/logout', [$adm, 'route_logout'], ['GET', 'POST']);
$adm->route('/byway/oauth/<service_type>/<service_name>/auth',
	[$adm, 'route_byway_auth'], 'POST');
$adm->route('/byway/oauth/<service_type>/<service_name>/callback',
	[$adm, 'route_byway_callback'], 'GET');

