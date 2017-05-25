<?php


require(__DIR__ . '/../../vendor/autoload.php');


use BFITech\ZapCore\Logger;
use BFITech\ZapCore\Router;
use BFITech\ZapStore\SQLite3;
use BFITech\ZapAdmin\AdminRoute;
use BFITech\ZapAdmin\OAuthRoute;


class OAuthRouteHTTP extends OAuthRoute {
	public function oauth_fetch_profile(
		$oauth_action, $service_type, $service_name, $kwargs=[]
	) {
		if ($service_name != 'reddit')
			return [];
		return [
			'uname' => 'john',
			'fname' => 'John Smith',
			'email' => 'john@example.org',
			'site' => 'http://example.org',
		];
	}

	public function route_status($args) {
		$core = $this->core;
		$udata = $this->adm_status();
		if (!$udata)
			return $core::pj([1, []], 403);
		return $core::$pj([0, $udata]);
	}

	public function route_logout($args=null) {
		$core = $this->core;
		$udata = $this->adm_status();
		if (!$udata)
			return $core::pj([1, []], 403);
		$this->adm_logout();
		return $core::$pj([0, []]);
	}
}

$logger = new Logger(Logger::ERROR, __DIR__ . '/zapmin-oauth.log');
$core = new Router(null, null, true, $logger);
$store = new SQLite3(['dbname' => __DIR__ . '/zapmin-oauth.sq3'], $logger);
$acore = new AdminRoute($store, $logger, null, $core);
$ocore = new OAuthRouteHTTP($store, $logger, null, $core);


# Make sure server config exists. Use sample for a quick start.

$confl = __DIR__ . '/config.json';
if (!is_file($confl))
	die("Config not found.");
$config = json_decode(file_get_contents($confl));

# NOTE: Make sure callback URLs in the configuration and on
# remote server match.

foreach ($config as $cf)
	call_user_func_array([$ocore, 'oauth_add_service'], $cf);

$ocore->route('/', function($args) use($ocore) {
	require('home.php');
	die();
});
$ocore->route('/status', [$ocore, 'route_status'], 'GET');
$ocore->route('/logout', [$ocore, 'route_logout'], ['GET', 'POST']);
$ocore->route('/byway/oauth/<service_type>/<service_name>/auth',
	[$ocore, 'route_byway_auth'], 'POST');
$ocore->route('/byway/oauth/<service_type>/<service_name>/callback',
	[$ocore, 'route_byway_callback'], 'GET');

