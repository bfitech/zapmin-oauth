<?php


require_once(__DIR__ . '/OAuthFixture.php');


use PHPUnit\Framework\TestCase;
use BFITech\ZapCore\Logger;
use BFITech\ZapCoreDev\RouterDev;
use BFITech\ZapCoreDev\RoutingDev;
use BFITech\ZapStore\SQLite3;
use BFITech\ZapStore\SQLError;
use BFITech\ZapAdmin\Admin;
use BFITech\ZapAdmin\AuthCtrl;
use BFITech\ZapAdmin\AuthManage;
use BFITech\ZapAdmin\OAuthRoute;
use BFITech\ZapAdmin\OAuthStore;
use BFITech\ZapOAuth\OAuthCommon;
use BFITech\ZapOAuth\OAuthError;


class Router extends RouterDev {

	public static function send_cookie(
		$name, $value='', $expire=0, $path='', $domain='',
		$secure=false, $httponly=false
	) {
		// do nothing
	}

}

class OAuthRoutePatched extends OAuthRoute {

	public function oauth_fetch_profile(
		OAuthCommon $oauth_action,
		string $service_type, string $service_name, array $kwargs=[]
	) {
		return ServiceFixture::oauth_fetch_profile(
			$oauth_action, $service_type, $service_name, $kwargs);
	}

	public function oauth_finetune_permission(
		array $args, OAuthCommon $perm
	) {
		if ($args['params']['service_name'] == 'reddit') {
			$perm->auth_basic_for_site_callback = true;
			$perm->access_token_url_extra_params = [
				'response' => 'noop',
			];
		}
		return $perm;
	}

}

class OAuthRoute10Patched extends OAuthRoutePatched {

	public function http_client($kwargs) {
		return ServiceFixture::oauth10($kwargs);
	}

}

class OAuthRoute20Patched extends OAuthRoutePatched {

	public function http_client($kwargs) {
		return ServiceFixture::oauth20($kwargs);
	}

}

function testdir() {
	$dir = __DIR__ . '/testdata';
	if (!is_dir($dir))
		mkdir($dir, 0755);
	return $dir;
}

class OAuthRouteTest extends TestCase {

	public static $store;
	public static $logger;
	public static $core;

	public static function setUpBeforeClass() {
		// self::$logger = new Logger(Logger::ERROR, '/dev/null');
		$logfile = testdir() . '/zapmin-route.log';
		if (file_exists($logfile))
			unlink($logfile);
		self::$logger = new Logger(
			Logger::DEBUG, $logfile);

		self::$store = new SQLite3(['dbname' => ':memory:'],
			self::$logger);
		self::$core = (new Router())->config('home', '/');
	}

	private function create_route_10() {
		$admin = new Admin(self::$store, self::$logger);
		$admin
			->config('expire', 3600)
			->config('token_name', 'testing')
			->config('check_tables', true);
		$ctrl = new AuthCtrl($admin, self::$logger);
		$manage = new AuthManage($admin, self::$logger);
		$router = new OAuthRoute10Patched(self::$core, $ctrl, $manage);
		$router->oauth_add_service(
			'10', 'tumblr',
			'test-consumer-key', 'test-consumer-secret',
			'http://tumblr.example.org/10/auth_request',
			'http://tumblr.example.org/10/auth',
			'http://tumblr.example.org/10/access',
			null, 'http://localhost'
		);
		$router->oauth_add_service(
			'10', 'twitter',
			'test-consumer-key', 'test-consumer-secret',
			'http://twitter.example.org/10/auth_request',
			'http://twitter.example.org/10/auth',
			'http://twitter.example.org/10/access',
			null, 'http://localhost'
		);
		return $router;
	}

	private function create_route_20() {
		$admin = new Admin(self::$store, self::$logger);
		$admin
			->config('expire', 3600)
			->config('token_name', 'testing')
			->config('check_tables', true);
		$ctrl = new AuthCtrl($admin, self::$logger);
		$manage = new AuthManage($admin, self::$logger);
		$router = new OAuthRoute20Patched(self::$core, $ctrl, $manage);
		$router->oauth_add_service(
			'20', 'reddit',
			'test-consumer-key', 'test-consumer-secret',
			null,
			'http://reddit.example.org/20/auth',
			'http://reddit.example.org/20/access',
			'email', 'http://localhost'
		);
		return $router;
	}

	public function test_constructor() {
		$logger = new Logger(Logger::ERROR, '/dev/null');
		$store = new SQLite3(['dbname' => ':memory:'], $logger);
		$core = (new Router())
			->config('logger', $logger);

		$no_table = false;
		try {
			$store->query("SELECT 1 FROM uoauth");
		} catch(SQLError $e) {
			$no_table = true;
		}
		$this->assertTrue($no_table);

		$admin = new Admin($store, $logger);
		$admin
			->config('expire', 3600)
			->config('token_name', 'testing')
			->config('check_tables', true);
		$ctrl = new AuthCtrl($admin, $logger);
		$manage = new AuthManage($admin, $logger);
		$router = new OAuthRoute10Patched($core, $ctrl, $manage);

		// # deinit won't take effect on uninited instance
		// $router->deinit();
		// # let's init
		// $router->init();
		//
		// # table just got installed with one default user
		// $store->query("SELECT 1 FROM uoauth");
		//
		// # let's ruin default user from the db
		// $store->update('udata', ['uname' => 'toor'],
		// 	['uname' => 'root']);
		//
		// # recreate tables, including those installed by AdminStore
		// $router->deinit()
		// 	->config('force_create_table', true)
		// 	->init();

		$this->assertNotFalse(
			$store->query("SELECT uid FROM udata WHERE uname=?",
			['root']));
	}

	private function get_redir_url($heads) {
		$location_header = array_filter($heads, function($ele){
			return strpos($ele, 'Location:') === 0;
		}
		);
		if (!$location_header)
			return null;
		return explode(' ', $location_header[0])[1];
	}

	public function test_route_10() {

		$router = $this->create_route_10();
		$router->oauth_callback_fail_redirect = 'http://localhost/fail';
		$router->oauth_callback_ok_redirect = null;
		$core = $router::$core;
		$rdev = new RoutingDev($core);

		# invalid params
		$rdev->request('/');
		$router->route('/', [$router, 'route_byway_auth']);
		$this->assertEquals($core::$code, 404);
		$this->assertEquals($core::$body['errno'],
			OAuthError::INCOMPLETE_DATA);

		# wrong route callback application
		$rdev->request('/oauth/wrong/url');
		$router->route('/oauth/wrong/url',
			[$router, 'route_byway_auth']);
		$this->assertEquals($core::$code, 404);
		$this->assertEquals($core::$body['errno'],
			OAuthError::INCOMPLETE_DATA);

		# unregistered service
		$rdev->request('/oauth/10/vk/auth');
		$router->route('/oauth/<service_type>/<service_name>/auth',
			[$router, 'route_byway_auth']);
		$this->assertEquals($core::$code, 404);
		$this->assertEquals($core::$body['errno'],
			OAuthError::SERVICE_UNKNOWN);

		# server/network error, see fixture
		$rdev->request('/oauth/10/tumblr/auth');
		$router->route('/oauth/<service_type>/<service_name>/auth',
			[$router, 'route_byway_auth']);
		$this->assertEquals($core::$code, 503);
		$this->assertEquals($core::$body['errno'],
			OAuthError::ACCESS_URL_MISSING);

		# access token success
		$rdev->request('/oauth/10/twitter/auth');
		$router->route('/oauth/<service_type>/<service_name>/auth',
			[$router, 'route_byway_auth']);
		$this->assertEquals($core::$code, 200);
		$auth_url = $core::$body['data'];
		$this->assertEquals(0,
			strpos($auth_url, 'http://example.org/10/auth'));

		# open access token URL
		$access = $router->http_client([
			'method' => 'GET',
			'url' => $auth_url,
		]);
		$this->assertEquals($access[0], 200);
		$redir = $access[1];
		$this->assertEquals(0, strpos($redir, 'http://localhost'));
		# collect access tokens from URL
		parse_str(parse_url($redir)['query'], $received_qs);

		# failed authentication due to wrong query string
		$rdev->request('/oauth/10/twitter/callback', 'GET',
			['get' => ['wrong' => 'data']]);
		$router->route('/oauth/<service_type>/<service_name>/callback',
			[$router, 'route_byway_callback']);
		# redirect to fail callback
		$this->assertEquals($core::$code, 301);
		$this->assertEquals(
			$this->get_redir_url($core::$head),
			$router->oauth_callback_fail_redirect);

		# failed authentication due to wrong service
		$rdev->request('/oauth/10/tumblr/callback', 'GET',
			['get' => $received_qs]);
		$router->route('/oauth/<service_type>/<service_name>/callback',
			[$router, 'route_byway_callback']);
		# redirect to fail callback
		$this->assertEquals($core::$code, 301);
		$this->assertEquals(
			$this->get_redir_url($core::$head),
			$router->oauth_callback_fail_redirect);

		# successful authentication
		$rdev->request('/oauth/10/twitter/callback', 'GET',
			['get' => $received_qs]);
		$router->route('/oauth/<service_type>/<service_name>/callback',
			[$router, 'route_byway_callback']);
		# redirect to ok callback
		$this->assertEquals($core::$code, 301);
		$this->assertEquals(
			$this->get_redir_url($core::$head),
			$router::$core->get_home());

		# token is sent via cookie only, which is not available in
		# the test; let's pull it from database
		$session_token = $router::$ctrl::$admin::$store->query(
			"SELECT token FROM usess " .
			"ORDER BY sid DESC LIMIT 1")['token'];

		# use session token for signing in
		$router::$ctrl->set_token_value($session_token);
		$rv = $router::$ctrl->get_user_data();
		$this->assertEquals($rv['token'], $session_token);

		# token can be used to instantiate oauth action
		$act = $router->oauth_get_action_from_session($session_token);
		# action instance can be used to make requests
		$rv = $act->request([
			'method' => 'GET',
			'url' => 'http://twitter.example.org/10/api/me',
		]);
		$this->assertEquals($rv[0], 200);
		extract(json_decode($rv[1], true));
		$this->assertEquals($fname, "John Smith");
	}

	public function test_route_20() {

		$router = $this->create_route_20();
		#$router->oauth_callback_fail_redirect = 'http://localhost/fail';
		$router->oauth_callback_ok_redirect = 'http://localhost/ok';
		$core = $router::$core;
		$rdev = new RoutingDev($core);

		# invalid params
		$rdev->request('/');
		$router->route('/', [$router, 'route_byway_auth']);
		$this->assertEquals($core::$code, 404);

		# unregistered service
		$rdev->request('/oauth/20/instagram/auth');
		$router->route('/oauth/<service_type>/<service_name>/auth',
			[$router, 'route_byway_auth']);
		$this->assertEquals($core::$code, 404);
		$this->assertEquals($core::$body['errno'],
			OAuthError::SERVICE_UNKNOWN);

		# success
		$rdev->request('/oauth/20/reddit/auth');
		$router->route('/oauth/<service_type>/<service_name>/auth',
			[$router, 'route_byway_auth']);
		$this->assertEquals($core::$code, 200);
		$auth_url = $core::$body['data'];
		$this->assertSame(0,
			strpos($auth_url, 'http://reddit.example.org/20/auth'));

		$access = $router->http_client([
			'method' => 'GET',
			'url' => $auth_url,
		]);
		$this->assertEquals($access[0], 200);
		$redir = $access[1];
		$this->assertSame(0, strpos($redir, 'http://localhost'));

		parse_str(parse_url($redir)['query'], $received_qs);

		# wrong route callback application
		$rdev->request('/oauth/wrong/url');
		$router->route('/oauth/wrong/url',
			[$router, 'route_byway_callback']);
		$this->assertEquals($core::$code, 404);

		# visiting invalid site callback
		$rdev->request('/oauth/20/google/callback');
		$router->route('/oauth/<service_type>/<service_name>/callback',
			[$router, 'route_byway_callback']);
		$this->assertEquals($core::$code, 404);

		# failed authentication without redirect, shows abort(503)
		$rdev->request('/oauth/20/reddit/callback', 'GET', [
			'get' => ['wrong' => 'data']]);
		$router->route('/oauth/<service_type>/<service_name>/callback',
			[$router, 'route_byway_callback']);
		$this->assertEquals($core::$code, 503);

		$rdev->request('/oauth/20/reddit/callback', 'GET', [
			'get' => $received_qs]);
		$router->route('/oauth/<service_type>/<service_name>/callback',
			[$router, 'route_byway_callback']);
		$this->assertEquals($core::$code, 301);
		$redir_local = explode(
			' ', array_filter($core::$head, function($ele){
				return strpos($ele, 'Location:') === 0;
			})[0]
		)[1];
		$this->assertEquals($redir_local,
			$router->oauth_callback_ok_redirect);

		# token is sent via cookie only, which is not available in
		# the test; let's pull it from database
		$session_token = $router::$ctrl::$admin::$store->query(
			"SELECT token FROM usess " .
			"ORDER BY sid DESC LIMIT 1")['token'];

		# use session token for signing in
		$router::$ctrl->set_token_value($session_token);
		$rv = $router::$ctrl->get_user_data();
		$this->assertEquals($rv['token'], $session_token);

		$act = $router->oauth_get_action_from_session($session_token);
		$rv = $act->request([
			'method' => 'GET',
			'url' => 'http://reddit.example.org/20/api/me',
		]);
		$this->assertEquals($rv[0], 200);
		extract(json_decode($rv[1], true));
		$this->assertEquals($fname, "John Smith");

	}

}
