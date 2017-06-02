<?php


require_once(__DIR__ . '/OAuthFixture.php');


use PHPUnit\Framework\TestCase;
use BFITech\ZapCore\Logger;
use BFITech\ZapCoreDev\RouterDev;
use BFITech\ZapStore\SQLite3;
use BFITech\ZapStore\SQLError;
use BFITech\ZapAdmin\AdminRoute;
use BFITech\ZapAdmin\OAuthRoute;
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
		$oauth_action, $service_type, $service_name, $kwargs=[]
	) {
		return ServiceFixture::oauth_fetch_profile(
			$oauth_action, $service_type, $service_name, $kwargs);
	}

	public function oauth_finetune_permission($args, $perm) {
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

class OAuthRouteTest extends TestCase {

	public static $store;
	public static $logger;
	public static $core;

	public static function setUpBeforeClass() {
		self::$logger = new Logger(Logger::ERROR, '/dev/null');
		self::$store = new SQLite3(['dbname' => ':memory:'],
			self::$logger);
		self::$core = (new Router())->config('home', '/');
	}

	private function create_route_10() {

		$adm = new OAuthRoute10Patched(self::$store, self::$logger,
			null, self::$core);
		$adm->adm_set_token_name('testing');
		$adm->oauth_add_service(
			'10', 'tumblr',
			'test-consumer-key', 'test-consumer-secret',
			'http://tumblr.example.org/10/auth_request',
			'http://tumblr.example.org/10/auth',
			'http://tumblr.example.org/10/access',
			null, 'http://localhost'
		);
		$adm->oauth_add_service(
			'10', 'twitter',
			'test-consumer-key', 'test-consumer-secret',
			'http://twitter.example.org/10/auth_request',
			'http://twitter.example.org/10/auth',
			'http://twitter.example.org/10/access',
			null, 'http://localhost'
		);
		return $adm;
	}

	private function core_reinit() {
		self::$core->deinit()->reset();
		self::$core->config('home', '/');
	}

	private function create_route_20() {
		$adm = new OAuthRoute20Patched(self::$store, self::$logger,
			null, self::$core);
		$adm->adm_set_token_name('testing');
		$adm->oauth_add_service(
			'20', 'reddit',
			'test-consumer-key', 'test-consumer-secret',
			null,
			'http://reddit.example.org/20/auth',
			'http://reddit.example.org/20/access',
			'email', 'http://localhost'
		);
		return $adm;
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

		$adm = new OAuthRoute10Patched($store, $logger,
			null, $core);
		# deinit won't take effect on uninited instance
		$adm->deinit();
		# let's init
		$adm->init();

		# table just got installed with one default user
		$store->query("SELECT 1 FROM uoauth");

		# let's ruin default user from the db
		$store->update('udata', ['uname' => 'toor'],
			['uname' => 'root']);

		# recreate tables, including those installed by AdminStore
		$adm->deinit()
			->config('force_create_table', true)
			->init();

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

		$adm = $this->create_route_10();
		$adm->oauth_callback_fail_redirect = 'http://localhost/fail';
		$adm->oauth_callback_ok_redirect = null;
		$core = $adm->core;

		# invalid params
		$_SERVER['REQUEST_URI'] = '/';
		$adm->route('/', [$adm, 'route_byway_auth']);
		$this->assertEquals($core::$code, 404);
		$this->assertEquals($core::$body['errno'],
			OAuthError::INCOMPLETE_DATA);
		$this->core_reinit();

		# wrong route callback application
		$_SERVER['REQUEST_URI'] = '/oauth/wrong/url';
		$adm->route('/oauth/wrong/url',
			[$adm, 'route_byway_auth']);
		$this->assertEquals($core::$code, 404);
		$this->assertEquals($core::$body['errno'],
			OAuthError::INCOMPLETE_DATA);
		$this->core_reinit();

		# unregistered service
		$_SERVER['REQUEST_URI'] = '/oauth/10/vk/auth';
		$adm->route('/oauth/<service_type>/<service_name>/auth',
			[$adm, 'route_byway_auth']);
		$this->assertEquals($core::$code, 404);
		$this->assertEquals($core::$body['errno'],
			OAuthError::SERVICE_UNKNOWN);
		$this->core_reinit();

		# server/network error, see fixture
		$_SERVER['REQUEST_URI'] = '/oauth/10/tumblr/auth';
		$adm->route('/oauth/<service_type>/<service_name>/auth',
			[$adm, 'route_byway_auth']);
		$this->assertEquals($core::$code, 503);
		$this->assertEquals($core::$body['errno'],
			OAuthError::ACCESS_URL_MISSING);
		$this->core_reinit();

		# access token success
		$_SERVER['REQUEST_URI'] = '/oauth/10/twitter/auth';
		$adm->route('/oauth/<service_type>/<service_name>/auth',
			[$adm, 'route_byway_auth']);
		$this->assertEquals($core::$code, 200);
		$auth_url = $core::$body['data'];
		$this->assertEquals(0,
			strpos($auth_url, 'http://example.org/10/auth'));
		$this->core_reinit();

		# open access token URL
		$access = $adm->http_client([
			'method' => 'GET',
			'url' => $auth_url,
		]);
		$this->assertEquals($access[0], 200);
		$redir = $access[1];
		$this->assertEquals(0, strpos($redir, 'http://localhost'));
		# collect access tokens from URL
		parse_str(parse_url($redir)['query'], $received_qs);

		# failed authentication due to wrong query string
		$_SERVER['REQUEST_URI'] = '/oauth/10/twitter/callback';
		$_GET = ['wrong' => 'data'];
		$adm->route('/oauth/<service_type>/<service_name>/callback',
			[$adm, 'route_byway_callback']);
		# redirect to fail callback
		$this->assertEquals($core::$code, 301);
		$this->assertEquals(
			$this->get_redir_url($core::$head),
			$adm->oauth_callback_fail_redirect);
		$this->core_reinit();

		# failed authentication due to wrong service
		$_SERVER['REQUEST_URI'] = '/oauth/10/tumblr/callback';
		$_GET = $received_qs;
		$adm->route('/oauth/<service_type>/<service_name>/callback',
			[$adm, 'route_byway_callback']);
		# redirect to fail callback
		$this->assertEquals($core::$code, 301);
		$this->assertEquals(
			$this->get_redir_url($core::$head),
			$adm->oauth_callback_fail_redirect);
		$this->core_reinit();

		# successful authentication
		$_SERVER['REQUEST_URI'] = '/oauth/10/twitter/callback';
		$_GET = $received_qs;
		$adm->route('/oauth/<service_type>/<service_name>/callback',
			[$adm, 'route_byway_callback']);
		# redirect to ok callback
		$this->assertEquals($core::$code, 301);
		$this->assertEquals(
			$this->get_redir_url($core::$head),
			$adm->core->get_home());
		$this->core_reinit();

		# token is sent via cookie only, which is not available in
		# the test; let's pull it from database
		$session_token = $adm->store->query(
			"SELECT token FROM usess " .
			"ORDER BY sid DESC LIMIT 1")['token'];

		# use session token for signing in
		$adm->adm_set_user_token($session_token);
		$rv = $adm->adm_status();
		$this->assertEquals($rv['token'], $session_token);

		# token can be used to instantiate oauth action
		$act = $adm->oauth_get_action_from_session($session_token);
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

		$adm = $this->create_route_20();
		#$adm->oauth_callback_fail_redirect = 'http://localhost/fail';
		$adm->oauth_callback_ok_redirect = 'http://localhost/ok';
		$core = $adm->core;

		# invalid params
		$_SERVER['REQUEST_URI'] = '/';
		$adm->route('/', [$adm, 'route_byway_auth']);
		$this->assertEquals($core::$code, 404);
		$this->core_reinit();

		# unregistered service
		$_SERVER['REQUEST_URI'] = '/oauth/20/instagram/auth';
		$adm->route('/oauth/<service_type>/<service_name>/auth',
			[$adm, 'route_byway_auth']);
		$this->assertEquals($core::$code, 404);
		$this->assertEquals($core::$body['errno'],
			OAuthError::SERVICE_UNKNOWN);
		$this->core_reinit();

		# success
		$_SERVER['REQUEST_URI'] = '/oauth/20/reddit/auth';
		$adm->route('/oauth/<service_type>/<service_name>/auth',
			[$adm, 'route_byway_auth']);
		$this->assertEquals($core::$code, 200);
		$auth_url = $core::$body['data'];
		$this->assertSame(0,
			strpos($auth_url, 'http://reddit.example.org/20/auth'));
		$this->core_reinit();

		$access = $adm->http_client([
			'method' => 'GET',
			'url' => $auth_url,
		]);
		$this->assertEquals($access[0], 200);
		$redir = $access[1];
		$this->assertSame(0, strpos($redir, 'http://localhost'));

		parse_str(parse_url($redir)['query'], $received_qs);

		# wrong route callback application
		$_SERVER['REQUEST_URI'] = '/oauth/wrong/url';
		$adm->route('/oauth/wrong/url',
			[$adm, 'route_byway_callback']);
		$this->assertEquals($core::$code, 404);
		$this->core_reinit();

		# visiting invalid site callback
		$_SERVER['REQUEST_URI'] = '/oauth/20/google/callback';
		$adm->route('/oauth/<service_type>/<service_name>/callback',
			[$adm, 'route_byway_callback']);
		$this->assertEquals($core::$code, 404);
		$this->core_reinit();

		# failed authentication without redirect, shows abort(503)
		$_SERVER['REQUEST_URI'] = '/oauth/20/reddit/callback';
		$_GET = ['wrong' => 'data'];
		$adm->route('/oauth/<service_type>/<service_name>/callback',
			[$adm, 'route_byway_callback']);
		$this->assertEquals($core::$code, 503);
		$this->core_reinit();

		$_GET = $received_qs;
		$_SERVER['REQUEST_URI'] = '/oauth/20/reddit/callback';
		$adm->route('/oauth/<service_type>/<service_name>/callback',
			[$adm, 'route_byway_callback']);
		$this->assertEquals($core::$code, 301);
		$redir_local = explode(' ', array_filter($core::$head, function($ele){
			return strpos($ele, 'Location:') === 0;
		})[0])[1];
		$this->assertEquals($redir_local,
			$adm->oauth_callback_ok_redirect);
		$this->core_reinit();

		# token is sent via cookie only, which is not available in
		# the test; let's pull it from database
		$session_token = $adm->store->query(
			"SELECT token FROM usess " .
			"ORDER BY sid DESC LIMIT 1")['token'];

		# use session token for signing in
		$adm->adm_set_user_token($session_token);
		$rv = $adm->adm_status();
		$this->assertEquals($rv['token'], $session_token);

		$act = $adm->oauth_get_action_from_session($session_token);
		$rv = $act->request([
			'method' => 'GET',
			'url' => 'http://reddit.example.org/20/api/me',
		]);
		$this->assertEquals($rv[0], 200);
		extract(json_decode($rv[1], true));
		$this->assertEquals($fname, "John Smith");

	}

}
