<?php


require_once(__DIR__ . '/OAuthFixture.php');


use PHPUnit\Framework\TestCase;
use BFITech\ZapCore\Logger;
use BFITech\ZapCoreDev\RouterDev;
use BFITech\ZapStore\SQLite3;
use BFITech\ZapStore\SQLError;
use BFITech\ZapAdmin\AdminRoute;
use BFITech\ZapAdmin\OAuthRoute;
use BFITech\ZapAdmin\OAuthError;


class Router extends RouterDev {
	public static function send_cookie(
		$name, $value='', $expire=0, $path='', $domain='',
		$secure=false, $httponly=false
	) {
		// do nothing
	}
}

class OAuthRoute10Patched extends OAuthRoute {
	public function http_client($kwargs) {
		return ServiceFixture::oauth10($kwargs);
	}
	public function oauth_fetch_profile(
		$oauth_action, $service_type, $service_name, $kwargs=[]
	) {
		if ($service_name != 'twitter')
			return [];
		return [
			'uname' => 'john',
			'fname' => 'John Smith',
			'email' => 'john@example.org',
			'site' => 'http://example.org',
		];
	}
}

class OAuthRoute20Patched extends OAuthRoute {
	public function http_client($kwargs) {
		return ServiceFixture::oauth20($kwargs);
	}
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
}

class OAuthRouteTest extends TestCase {

	private function create_route_10() {
		$logger = new Logger(Logger::ERROR, '/dev/null');
		$store = new SQLite3(['dbname' => ':memory:'], $logger);
		$core = new Router();

		$ocore = new OAuthRoute10Patched($store, $logger, null, $core);
		$ocore->adm_set_token_name('testing');
		$ocore->oauth_add_service(
			'10',
			'twitter',
			'test-consumer-key', 'test-consumer-secret',
			'http://example.org/10/auth_request',
			'http://example.org/10/auth',
			'http://example.org/10/access',
			null,
			'http://localhost'
		);
		return $ocore;
	}

	private function create_route_20() {
		$logger = new Logger(Logger::ERROR, '/dev/null');
		$store = new SQLite3(['dbname' => ':memory:'], $logger);
		$core = (new Router())->config('home', '/')
			->config('shutdown', false);

		$ocore = new OAuthRoute20Patched($store, $logger, null, $core);
		$ocore->adm_set_token_name('testing');
		$ocore->oauth_add_service(
			'20',
			'reddit',
			'test-consumer-key', 'test-consumer-secret',
			null,
			'http://example.org/20/auth',
			'http://example.org/20/access',
			'email',
			'http://localhost'
		);
		return $ocore;
	}

	public function test_constructor() {
		$logger = new Logger(Logger::ERROR, '/dev/null');
		$store = new SQLite3(['dbname' => ':memory:'], $logger);
		$core = new Router('/', null, false);

		$no_table = false;
		try {
			$store->query("SELECT 1 FROM uoauth");
		} catch(SQLError $e) {
			$no_table = true;
		}
		$this->assertTrue($no_table);

		$ocore = (new OAuthRoute10Patched($store, $logger,
			null, $core))->init();
		$store->query("SELECT 1 FROM uoauth");
		$store->update('udata', ['uname' => 'toor'],
			['uname' => 'root']);

		$this->assertFalse(
			$store->query("SELECT uid FROM udata WHERE uname=?",
			['root']));

		# recreate tables, including those installed by AdminStore
		$ocore->deinit()
			->config('force_create_table', true)
			->init();

		$this->assertNotFalse(
			$store->query("SELECT uid FROM udata WHERE uname=?",
			['root']));
	}

	public function test_route_10() {

		$_SERVER['REQUEST_URI'] = '/';

		# invalid params
		$ocore = $this->create_route_10();
		$ocore->route('/', [$ocore, 'route_byway_auth']);
		$core = $ocore->core;
		$this->assertEquals($core::$code, 404);
		$core->reset();

		# wrong route callback application
		$_SERVER['REQUEST_URI'] = '/oauth/wrong/url';
		$ocore = $this->create_route_10();
		$ocore->route('/oauth/wrong/url',
			[$ocore, 'route_byway_auth']);
		$core = $ocore->core;
		$this->assertEquals($core::$code, 404);

		# unregistered service
		$_SERVER['REQUEST_URI'] = '/oauth/10/tumblr/auth';
		$ocore = $this->create_route_10();
		$ocore->route('/oauth/<service_type>/<service_name>/auth',
			[$ocore, 'route_byway_auth']);
		$core = $ocore->core;
		$this->assertEquals($core::$code, 404);

		$_SERVER['REQUEST_URI'] = '/oauth/10/twitter/auth';
		$ocore = $this->create_route_10();
		$ocore->route('/oauth/<service_type>/<service_name>/auth',
			[$ocore, 'route_byway_auth']);
		$core = $ocore->core;
		$this->assertEquals($core::$code, 200);
		$auth_url = $core::$body['data'];
		$this->assertEquals(0,
			strpos($auth_url, 'http://example.org/10/auth'));

		$access = $ocore->http_client([
			'method' => 'GET',
			'url' => $auth_url,
		]);
		$this->assertEquals($access[0], 200);
		$redir = $access[1];
		$this->assertEquals(0, strpos($redir, 'http://localhost'));
		$core->reset();

		$purl = parse_url($redir);
		parse_str($purl['query'], $get);

		# failed authentication
		$_SERVER['REQUEST_URI'] = '/oauth/10/twitter/callback';
		$_GET = ['wrong' => 'data'];
		$ocore = $this->create_route_10();
		$ocore->oauth_callback_fail_redirect = 'http://localhost/fail';
		$ocore->route('/oauth/<service_type>/<service_name>/callback',
			[$ocore, 'route_byway_callback']);
		$core = $ocore->core;
		$this->assertEquals($core::$code, 301);

		$_GET = $get;
		$_SERVER['REQUEST_URI'] = '/oauth/10/twitter/callback';
		$ocore = $this->create_route_10();
		$ocore->oauth_callback_ok_redirect = 'http://localhost/ok';
		$ocore->route('/oauth/<service_type>/<service_name>/callback',
			[$ocore, 'route_byway_callback']);
		$core = $ocore->core;
		$this->assertEquals($core::$code, 301);
		$redir_local = explode(' ',
			array_filter($core::$head, function($ele){
				return strpos($ele, 'Location:') === 0;
			}
		)[0])[1];
		$this->assertEquals($redir_local,
			$ocore->oauth_callback_ok_redirect);

		# token is sent via cookie only, which is not available in
		# the test; let's pull it from database
		$session_token = $ocore->store->query(
			"SELECT token FROM usess " .
			"ORDER BY sid DESC LIMIT 1")['token'];

		# use session token for signing in
		$ocore->adm_set_user_token($session_token);
		$rv = $ocore->adm_status();
		$this->assertEquals($rv['token'], $session_token);

		$act = $ocore->oauth_get_action_from_session($session_token);
		$rv = $act->request([
			'method' => 'GET',
			'url' => 'http://example.org/10/api/me',
		]);
		$this->assertEquals($rv[0], 200);
		extract(json_decode($rv[1], true));
		$this->assertEquals($fname, "John Smith");
	}

	public function test_route_20() {

		$_SERVER['REQUEST_URI'] = '/';

		# invalid params
		$ocore = $this->create_route_20();
		$ocore->route('/', [$ocore, 'route_byway_auth']);
		$core = $ocore->core;
		$this->assertEquals($core::$code, 404);
		$core->reset();

		# unregistered service
		$_SERVER['REQUEST_URI'] = '/oauth/20/linkedin/auth';
		$ocore = $this->create_route_20();
		$ocore->route('/oauth/<service_type>/<service_name>/auth',
			[$ocore, 'route_byway_auth']);
		$core = $ocore->core;
		$this->assertEquals($core::$code, 404);

		$_SERVER['REQUEST_URI'] = '/oauth/20/reddit/auth';
		$ocore = $this->create_route_20();
		$ocore->route('/oauth/<service_type>/<service_name>/auth',
			[$ocore, 'route_byway_auth']);
		$core = $ocore->core;
		$this->assertEquals($core::$code, 200);
		$auth_url = $core::$body['data'];
		$this->assertEquals(0,
			strpos($auth_url, 'http://example.org/20/auth'));

		$access = $ocore->http_client([
			'method' => 'GET',
			'url' => $auth_url,
		]);
		$this->assertEquals($access[0], 200);
		$redir = $access[1];
		$this->assertEquals(0, strpos($redir, 'http://localhost'));
		$core->reset();

		$purl = parse_url($redir);
		parse_str($purl['query'], $get);

		# wrong route callback application
		$_SERVER['REQUEST_URI'] = '/oauth/wrong/url';
		$ocore = $this->create_route_20();
		$ocore->route('/oauth/wrong/url',
			[$ocore, 'route_byway_callback']);
		$core = $ocore->core;
		$this->assertEquals($core::$code, 404);

		# failed authentication
		$_SERVER['REQUEST_URI'] = '/oauth/20/reddit/callback';
		$_GET = ['wrong' => 'data'];
		$ocore = $this->create_route_20();
		$ocore->route('/oauth/<service_type>/<service_name>/callback',
			[$ocore, 'route_byway_callback']);
		$core = $ocore->core;
		$this->assertEquals($core::$code, 503);

		$_GET = $get;
		$_SERVER['REQUEST_URI'] = '/oauth/20/reddit/callback';
		$ocore = $this->create_route_20();
		$ocore->route('/oauth/<service_type>/<service_name>/callback',
			[$ocore, 'route_byway_callback']);
		$core = $ocore->core;
		$this->assertEquals($core::$code, 301);
		$redir_local = explode(' ', array_filter($core::$head, function($ele){
			return strpos($ele, 'Location:') === 0;
		})[0])[1];
		$this->assertEquals($redir_local, '/');

		# token is sent via cookie only, which is not available in
		# the test; let's pull it from database
		$session_token = $ocore->store->query(
			"SELECT token FROM usess " .
			"ORDER BY sid DESC LIMIT 1")['token'];

		# use session token for signing in
		$ocore->adm_set_user_token($session_token);
		$rv = $ocore->adm_status();
		$this->assertEquals($rv['token'], $session_token);

		$act = $ocore->oauth_get_action_from_session($session_token);
		$rv = $act->request([
			'method' => 'GET',
			'url' => 'http://example.org/20/api/me',
		]);
		$this->assertEquals($rv[0], 200);
		extract(json_decode($rv[1], true));
		$this->assertEquals($fname, "John Smith");
	}

}
