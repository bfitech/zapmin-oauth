<?php


require_once(__DIR__ . '/OAuthFixture.php');
require_once(__DIR__ . '/RoutingDevPatched.php');


use BFITech\ZapCore\Logger;
use BFITech\ZapStore\SQLite3;
use BFITech\ZapStore\SQLError;
use BFITech\ZapAdmin\Admin;
use BFITech\ZapAdmin\AuthCtrl;
use BFITech\ZapAdmin\OAuthManage;
use BFITech\ZapAdmin\OAuthRouteDefault;
use BFITech\ZapOAuth\OAuthCommon;
use BFITech\ZapOAuth\OAuthError;
use BFITech\ZapCoreDev\TestCase;


/**
 * OAuthRouteDefault with mock http client.
 */
class OAuthRouteDefaultPatched extends OAuthRouteDefault {

	/** Service type, for fixture selection. */
	public static $service_type;

	/**
	 * Fake HTTP client.
	 *
	 * Not to be confused with OAuthManage::http_client_custom which is
	 * used internally by OAuth*{Action,Permission} classes. This is for
	 * simulating a workflow on the browser.
	 */
	public function fake_http_client($kwargs) {
		if (self::$service_type == '10')
			return ServiceFixture::oauth10($kwargs);
		return ServiceFixture::oauth20($kwargs);
	}

}

/**
 * OAuthManage with mock http client and other mock methods.
 */
class OAuthManagePatched extends OAuthManage {

	/** Service type, for fixture selection. */
	public static $service_type;

	/** Mock profile fetcher. */
	public function fetch_profile(
		OAuthCommon $oauth_action, string $service_type,
		string $service_name, array $kwargs=[]
	) {
		return ServiceFixture::fetch_profile(
			$oauth_action, $service_type, $service_name, $kwargs);
	}

	/** Mock HTTP client. */
	public function http_client_custom($kwargs) {
		if (self::$service_type == '10') {
			return ServiceFixture::oauth10($kwargs);
		}
		return ServiceFixture::oauth20($kwargs);
	}

	/** Permission finetune. */
	public function finetune_permission(
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

class OAuthRouteTest extends TestCase {

	public static $logger;
	public static $sql;

	public static function setUpBeforeClass() {
		$logfile = self::tdir(__FILE__) . '/zapmin-oauth-route.log';
		if (file_exists($logfile))
			unlink($logfile);
		self::$logger = new Logger(Logger::DEBUG, $logfile);
	}

	public function tearDown() {
		self::$sql = null;
		self::$logger->info("TEST DONE.");
	}

	/** Get redirect from list of response headers. */
	private function get_redir_url($heads) {
		$location_header = array_filter($heads, function($ele){
			return strpos($ele, 'Location:') === 0;
		});
		if (!$location_header)
			return null;
		return explode(' ', $location_header[0])[1];
	}

	private function make_dev_patched() {
		### RoutingDev instance. Renew every time after mock request is
		### complete. Do not reuse.
		$rdev = new RoutingDevPatched;

		$log = self::$logger;
		$core = $rdev::$core
			->config('home', '/')
			->config('logger', $log);

		### Renew database if null, typically after tearDown.
		if (!self::$sql)
			self::$sql = new SQLite3(['dbname' => ':memory:'], $log);

		### Admin instance.
		$admin = (new Admin(self::$sql, $log))
			->config('expire', 3600)
			->config('token_name', 'test-zapmin-oauth')
			->config('check_tables', true);

		### AuthCtrl instance.
		$ctrl = new AuthCtrl($admin, $log);

		### OAuthManage instance.
		$manage = (new OAuthManagePatched($admin, $log))
			->config('check_table', true)
			->init();
			#->init()->config('check_table', false);

		return [$rdev, $ctrl, $manage];
	}

	private function make_zcore_10() {
		list($rdev, $ctrl, $manage) = $this->make_dev_patched();
		$core = $rdev::$core;

		# Add services.
		$manage->add_service(
			'10', 'tumblr',
			'test-consumer-key', 'test-consumer-secret',
			'http://tumblr.example.org/10/auth_request',
			'http://tumblr.example.org/10/auth',
			'http://tumblr.example.org/10/access',
			null, 'http://localhost'
		);
		$manage->add_service(
			'10', 'twitter',
			'test-consumer-key', 'test-consumer-secret',
			'http://twitter.example.org/10/auth_request',
			'http://twitter.example.org/10/auth',
			'http://twitter.example.org/10/access',
			null, 'http://localhost'
		);
		$manage->callback_fail_redirect = 'http://localhost/fail';
		$manage::$service_type = '10';

		### OAuthRouteDefault instance.
		$zcore = new OAuthRouteDefaultPatched($core, $ctrl, $manage);
		$zcore::$service_type = '10';

		### Set $rdev::$zcore so we can do request-route chaining.
		$rdev::$zcore = $zcore;

		return [$zcore, $rdev, $core];
	}

	private function make_zcore_20() {
		list($rdev, $ctrl, $manage) = $this->make_dev_patched();
		$core = $rdev::$core;

		# Add service.
		$manage->add_service(
			'20', 'reddit',
			'test-consumer-key', 'test-consumer-secret',
			null,
			'http://reddit.example.org/20/auth',
			'http://reddit.example.org/20/access',
			'email', 'http://localhost'
		);
		$manage->callback_ok_redirect = 'http://localhost/ok';
		$manage::$service_type = '20';

		### OAuthRouteDefault instance.
		$zcore = new OAuthRouteDefaultPatched($core, $ctrl, $manage);
		$zcore::$service_type = '20';

		### Set $rdev::$zcore so we can do request-route chaining.
		$rdev::$zcore = $zcore;

		return [$zcore, $rdev, $core];
	}

	public function test_oauth_10() {
		extract(self::vars());

		# invalid params
		list($zcore, $rdev, $core) = $this->make_zcore_10();
		$rdev
			->request('/')
			->route('/', [$zcore, 'route_byway_auth']);
		$eq($core::$code, 404);
		$eq($core::$errno, OAuthError::INCOMPLETE_DATA);

		# wrong route callback application
		list($zcore, $rdev, $core) = $this->make_zcore_10();
		$rdev
			->request('/oauth/wrong/url')
			->route('/oauth/wrong/url', [$zcore, 'route_byway_auth']);
		$eq($core::$code, 404);
		$eq($core::$errno, OAuthError::INCOMPLETE_DATA);

		# unregistered service
		list($zcore, $rdev, $core) = $this->make_zcore_10();
		$rdev
			->request('/oauth/10/vk/auth')
			->route('/oauth/<service_type>/<service_name>/auth',
				[$zcore, 'route_byway_auth']);
		$eq($core::$code, 404);
		$eq($core::$errno, OAuthError::SERVICE_UNKNOWN);

		# server/network error, see fixture
		list($zcore, $rdev, $core) = $this->make_zcore_10();
		$rdev
			->request('/oauth/10/tumblr/auth')
			->route('/oauth/<service_type>/<service_name>/auth',
				[$zcore, 'route_byway_auth']);
		$eq($core::$code, 503);
		$eq($core::$errno, 	OAuthError::ACCESS_URL_MISSING);

		# access token success
		list($zcore, $rdev, $core) = $this->make_zcore_10();
		$rdev
			->request('/oauth/10/twitter/auth')
			->route('/oauth/<service_type>/<service_name>/auth',
				[$zcore, 'route_byway_auth']);
		$eq($core::$code, 200);
		$auth_url = $core::$body['data'];
		$eq(0, strpos($auth_url, 'http://example.org/10/auth'));

		# open access token URL
		$access = $zcore->fake_http_client([
			'method' => 'GET',
			'url' => $auth_url,
		]);
		$eq($access[0], 200);
		$redir = $access[1];
		$eq(0, strpos($redir, 'http://localhost'));
		# collect access tokens from URL
		parse_str(parse_url($redir)['query'], $received_qs);

		# failed authentication due to wrong query string
		list($zcore, $rdev, $core) = $this->make_zcore_10();
		$rdev
			->request('/oauth/10/twitter/callback', 'GET',
				['get' => ['wrong' => 'data']])
			->route('/oauth/<service_type>/<service_name>/callback',
				[$zcore, 'route_byway_callback']);
		# redirect to fail callback
		$eq($core::$code, 301);
		$eq($this->get_redir_url($core::$head),
			$zcore::$manage->callback_fail_redirect);

		# failed authentication due to wrong service
		list($zcore, $rdev, $core) = $this->make_zcore_10();
		$rdev
			->request('/oauth/10/tumblr/callback', 'GET',
				['get' => $received_qs])
			->route('/oauth/<service_type>/<service_name>/callback',
				[$zcore, 'route_byway_callback']);
		# redirect to fail callback
		$eq($core::$code, 301);
		$eq($this->get_redir_url($core::$head),
			$zcore::$manage->callback_fail_redirect);

		# successful authentication
		list($zcore, $rdev, $core) = $this->make_zcore_10();
		$rdev
			->request('/oauth/10/twitter/callback', 'GET',
				['get' => $received_qs])
			->route('/oauth/<service_type>/<service_name>/callback',
				[$zcore, 'route_byway_callback']);
		# redirect to ok callback
		$eq($core::$code, 301);
		$eq(
			$this->get_redir_url($core::$head),
			$zcore::$core->get_home());

		# token is sent via cookie
		$session_token = $_COOKIE['test-zapmin-oauth'];

		# use session token for retrieving user data
		$zcore::$ctrl->set_token_value($session_token);
		$rv = $zcore::$ctrl->get_user_data();
		$eq($rv['token'], $session_token);

		### token can be used to instantiate oauth action
		$act = $zcore::$manage->get_action_from_session($session_token);

		# action instance can be used to make requests
		$rv = $act->request([
			'method' => 'GET',
			'url' => 'http://twitter.example.org/10/api/me?q=1',
		]);
		$eq($rv[0], 200);
		extract(json_decode($rv[1], true));
		$eq($fname, "John Smith");
	}

	public function test_oauth_20() {
		extract(self::vars());

		# invalid params
		list($zcore, $rdev, $core) = $this->make_zcore_20();
		$rdev
			->request('/')
			->route('/', [$zcore, 'route_byway_auth']);
		$eq($core::$code, 404);

		# unregistered service
		list($zcore, $rdev, $core) = $this->make_zcore_20();
		$rdev
			->request('/oauth/20/instagram/auth')
			->route('/oauth/<service_type>/<service_name>/auth',
				[$zcore, 'route_byway_auth']);
		$eq($core::$code, 404);
		$eq($core::$body['errno'], OAuthError::SERVICE_UNKNOWN);

		# success
		list($zcore, $rdev, $core) = $this->make_zcore_20();
		$rdev
			->request('/oauth/20/reddit/auth')
			->route('/oauth/<service_type>/<service_name>/auth',
				[$zcore, 'route_byway_auth']);
		$eq($core::$code, 200);
		$auth_url = $core::$body['data'];
		$sm(0, strpos($auth_url, 'http://reddit.example.org/20/auth'));

		# open access token URL
		$access = $zcore->fake_http_client([
			'method' => 'GET',
			'url' => $auth_url,
		]);
		$eq($access[0], 200);
		$redir = $access[1];
		$sm(0, strpos($redir, 'http://localhost'));

		parse_str(parse_url($redir)['query'], $received_qs);

		# wrong route callback application
		list($zcore, $rdev, $core) = $this->make_zcore_20();
		$rdev
			->request('/oauth/wrong/url')
			->route('/oauth/wrong/url',
				[$zcore, 'route_byway_callback']);
		$eq($core::$code, 404);

		# visiting invalid site callback
		list($zcore, $rdev, $core) = $this->make_zcore_20();
		$rdev
			->request('/oauth/20/google/callback')
			->route('/oauth/<service_type>/<service_name>/callback',
				[$zcore, 'route_byway_callback']);
		$eq($core::$code, 404);

		# failed authentication without redirect, shows abort(503)
		list($zcore, $rdev, $core) = $this->make_zcore_20();
		$rdev
			->request('/oauth/20/reddit/callback', 'GET',
				['get' => ['wrong' => 'data']])
			->route('/oauth/<service_type>/<service_name>/callback',
				[$zcore, 'route_byway_callback']);
		$eq($core::$code, 503);

		# success
		list($zcore, $rdev, $core) = $this->make_zcore_20();
		$rdev
			->request('/oauth/20/reddit/callback', 'GET',
				['get' => $received_qs])
			->route('/oauth/<service_type>/<service_name>/callback',
				[$zcore, 'route_byway_callback']);
		$eq($core::$code, 301);
		$eq($this->get_redir_url($core::$head),
			$zcore::$manage->callback_ok_redirect);

		# token is sent via cookie
		$session_token = $_COOKIE['test-zapmin-oauth'];

		# use session token for retrieving user data
		$zcore::$ctrl->set_token_value($session_token);
		$rv = $zcore::$ctrl->get_user_data();
		$eq($rv['token'], $session_token);

		### token can be used to instantiate oauth action
		$act = $zcore::$manage->get_action_from_session($session_token);

		# use session token for mock action
		$rv = $act->request([
			'method' => 'GET',
			'url' => 'http://reddit.example.org/20/api/me',
		]);
		$eq($rv[0], 200);
		extract(json_decode($rv[1], true));
		$eq($fname, "John Smith");
	}

}
