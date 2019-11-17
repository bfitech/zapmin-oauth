<?php


use BFITech\ZapCore\Logger;
use BFITech\ZapStore\SQLite3;
use BFITech\ZapAdmin\Admin;
use BFITech\ZapAdmin\AuthCtrl;
use BFITech\ZapAdmin\OAuthManage;
use BFITech\ZapAdminDev\OAuthRouteDev;
use BFITech\ZapCoreDev\RouterDev;
use BFITech\ZapCoreDev\RoutingDev;
use BFITech\ZapOAuth\OAuthError;
use BFITech\ZapCoreDev\TestCase;


class OAuthRouteDevTest extends TestCase {

	public static $store;
	public static $logger;
	public static $core;

	public static function setUpBeforeClass() {
		self::$logger = new Logger(Logger::ERROR, '/dev/null');
		self::$store = new SQLite3(['dbname' => ':memory:'],
			self::$logger);
		self::$core = (new RouterDev())
			->config('home', '/')
			->config('logger', self::$logger);
	}

	private function create_route() {
		$admin = new Admin(self::$store, self::$logger);
		$admin
			->config('expire', 3600)
			->config('token_name', 'testing')
			->config('check_tables', true);
		$ctrl = new AuthCtrl($admin, self::$logger);
		$manage = new OAuthManage($admin, self::$logger);

		$manage->add_service(
			'10', 'twitter',
			'test-consumer-key', 'test-consumer-secret',
			'http://twitter.example.org/10/auth_request',
			'http://twitter.example.org/10/auth',
			'http://twitter.example.org/10/access',
			null, 'http://localhost'
		);
		$manage->add_service(
			'20', 'tumblr',
			'test-consumer-key', 'test-consumer-secret',
			'http://tumblr.example.org/10/auth_request',
			'http://tumblr.example.org/10/auth',
			'http://tumblr.example.org/10/access',
			null, 'http://localhost'
		);
		$manage->callback_ok_redirect = '/ok';
		return new OAuthRouteDev(self::$core, $ctrl, $manage);
	}

	public function test_fake_login() {
		extract(self::vars());

		$router = $this->create_route();
		$manage = $router::$manage;
		$core = $router::$core;
		$rdev = new RoutingDev($core);

		$rdev
			->request('/oauth/10/github/auth')
			->route('/oauth/<service_type>/<service_name>/auth',
				[$router, 'route_fake_login']);
		$eq($core::$code, 404);

		if (!defined('ZAPMIN_OAUTH_DEV'))
			define('ZAPMIN_OAUTH_DEV', 1);

		$pfail = function($_core) {
			$loc = array_filter($_core::$head, function($ele) {
				return strpos($ele, 'Location:') !== false;
			})[0];
			$loc = explode('?', $loc)[1];
			parse_str($loc, $out);
			$code = $out['code'] ?? -1;
			$errno = $out['errno'] ?? -1;
			return [$code, $errno];
		};

		$rdev
			->request('/oauth/10/github/auth')
			->route('/oauth/<service_type>/<service_name>/auth',
				[$router, 'route_fake_login']);
		list($code, $errno) = $pfail($core);
		$eq($code, 403);
		$eq($errno, OAuthError::INCOMPLETE_DATA);

		$rdev
			->request('/oauth/10/github/auth')
			->route('/oauth/<service_type>/github/auth',
				[$router, 'route_fake_login']);
		list($code, $errno) = $pfail($core);
		$eq($code, 404);
		$eq($errno, OAuthError::SERVICE_UNKNOWN);

		$rdev
			->request('/oauth/10/github/auth', 'GET',
				['get' => ['email' => 'me@github.io']])
			->route('/oauth/<service_type>/<service_name>/auth',
				[$router, 'route_fake_login']);
		list($code, $errno) = $pfail($core);
		$eq($code, 404);
		$eq($errno, OAuthError::SERVICE_UNKNOWN);

		$rdev
			->request('/oauth/10/github/auth', 'GET',
				['get' => ['email' => 'me+github.io']])
			->route('/oauth/<service_type>/<service_name>/auth',
				[$router, 'route_fake_login']);
		list($code, $errno) = $pfail($core);
		$eq($code, 403);
		$eq($errno, OAuthError::INCOMPLETE_DATA);

		$rdev
			->request('/oauth/20/tumblr/auth', 'GET',
				['get' => ['email' => 'me@github.io']])
			->route('/oauth/<service_type>/<service_name>/auth',
				[$router, 'route_fake_login']);
		list($code, $errno) = $pfail($core);
		$eq($code, 404);
		$eq($errno, OAuthError::SERVICE_UNKNOWN);

		$rdev
			->request('/oauth/20/tumblr/auth', 'GET',
				['get' => ['email' => 'me@tumblr.xyz']])
			->route('/oauth/<service_type>/<service_name>/auth',
				[$router, 'route_fake_login']);
		$eq($core::$code, 301);
		$eq($core::$head[0], 'Location: /ok');

		$rdev
			->request('/oauth/20/tumblr/auth', 'GET', [
				'get' => ['email' => 'me@tumblr.xyz']
			], [
				'testing' => $_COOKIE['testing'],
			])
			->route('/oauth/<service_type>/<service_name>/auth',
				[$router, 'route_fake_login']);
		$eq($core::$code, 401);

		$rdev
			->request('/status', 'GET', null, [
				'testing' => $_COOKIE['testing'],
			])
			->route('/status', [$router, 'route_fake_status']);
		$eq($core::$data['email'], 'me@tumblr.xyz');
	}
}
