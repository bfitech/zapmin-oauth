<?php


use PHPUnit\Framework\TestCase;
use BFITech\ZapCore\Logger;
use BFITech\ZapStore\SQLite3;
use BFITech\ZapAdmin\Admin;
use BFITech\ZapAdmin\AuthCtrl;
use BFITech\ZapAdmin\AuthManage;
use BFITech\ZapAdminDev\OAuthRouteDev;
use BFITech\ZapCoreDev\RouterDev;
use BFITech\ZapCoreDev\RoutingDev;
use BFITech\ZapOAuth\OAuthError;


class OAuthRouteDevTest extends TestCase {

	public static $store;
	public static $logger;
	public static $core;

	public static function setUpBeforeClass() {
		self::$logger = new Logger(Logger::ERROR, '/dev/null');
		self::$store = new SQLite3(['dbname' => ':memory:'],
			self::$logger);
		self::$core = (new RouterDev())->config('home', '/');
	}

	private function create_route() {
		$store = new SQLite3(
			['dbname' => ':memory:'], self::$logger);
		$core = (new RouterDev())
			->config('logger', self::$logger);
		$admin = new Admin($store, self::$logger);
		$admin
			->config('expire', 3600)
			->config('token_name', 'testing')
			->config('check_tables', true);
		$ctrl = new AuthCtrl($admin, self::$logger);
		$manage = new AuthManage($admin, self::$logger);
		$adm = new OAuthRouteDev($core, $ctrl, $manage);

		// $adm->adm_set_token_name('testing');
		$adm->oauth_add_service(
			'10', 'twitter',
			'test-consumer-key', 'test-consumer-secret',
			'http://twitter.example.org/10/auth_request',
			'http://twitter.example.org/10/auth',
			'http://twitter.example.org/10/access',
			null, 'http://localhost'
		);
		$adm->oauth_add_service(
			'20', 'tumblr',
			'test-consumer-key', 'test-consumer-secret',
			'http://tumblr.example.org/10/auth_request',
			'http://tumblr.example.org/10/auth',
			'http://tumblr.example.org/10/access',
			null, 'http://localhost'
		);
		$adm->oauth_callback_ok_redirect = '/ok';
		return $adm;
	}

	public function test_fake_login() {
		$adm = $this->create_route();
		$core = $adm::$core;
		$rdev = new RoutingDev($core);

		$rdev->request('/oauth/10/github/auth');
		$adm->route('/oauth/<service_type>/<service_name>/auth',
			[$adm, 'route_fake_login']);
		$this->assertEquals($core::$code, 404);

		if (!defined('ZAPMIN_OAUTH_DEV'))
			define('ZAPMIN_OAUTH_DEV', 1);

		$rdev->request('/oauth/10/github/auth');
		$adm->route('/oauth/<service_type>/<service_name>/auth',
			[$adm, 'route_fake_login']);
		$this->assertEquals($core::$code, 403);
		$this->assertEquals($core::$body['errno'],
			OAuthError::INCOMPLETE_DATA);

		$rdev->request('/oauth/10/github/auth');
		$adm->route('/oauth/<service_type>/github/auth',
			[$adm, 'route_fake_login']);
		$this->assertEquals($core::$code, 404);
		$this->assertEquals($core::$body['errno'],
			OAuthError::SERVICE_UNKNOWN);

		$rdev->request('/oauth/10/github/auth', 'GET',
			['get' => ['email' => 'me@github.io']]);
		$adm->route('/oauth/<service_type>/<service_name>/auth',
			[$adm, 'route_fake_login']);
		$this->assertEquals($core::$code, 404);
		$this->assertEquals($core::$body['errno'],
			OAuthError::SERVICE_UNKNOWN);

		$rdev->request('/oauth/10/github/auth', 'GET',
			['get' => ['email' => 'me+github.io']]);
		$adm->route('/oauth/<service_type>/<service_name>/auth',
			[$adm, 'route_fake_login']);
		$this->assertEquals($core::$code, 403);
		$this->assertEquals($core::$body['errno'],
			OAuthError::INCOMPLETE_DATA);

		$rdev->request('/oauth/20/tumblr/auth', 'GET',
			['get' => ['email' => 'me@github.io']]);
		$adm->route('/oauth/<service_type>/<service_name>/auth',
			[$adm, 'route_fake_login']);
		$this->assertEquals($core::$code, 404);
		$this->assertEquals($core::$body['errno'],
			OAuthError::SERVICE_UNKNOWN);

		$rdev->request('/oauth/20/tumblr/auth', 'GET',
			['get' => ['email' => 'me@tumblr.xyz']]);
		$adm->route('/oauth/<service_type>/<service_name>/auth',
			[$adm, 'route_fake_login']);
		$this->assertEquals($core::$code, 301);
		$this->assertEquals($core::$head[0], 'Location: /ok');

		$rdev->request('/oauth/20/tumblr/auth', 'GET',
			['get' => ['email' => 'me@tumblr.xyz']],
			['testing' => $_COOKIE['testing']]
		);
		$adm->route('/oauth/<service_type>/<service_name>/auth',
			[$adm, 'route_fake_login']);
		$this->assertEquals($core::$code, 401);

		$rdev->request('/status', 'GET', [], [
			['testing' => $_COOKIE['testing']]
		]);
		$adm->route('/status', [$adm, 'route_fake_status']);
		$this->assertEquals($core::$data['email'], 'me@tumblr.xyz');
	}
}
