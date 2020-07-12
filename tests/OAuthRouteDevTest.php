<?php


use BFITech\ZapCore\Logger;
use BFITech\ZapStore\SQLite3;
use BFITech\ZapAdmin\Admin;
use BFITech\ZapAdmin\AuthCtrl;
use BFITech\ZapAdmin\OAuthManage;
use BFITech\ZapAdminDev\OAuthRouteDev;
use BFITech\ZapOAuth\OAuthError;
use BFITech\ZapCoreDev\RoutingDev;
use BFITech\ZapCoreDev\TestCase;


/**
 * OAuthRouteDev test.
 *
 * This doesn't require fixture since the internal process of
 * OAuthRouteDev::route_fake_login is only based on registered service
 * and request uri.
 */
class OAuthRouteDevTest extends TestCase {

	public static $logger;
	public static $sql;

	public static function setUpBeforeClass() {
		$logfile = self::tdir(__FILE__) . '/zapmin-oauth-dev-route.log';
		if (file_exists($logfile))
			unlink($logfile);
		self::$logger = new Logger(Logger::DEBUG, $logfile);
	}

	public function tearDown() {
		self::$sql = null;
		self::$logger->info("TEST DONE.");
	}

	private function make_zcore() {
		### RoutingDev instance. Renew every time after mock request is
		### complete. Do not reuse.
		$rdev = new RoutingDev;

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
			->config('token_name', 'test-zapmin-oauth-dev')
			->config('check_tables', true);

		### AuthCtrl instance.
		$ctrl = new AuthCtrl($admin, $log);

		### OAuthManage instance.
		$manage = (new OAuthManage($admin, $log))
			->config('check_table', true);

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

		### OAuthRouteDev instance.
		$zcore = new OAuthRouteDev($core, $ctrl, $manage);

		return [$zcore, $rdev, $core];
	}

	public function test_fake_login() {
		extract(self::vars());

		# required constant not available
		list($zcore, $rdev, $core) = $this->make_zcore();
		$rdev
			->request('/oauth/10/github/auth')
			->route('/oauth/<service_type>/<service_name>/auth',
				[$zcore, 'route_fake_login']);
		$eq($core::$code, 404);

		if (!defined('ZAPMIN_OAUTH_DEV'))
			define('ZAPMIN_OAUTH_DEV', 1);

		# incomplete data
		list($zcore, $rdev, $core) = $this->make_zcore();
		$rdev
			->request('/oauth/10/github/auth')
			->route('/oauth/<service_type>/<service_name>/auth',
				[$zcore, 'route_fake_login']);
		$eq($core::$code, 403);
		$eq($core::$errno, OAuthError::INCOMPLETE_DATA);

		# service unknown
		list($zcore, $rdev, $core) = $this->make_zcore();
		$rdev
			->request('/oauth/10/github/auth')
			->route('/oauth/<service_type>/github/auth',
				[$zcore, 'route_fake_login']);
		$eq($core::$code, 403);
		$eq($core::$errno, OAuthError::SERVICE_UNKNOWN);

		# service unknown
		list($zcore, $rdev, $core) = $this->make_zcore();
		$rdev
			->request('/oauth/10/github/auth', 'GET',
				['get' => ['email' => 'me@github.io']])
			->route('/oauth/<service_type>/<service_name>/auth',
				[$zcore, 'route_fake_login']);
		$eq($core::$code, 403);
		$eq($core::$errno, OAuthError::SERVICE_UNKNOWN);

		# invalid email address
		list($zcore, $rdev, $core) = $this->make_zcore();
		$rdev
			->request('/oauth/10/github/auth', 'GET',
				['get' => ['email' => 'me+github.io']])
			->route('/oauth/<service_type>/<service_name>/auth',
				[$zcore, 'route_fake_login']);
		$eq($core::$code, 403);
		$eq($core::$errno, OAuthError::INCOMPLETE_DATA);

		# email address and registered services don't match
		list($zcore, $rdev, $core) = $this->make_zcore();
		$rdev
			->request('/oauth/20/tumblr/auth', 'GET',
				['get' => ['email' => 'me@github.io']])
			->route('/oauth/<service_type>/<service_name>/auth',
				[$zcore, 'route_fake_login']);
		$eq($core::$code, 403);
		$eq($core::$errno, OAuthError::SERVICE_UNKNOWN);

		# success
		list($zcore, $rdev, $core) = $this->make_zcore();
		$rdev
			->request('/oauth/20/tumblr/auth', 'GET',
				['get' => ['email' => 'me@tumblr.xyz']])
			->route('/oauth/<service_type>/<service_name>/auth',
				[$zcore, 'route_fake_login']);
		$eq($core::$code, 200);
		$eq($core::$errno, 0);
		$eq($core::$data, '/ok');

		### get token value from cookie
		$token_name = 'test-zapmin-oauth-dev';
		$token_val = $_COOKIE[$token_name];

		# already signed in
		list($zcore, $rdev, $core) = $this->make_zcore();
		$rdev
			->request('/oauth/20/tumblr/auth', 'GET', [
				'get' => ['email' => 'me@tumblr.xyz']
			], [
				$token_name => $token_val,
			])
			->route('/oauth/<service_type>/<service_name>/auth',
				[$zcore, 'route_fake_login']);
		$eq($core::$code, 200);
		$eq($core::$errno, 0);
		$eq($core::$data, '/ok');

		# get fake status
		list($zcore, $rdev, $core) = $this->make_zcore();
		$rdev
			->request('/status', 'GET', [], [
				$token_name => $token_val,
			])
			->route('/status', [$zcore, 'route_fake_status']);
		$eq($core::$data['email'], 'me@tumblr.xyz');
	}

}
