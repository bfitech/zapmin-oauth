<?php


require_once(__DIR__ . '/OAuthFixture.php');


use PHPUnit\Framework\TestCase;
use BFITech\ZapCore\Common;
use BFITech\ZapCore\Logger;
use BFITech\ZapCoreDev\RouterDev;
use BFITech\ZapStore\SQLite3;
use BFITech\ZapAdmin\Admin;
use BFITech\ZapAdmin\AuthCtrl;
use BFITech\ZapAdmin\AuthManage;
use BFITech\ZapAdmin\OAuthStore;
use BFITech\ZapOAuth\OAuthCommon;
use BFITech\ZapOAuth\OAuthError;


class OAuth10Store extends OAuthStore {

	public function oauth_fetch_profile(
		OAuthCommon $oauth_action,
		string $service_type, string $service_name, array $kwargs=[]
	) {
		return ServiceFixture::oauth_fetch_profile(
			$oauth_action, $service_type, $service_name, $kwargs);
	}

	public function oauth_add_user(
		string $service_type, string $service_name, string $uname,
		string $access_token, string $access_token_secret=null,
		string $refresh_token=null, array $profile=[]
	) {
		return parent::oauth_add_user(
			$service_type, $service_name, $uname, $access_token,
			$access_token_secret, $refresh_token, $profile
		);
	}

}


class OAuth10Test extends TestCase {

	protected static $logger;

	public static function setUpBeforeClass() {
		self::$logger = new Logger(Logger::ERROR, '/dev/null');
	}

	private function register_services() {
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
		$adm = new OAuth10Store($core, $ctrl, $manage);

		try {
			$adm->oauth_add_service(
				'30', 'twitter',
				'consumer-key', 'consumer-secret-test',
				'http://www.example.org/10/auth_request',
				'http://www.example.org/10/auth',
				'http://www.example.org/10/access',
				null, null
			);
		} catch(OAuthError $e) {
			# invalid service
		}

		$make_service = function($srv) use($adm) {
			call_user_func_array([$adm, 'oauth_add_service'],[
				'10', $srv,
				'consumer-key-test',
				'consumer-secret-test',
				"http://${srv}.example.org/10/auth_request",
				"http://${srv}.example.org/10/auth",
				"http://${srv}.example.org/10/access",
				null, 'http://localhost'
			]);
		};
		# register these bogus services
		foreach ([
			'trakt', 'trello', 'twitter', 'tumblr', 'reddit',
		] as $srv)
			$make_service($srv);

		return $adm;
	}

	public function test_oauth10_store_request_fail() {
		$adm = $this->register_services();
		# these all won't pass request token phase
		foreach (['reddit', 'trello', 'tumblr'] as $srv) {
			$perm = $adm->oauth_get_permission_instance('10', $srv);
			# patch http client
			$perm->http_client_custom = function($args) {
				return ServiceFixture::oauth10($args);
			};
			$this->assertNull($perm->get_access_token_url());
		}
	}

	public function test_oauth10_store() {
		$adm = $this->register_services();

		# create OAuth1.0 permission instance
		$perm = $adm->oauth_get_permission_instance('10', 'trakt');
		# patch http client
		$perm->http_client_custom = function($args) {
			return ServiceFixture::oauth10($args);
		};

		# -> LOCAL -> REMOTE
		# get auth url, this will internally make request to
		# POST: /10/auth_request from local and process response such
		# that return value is redirect URL on valid auth request
		$redir_url = $perm->get_access_token_url();
		## run some tests
		$purl = parse_url($redir_url);
		parse_str($purl['query'], $res);
		$this->assertTrue(isset($res['oauth_token']));
		$this->assertEquals($purl['path'], '/10/auth');

		# create OAuth1.0 permission instance
		$perm = $adm->oauth_get_permission_instance('10', 'twitter');
		# patch http client
		$perm->http_client_custom = function($args) {
			return ServiceFixture::oauth10($args);
		};

		# -> LOCAL -> REMOTE
		# get auth url, this will internally make request to
		# POST: /10/auth_request from local and process response such
		# that return value is redirect URL on valid auth request
		$redir_url = $perm->get_access_token_url();
		## run some tests
		$purl = parse_url($redir_url);
		parse_str($purl['query'], $res);
		$this->assertTrue(isset($res['oauth_token']));
		$this->assertEquals($purl['path'], '/10/auth');

		# => REMOTE
		# user must be redirected to $redir_url on the browser, signed
		# in on the remote service, and dis/agree to grant access
		$rv = $perm->http_client([
			'method' => 'GET',
			'url' => $redir_url
		]);
		$access_url = $rv[1];

		# -> REMOTE => LOCAL
		# user is redirected back to callback URL, appended with
		# appropriate query string containing 'oauth_token' if s/he
		# grants access, optionally 'oauth_verifier' for OAuth1.0a
		$purl = parse_url($access_url);
		# res is used by site_callback()
		parse_str($purl['query'], $res);
		$this->assertSame(array_keys($res),
			['oauth_token', 'oauth_verifier']);

		# -> LOCAL -> REMOTE
		# get access token from params provided by site callback
		# which internally makes request to POST: /10/access and
		# attains 'oauth_token' and 'oauth_token_secret' on success
		$rv = $perm->site_callback($res);
		$this->assertEquals($rv[0], 0);
		$this->assertSame(array_keys($rv[1]),
			['access_token', 'access_token_secret']);
		extract($rv[1]);

		# create OAuth1.0 action instance
		$act = $adm->oauth_get_action_instance('10', 'twitter',
			$access_token, $access_token_secret);
		# patch http client
		$act->http_client_custom = function($args) {
			return ServiceFixture::oauth10($args);
		};

		# use access token for a non-well-formed resource
		$rv = $act->request([
			'method' => 'GET',
			'url' => 'twitter.example.org/10/api/me?q=1',
		]);
		$this->assertEquals($rv[0], -1);

		# use access token to fetch profile successfully
		$rv = $act->request([
			'method' => 'GET',
			'url' => 'http://twitter.example.org/10/api/me?q=1',
		]);
		$data = json_decode($rv[1], true);
		$this->assertEquals($data['uname'], 'john');

		# fake-fetch profile
		$profile = $adm->oauth_fetch_profile($act, '10', 'twitter');

		# save to database and obtain session token
		$session_token = $adm->oauth_add_user(
			'10', 'twitter', $data['uname'],
			$access_token, $access_token_secret, null, $data);

		# check if we're truly signed in
		$adm::$ctrl->set_token_value($session_token);
		$rv = $adm::$ctrl->get_safe_user_data();
		$this->assertEquals($rv[1]['fname'], 'John Smith');

		# retrieve all stored tokens
		$rv = $adm->adm_get_oauth_tokens($session_token);
		$this->assertEquals($rv['oname'], 'twitter');
		$this->assertEquals($rv['otype'], '10');
		$this->assertEquals($rv['access'], $access_token);
		$this->assertEquals($rv['access_secret'], $access_token_secret);

		# test action instance
		$act = $adm->oauth_get_action_from_session($session_token);
		# patch http client
		$act->http_client_custom = function($args) {
			return ServiceFixture::oauth10($args);
		};
		$rv = $act->request([
			'method' => 'GET',
			'url' => 'http://twitter.example.org/10/api/me'
		]);
		$data = json_decode($rv[1], true);
		$this->assertEquals($data['uname'], 'john');

	}

}
