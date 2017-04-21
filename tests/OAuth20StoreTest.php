<?php


require_once(__DIR__ . '/OAuthFixture.php');


use PHPUnit\Framework\TestCase;
use BFITech\ZapCore\Common;
use BFITech\ZapCore\Logger;
use BFITech\ZapStore\SQLite3;
use BFITech\ZapAdmin\AdminStore;
use BFITech\ZapAdmin\OAuthStore;
use BFITech\ZapAdmin\OAuthError;


class OAuth20Store extends OAuthStore {
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

class AdminStore20Tab extends AdminStore {}

class OAuth20Test extends TestCase {

	protected static $logger;

	public static function setUpBeforeClass() {
		self::$logger = new Logger(Logger::ERROR, '/dev/null');
	}

	public function test_oauth20_store() {
		$store = new SQLite3(
			['dbname' => ':memory:'], self::$logger);
		new AdminStore20Tab($store);
		$adm = new OAuth20Store($store, true, self::$logger);

		$adm->oauth_add_service(
			'20', 'reddit',
			'consumer-key-test',
			'consumer-secret-test',
			null,
			'http://reddit.example.org/20/auth',
			'http://reddit.example.org/20/access',
			'email',
			'http://localhost'
		);

		# create OAuth1.0 permission instance
		$perm = $adm->oauth_get_permission_instance('20', 'reddit');
		# patch http client
		$perm->http_client_custom = function($args) {
			return ServiceFixture::oauth20($args);
		};

		# -> LOCAL
		# get auth url, this will generate auth url, appended to
		# /10/auth
		$redir_url = $perm->get_access_token_url();
		## run some tests
		$purl = parse_url($redir_url);
		parse_str($purl['query'], $res);
		$this->assertNotFalse(Common::check_idict($res, [
			'client_id', 'state', 'redirect_uri', 'response_type'
		]));
		$this->assertEquals($res['response_type'], 'code');
		$this->assertEquals($purl['path'], '/20/auth');

		# => REMOTE
		# user must be redirected to $redir_url on the browser, signed
		# in on the remote service, and dis/agree to grant access
		$rv = $perm->http_client([
			'method' => 'GET',
			'url' => $redir_url,
		]);
		$redir_local = $rv[1];

		# -> REMOTE => LOCAL
		# user is redirected back to site callback with appropriate
		# query string containing 'code' and 'state'
		$purl = parse_url($rv[1]);
		parse_str($purl['query'], $res);

		# -> LOCAL -> REMOTE
		# get access token from params provided by site callback
		$rv = $perm->site_callback(['get' => $res]);
		$this->assertEquals($rv[0], 0);
		$this->assertNotFalse(Common::check_idict($rv[1],
			['access_token', 'refresh_token']));
		extract($rv[1], EXTR_SKIP);

		# create OAuth1.0 action instance
		$act = $adm->oauth_get_action_instance('20', 'reddit',
			$access_token, $refresh_token,
			'http://reddit.example.org/20/access');
		# patch http client
		$act->http_client_custom = function($args) {
			return ServiceFixture::oauth20($args);
		};

		# use access token to fetch profile
		$rv = $act->request([
			'method' => 'GET',
			'url' => 'http://reddit.example.org/20/api/me',
			'expect_json' => true,
		]);
		$data = json_decode($rv[1], true);
		$this->assertEquals($data['uname'], 'john');

		# get refresh token
		# @fixme Never tested on live service.
		$rv = $act->refresh(true);
		$this->assertEquals($rv[0], 200);
		$this->assertNotFalse(Common::check_idict($rv[1],
			['access_token', 'refresh_token']));

		# fake-fetch profile
		$profile = $adm->oauth_fetch_profile(
			$act, '20', 'reddit');

		# save to database
		$rv = $adm->oauth_add_user(
			'20', 'reddit', $data['uname'],
			$access_token, null, $refresh_token, $profile);
		$this->assertEquals($rv[0], 0);
		$session_token = $rv[1];

		# check if we're truly signed in
		$adm->adm_set_user_token($session_token);
		$rv = $adm->adm_status();
		$this->assertEquals($rv['fname'], 'John Smith');

		# invalid session token
		$rv = $adm->adm_get_oauth_tokens('x');
		$this->assertEquals(null, $rv);

		# retrieve all stored tokens
		$rv = $adm->adm_get_oauth_tokens($session_token);
		$this->assertEquals($rv['oname'], 'reddit');
		$this->assertEquals($rv['otype'], '20');
		$this->assertEquals($rv['access'], $access_token);
		$this->assertEquals($rv['refresh'], $refresh_token);

		# test action instance
		$act = $adm->oauth_get_action_from_session($session_token);
		# patch http client
		$act->http_client_custom = function($args) {
			return ServiceFixture::oauth20($args);
		};
		$rv = $act->request([
			'method' => 'GET',
			'url' => 'http://reddit.example.org/20/api/me'
		]);
		$data = json_decode($rv[1], true);
		$this->assertEquals($data['uname'], 'john');
	}
}

