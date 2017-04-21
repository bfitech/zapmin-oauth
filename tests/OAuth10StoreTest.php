<?php


require_once(__DIR__ . '/OAuthFixture.php');


use PHPUnit\Framework\TestCase;
use BFITech\ZapCore\Common;
use BFITech\ZapCore\Logger;
use BFITech\ZapStore\SQLite3;
use BFITech\ZapAdmin\OAuthStore;
use BFITech\ZapAdmin\OAuthError;


class OAuth10Store extends OAuthStore {
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


class OAuth10Test extends TestCase {

	protected static $sql;
	protected static $adm;
	protected static $logger;

	protected static $pwdless_uid;

	public static function setUpBeforeClass() {
		self::$logger = new Logger(Logger::ERROR, '/dev/null');
	}

	public function test_oauth10_store() {
		$store = new SQLite3(
			['dbname' => ':memory:'], self::$logger);
		$adm = new OAuth10Store($store, null, true, self::$logger);

		try {
			$adm->oauth_add_service(
				'consumer-key', 'consumer-secret-test',
				'twitter', '30',
				'http://www.example.org/10/auth_request',
				'http://www.example.org/10/auth',
				'http://www.example.org/10/access',
				null, null, null
			);
		} catch(OAuthError $e) {
			# invalid service
		}

		$adm->oauth_add_service(
			'consumer-key-test',
			'consumer-secret-test',
			'twitter', '10',
			'http://example.org/10/auth_request',
			'http://example.org/10/auth',
			'http://example.org/10/access',
			null, null, 'http://localhost'
		);

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
		$rv = $perm->site_callback(['get' => $res]);
		$this->assertEquals($rv[0], 0);
		$this->assertSame(array_keys($rv[1]),
			['access_token', 'access_token_secret']);
		extract($rv[1], EXTR_SKIP);

		# create OAuth1.0 action instance
		$act = $adm->oauth_get_action_instance('10', 'twitter',
			$access_token, $access_token_secret);
		# patch http client
		$act->http_client_custom = function($args) {
			return ServiceFixture::oauth10($args);
		};

		# use access token to fetch profile
		$rv = $act->request([
			'method' => 'GET',
			'url' => 'http://example.org/10/api/me',
		]);
		$data = json_decode($rv[1], true);
		$this->assertEquals($data['uname'], 'john');

		# fake-fetch profile
		$profile = $adm->oauth_fetch_profile($act, '10', 'twitter');

		# save to database
		$rv = $adm->oauth_add_user(
			'10', 'twitter', $data['uname'],
			$access_token, $access_token_secret, null, $data);
		$this->assertEquals($rv[0], 0);
		$session_token = $rv[1];

		# check if we're truly signed in
		$adm->adm_set_user_token($session_token);
		$rv = $adm->adm_status();
		$this->assertEquals($rv['fname'], 'John Smith');

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
			'url' => 'http://example.org/10/api/me'
		]);
		$data = json_decode($rv[1], true);
		$this->assertEquals($data['uname'], 'john');
	}

}

