<?php


require_once(__DIR__ . '/OAuthFixture.php');


use BFITech\ZapCore\Common;
use BFITech\ZapCore\Logger;
use BFITech\ZapStore\SQLite3;
use BFITech\ZapAdmin\Admin;
use BFITech\ZapAdmin\AuthCtrl;
use BFITech\ZapAdmin\OAuthManage;
use BFITech\ZapOAuth\OAuthCommon;
use BFITech\ZapOAuth\OAuthError;
use BFITech\ZapCoreDev\TestCase;


class OAuth10Manage extends OAuthManage {

	public function fetch_profile(
		OAuthCommon $oauth_action,
		string $service_type, string $service_name, array $kwargs=[]
	) {
		return ServiceFixture::fetch_profile(
			$oauth_action, $service_type, $service_name, $kwargs);
	}

}


class OAuth10Test extends TestCase {

	protected static $logger;

	public static function setUpBeforeClass() {
		$logfile = self::tdir(__FILE__) . '/zapmin-oauth-10.log';
		if (file_exists($logfile))
			unlink($logfile);
		self::$logger = new Logger(Logger::DEBUG, $logfile);
	}

	private function register_services() {
		$sql = new SQLite3(
			['dbname' => ':memory:'], self::$logger);
		$admin = new Admin($sql, self::$logger);
		$admin
			->config('expire', 3600)
			->config('token_name', 'testing')
			->config('check_tables', true);
		$manage = (new OAuth10Manage($admin, self::$logger))
			->config('check_table', true)
			->init();

		try {
			$manage->add_service(
				'30', 'twitter',
				'consumer-key', 'consumer-secret-test',
				'http://www.example.org/10/auth_request',
				'http://www.example.org/10/auth',
				'http://www.example.org/10/access',
				null, null
			);
		} catch(OAuthError $err) {
			# invalid service, there's no oauth 3.0
		}

		$make_service = function($srv) use($manage) {
			call_user_func_array([$manage, 'add_service'], [
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

		return $manage;
	}

	public function test_oauth10_request_fail() {
		$adm = $this->register_services();
		# these all won't pass request token phase
		foreach (['reddit', 'trello', 'tumblr'] as $srv) {
			$perm = $adm->get_permission_instance('10', $srv);
			# patch http client
			$perm->http_client_custom = function($args) {
				return ServiceFixture::oauth10($args);
			};
			self::nil()($perm->get_access_token_url());
		}
	}

	public function test_oauth10() {
		extract(self::vars());

		$manage = $this->register_services();

		# create OAuth1.0 permission instance
		$perm = $manage->get_permission_instance('10', 'trakt');
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
		$tr(isset($res['oauth_token']));
		$eq($purl['path'], '/10/auth');

		# create OAuth1.0 permission instance
		$perm = $manage->get_permission_instance('10', 'twitter');
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
		$tr(isset($res['oauth_token']));
		$eq($purl['path'], '/10/auth');

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
		$sm(array_keys($res), ['oauth_token', 'oauth_verifier']);

		# -> LOCAL -> REMOTE
		# get access token from params provided by site callback
		# which internally makes request to POST: /10/access and
		# attains 'oauth_token' and 'oauth_token_secret' on success
		$rv = $perm->site_callback($res);
		$eq($rv[0], 0);
		$sm(array_keys($rv[1]),
			['access_token', 'access_token_secret']);
		extract($rv[1]);

		# create OAuth1.0 action instance
		$act = $manage->get_action_instance('10', 'twitter',
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
		$eq($rv[0], -1);

		# fake-fetch profile
		$profile = $manage->fetch_profile($act, '10', 'twitter');

		# save to database and obtain session token
		$session_token = $manage->add_user(
			'10', 'twitter', $profile['uname'],
			$access_token, $access_token_secret, null, $profile);

		# check if we're truly signed in
		$manage->set_token_value($session_token);
		$rv = $manage->get_safe_user_data();
		$eq($rv[1]['uname'], '+john:oauth10[twitter]');
		$eq($rv[1]['fname'], 'John Smith');

		# retrieve all stored tokens
		$rv = $manage->get_oauth_tokens($session_token);
		$eq($rv['oname'], 'twitter');
		$eq($rv['otype'], '10');
		$eq($rv['access'], $access_token);
		$eq($rv['access_secret'], $access_token_secret);

		# test action instance
		$act = $manage->get_action_from_session($session_token);
		# patch http client
		$act->http_client_custom = function($args) {
			return ServiceFixture::oauth10($args);
		};
		$rv = $act->request([
			'method' => 'GET',
			'url' => 'http://twitter.example.org/10/api/me'
		]);
		$data = json_decode($rv[1], true);
		$eq($data['uname'], 'john');

		# request by adding a query
		$rv = $act->request([
			'method' => 'GET',
			'url' => 'http://twitter.example.org/10/api/me?q=1'
		]);
		$data = json_decode($rv[1], true);
		$eq($data['uname'], 'john');
	}

}
