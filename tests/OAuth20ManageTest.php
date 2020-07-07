<?php


require_once(__DIR__ . '/OAuthFixture.php');


use BFITech\ZapCore\Common;
use BFITech\ZapCore\Logger;
use BFITech\ZapStore\SQLite3;
use BFITech\ZapAdmin\Admin;
use BFITech\ZapAdmin\AuthCtrl;
use BFITech\ZapAdmin\Error;
use BFITech\ZapAdmin\OAuthManage;
use BFITech\ZapOAuth\OAuthCommon;
use BFITech\ZapOAuth\OAuthError;
use BFITech\ZapCoreDev\TestCase;


class OAuth20Manage extends OAuthManage {

	public function fetch_profile(
		OAuthCommon $oauth_action,
		string $service_type, string $service_name, array $kwargs=[]
	) {
		return ServiceFixture::fetch_profile(
			$oauth_action, $service_type, $service_name, $kwargs);
	}

}


class OAuth20Test extends TestCase {

	protected static $logger;

	public static function setUpBeforeClass() {
		$logfile = self::tdir(__FILE__) . '/zapmin-oauth-20.log';
		if (file_exists($logfile))
			unlink($logfile);
		self::$logger = new Logger(Logger::ERROR, $logfile);
	}

	private function register_services() {
		$store = new SQLite3(
			['dbname' => ':memory:'], self::$logger);
		$admin = new Admin($store, self::$logger);
		$admin
			->config('expire', 3600)
			->config('token_name', 'testing')
			->config('check_tables', true);
		$manage = (new OAuth20Manage($admin, self::$logger))
			->config('check_table', true);

		$make_service = function($srv) use($manage) {
			call_user_func_array([$manage, 'add_service'],[
				'20', $srv,
				'consumer-key-test',
				'consumer-secret-test',
				"http://${srv}.example.org/20/auth_request",
				"http://${srv}.example.org/20/auth",
				"http://${srv}.example.org/20/access",
				'email', 'http://localhost'
			]);
		};
		# register these bogus services
		foreach (['github', 'google', 'reddit'] as $srv)
			$make_service($srv);

		return $manage;
	}

	public function test_oauth20() {
		extract(self::vars());

		$manage = $this->register_services();

		# cannot add the same type and name, though other parameters
		# are different
		$fl(
			$manage->add_service(
				'20', 'reddit',
				'xconsumer-key-test',
				'xconsumer-secret-test',
				null, null, null, null, null
			)
		);

		# create OAuth2.0 permission instance, success
		$perm = $manage->get_permission_instance('20', 'reddit');
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
		$eq($res['response_type'], 'code');
		$eq($purl['path'], '/20/auth');

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
		# get access token from query string provided by site callback
		$rv = $perm->site_callback($res);
		$eq($rv[0], 0);
		$this->assertNotFalse(Common::check_idict($rv[1],
			['access_token', 'refresh_token']));
		extract($rv[1]);

		# create OAuth2.0 action instance, invalid type
		$act = $manage->get_action_instance('30', 'reddit',
			$access_token, $refresh_token,
			'http://reddit.example.org/20/access');
		$nil($act);

		# create OAuth2.0 action instance
		$act = $manage->get_action_instance('20', 'reddit',
			$access_token, $refresh_token,
			'http://reddit.example.org/20/access');
		# patch http client
		$act->http_client_custom = function($args) {
			return ServiceFixture::oauth20($args);
		};

		# get refresh token
		# @fixme Never tested on live service.
		$rv = $act->refresh(true);
		$eq($rv[0], 200);
		$this->assertNotFalse(Common::check_idict($rv[1],
			['access_token', 'refresh_token']));

		# fake-fetch profile
		$profile = $manage->fetch_profile($act, '20', 'reddit');

		# save to database and obtain session token
		$session_token = $manage->add_user(
			'20', 'reddit', $profile['uname'],
			$access_token, null, $refresh_token, $profile);

		# check if we're truly signed in
		$manage->set_token_value($session_token);
		$rv = $manage->get_safe_user_data();
		$eq($rv[1]['uname'], '+john:oauth20[reddit]');
		$eq($rv[1]['fname'], 'John Smith');

		# invalid session token
		$nil($manage->get_oauth_tokens('x'));

		# retrieve all stored tokens
		$rv = $manage->get_oauth_tokens($session_token);
		$eq($rv['oname'], 'reddit');
		$eq($rv['otype'], '20');
		$eq($rv['access'], $access_token);
		$eq($rv['refresh'], $refresh_token);

		# get action instance with wrong token
		$nil($manage->get_action_from_session('wrong_token'));

		# get action instance
		$act = $manage->get_action_from_session($session_token);
		# patch http client
		$act->http_client_custom = function($args) {
			return ServiceFixture::oauth20($args);
		};

		# use action instance
		$rv = $act->request([
			'method' => 'GET',
			'url' => 'http://reddit.example.org/20/api/me'
		]);
		$data = json_decode($rv[1], true);
		$eq($data['uname'], 'john');

		# cannot re-add since user's already signed in
		$errno = false;
		try {
			$manage->add_user(
				'20', 'reddit', $profile['uname'],
				$access_token, null, $refresh_token, $profile);
		} catch(Error $err) {
			$errno = $err->getCode();
		}
		$sm($errno, Error::USER_ALREADY_LOGGED_IN);
	}

}
