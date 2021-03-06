<?php declare(strict_types=1);


namespace BFITech\ZapAdmin;


use BFITech\ZapCore\Common;
use BFITech\ZapCore\Logger;
use BFITech\ZapStore\SQL;
use BFITech\ZapStore\SQLError;
use BFITech\ZapOAuth\OAuthError;
use BFITech\ZapOAuth\OAuthCommon;
use BFITech\ZapOAuth\OAuth10Permission;
use BFITech\ZapOAuth\OAuth10Action;
use BFITech\ZapOAuth\OAuth20Permission;
use BFITech\ZapOAuth\OAuth20Action;


/**
 * OAuthManage class.
 *
 * General workflow:
 *
 * 1. Extend this class, e.g. OAuthManageCustom, with method
 *    fetch_profile() overridden.
 * 2. Instantiate OAuthManageCustom $so. Let's call this instance
 *    super-oauth.
 * 3. Register services with $so->add_service() with
 *    appropriate service parameters.
 * 4. Use $perm = $so->get_permission_instance() that will
 *    initiate sequence of acquiring access token, along with
 *    access token secret for OAuth1 and refresh token for OAuth2.
 * 5. When access token is obtained, use it to make API calls
 *    with $act = $so->get_action_instance(). $act->request()
 *    wraps regular API calls. Specific to OAuth2, there is
 *    $act->refresh() that requests access token given a
 *    previously-obtained refresh token.
 *
 * To override default http client, e.g. for testing, create a method
 * http_client_custom on your super-oauth, with the exact same args with
 * those in Common::http_client.
 *
 * @SuppressWarnings(PHPMD.LongVariable)
 */
class OAuthManage extends AuthManage {

	/** Redirect URL after successful callback. */
	public $callback_ok_redirect = null;

	/** Redirect URL after failed callback. */
	public $callback_fail_redirect = null;

	/** Service info hash table. */
	private $services = [];

	/**
	 * Configure.
	 *
	 * Available configurables:
	 *   - (bool)check_table: Check table existence.
	 *
	 * @param string $key Config key name.
	 * @param any $val Config value.
	 * @return OAuthManage Instance of this class for chaining.
	 * @throws BFITech.ZapStore.SQLError on table creation failure.
	 */
	public function config(string $key, $val=null) {
		switch ($key) {
			case 'check_table':
				if ((bool)$val)
					$this->create_table();
				break;
		}
		return $this;
	}

	/**
	 * Create OAuth session table.
	 *
	 * This table is not for authentication since it's done by
	 * OAuthStore::store::status. This is to retrieve OAuth* tokens
	 * and use them for request or refresh. Only executed if
	 * `check_table` config is set to true.
	 *
	 * @throws BFITech.ZapStore.SQLError on failure.
	 */
	private function create_table() {
		$sql = self::$admin::$store;
		$log = self::$logger;

		try {
			$sql->query("SELECT 1 FROM uoauth LIMIT 1");
			$log->debug("ZapOAuth: Table exists.");
			return;
		} catch (SQLError $err) {
			// no-op
		}

		foreach([
			"DROP VIEW IF EXISTS v_uoauth;",
			"DROP TABLE IF EXISTS uoauth;",
		] as $drop) {
			$sql->query_raw($drop);
		}

		# token table

		$index = $sql->stmt_fragment('index');
		$engine = $sql->stmt_fragment('engine');
		# Each row is associated with a session.sid.
		$table = sprintf("
			CREATE TABLE uoauth (
				aid %s,
				sid INTEGER REFERENCES usess(sid) ON DELETE CASCADE,
				oname VARCHAR(64),
				otype VARCHAR(12),
				access TEXT,
				access_secret TEXT,    -- OAuth1.0 only
				refresh TEXT           -- OAuth2.0 only
			) %s;
		", $index, $engine);
		$sql->query_raw($table);

		# session view

		$session_view = "
			CREATE VIEW v_uoauth AS
				SELECT
					uoauth.*,
					usess.token,
					usess.expire
				FROM uoauth, usess
				WHERE
					uoauth.sid=usess.sid;
		";
		$sql->query_raw($session_view);

		$log->info("ZapOAuth: Table created.");
	}

	/**
	 * Get active OAuth* tokens given a session token.
	 *
	 * @param string $session_token Session token.
	 * @return dict|null Dict of tokens and oauth information of
	 *     current service.
	 */
	public function get_oauth_tokens(string $session_token) {
		$sql = self::$admin::$store;
		$dtnow = $sql->stmt_fragment('datetime', ['delta' => 0]);
		$stmt = sprintf("
			SELECT oname, otype, access, access_secret, refresh
			FROM v_uoauth
			WHERE token=? AND expire>%s
			ORDER BY sid DESC LIMIT 1
		", $dtnow);
		$result = $sql->query($stmt, [$session_token]);
		if ($result)
			return $result;
		return null;
	}

	/**
	 * Register available services.
	 *
	 * @param string $service_type OAuth version, '10' or '20'.
	 * @param string $service_name A nickname of the service, short
	 *     alphabetic lowercase, e.g.: github.
	 * @param string $consumer_key The key you obtain from the service.
	 * @param string $consumer_secret The secret you obtain along with
	 *     consumer key.
	 * @param string $url_token Token request URL. Not used by OAuth2.0.
	 * @param string $url_token_auth Token request authentication URL.
	 * @param string $url_access Access token URL for callback URL.
	 * @param string $scope Access scope, service-independent.
	 * @param string $url_callback Callback URL. Services usually
	 *     require this to be explicitly set according to what you
	 *     register in there, or else, they will return error at
	 *     site callback.
	 */
	public function add_service(
		string $service_type, string $service_name,
		string $consumer_key=null, string $consumer_secret=null,
		string $url_token=null, string $url_token_auth=null,
		string $url_access=null,
		string $scope=null, string $url_callback=null
	) {
		$log = self::$logger;

		if (!in_array($service_type, ['10', '20'])) {
			$msg = sprintf("Service type invalid: '%s'",
				$service_type);
			$log->error("ZapOAuth: " . $msg);
			throw new OAuthError($msg);
		}

		$key = $service_type . '-' . $service_name;
		if (isset($this->services[$key])) {
			$log->error(sprintf(
				"ZapOAuth: Service already registered: '%s'", $key));
			return false;
		}

		$srv = $this->services[$key] = [
			'consumer_key' => $consumer_key,
			'consumer_secret' => $consumer_secret,
			'service_type' => $service_type,
			'service_name' => $service_name,
			'url_request_token' => $url_token,  # 1.0 only
			'url_request_token_auth' => $url_token_auth,
			'url_access_token' => $url_access,
			'url_callback' => $url_callback,
			'scope' => $scope,                  # 2.0 only
		];
		$log->debug(
			"ZapOAuth: Service added: " .
			json_encode($srv, JSON_UNESCAPED_SLASHES));
	}

	# super-oauth methods

	/**
	 * Instantiate OAuth*Permission class.
	 *
	 * @param string $service_type Service type.
	 * @param string $service_name Service name.
	 * @return OAuthCommon Instance of OAuth*Permission on success.
	 *     Null on failure.
	 */
	public function get_permission_instance(
		string $service_type, string $service_name
	) {
		$key = $service_type . '-' . $service_name;
		if (!isset($this->services[$key]))
			# key invalid
			return null;

		$consumer_key = $consumer_secret = null;
		$url_request_token = $url_request_token_auth = null;
		$url_access_token = $url_callback = null;
		$scope = null;

		$srv = $this->services[$key];
		extract($srv);

		$perm = $service_type == '10' ?
			new OAuth10Permission(
				$consumer_key, $consumer_secret,
				$url_request_token, $url_request_token_auth,
				$url_access_token, $url_callback
			) :
			new OAuth20Permission(
				$consumer_key, $consumer_secret,
				$url_request_token_auth, $url_access_token,
				$url_callback, $scope
			);

		# use custom client for permission instance
		if (method_exists($this, 'http_client_custom')) {
			$perm->http_client_custom = function($kwargs) {
				return $this->http_client_custom($kwargs);
			};
		}

		return $perm;
	}

	/**
	 * Finetune permission instance.
	 *
	 * Override this in a subclass to change, e.g.
	 * auth_basic_for_site_callback in OAuth2.0.
	 *
	 * @param dict $args Router HTTP variables.
	 * @param OAuthCommon $oauth_perm OAuth*Permission instance.
	 * @return OAuthCommon Modified OAuth*Permission instance.
	 * @codeCoverageIgnore
	 *
	 * ### Example:
	 *
	 * @code
	 * class OAuthManageCustom extends OAuthManage {
	 *     public function finetune_permission($args, $perm) {
	 *         if ($args['params']['service_name'] == 'reddit')
	 *             $perm->auth_basic_for_site_callback = true;
	 *         return $perm;
	 *     }
	 * }
	 * @endcode
	 *
	 * @SuppressWarnings(PHPMD.UnusedFormalParameter)
	 */
	public function finetune_permission(
		array $args, OAuthCommon $oauth_perm
	) {
		return $oauth_perm;
	}

	/**
	 * Instantiate OAuth*Action class.
	 *
	 * When succeeds, each instance has request() method that we
	 * can use to make any request. Specific to OAuth2.0, there's
	 * also refresh() method to refresh token when its access token
	 * is expired.
	 *
	 * @param string $service_type Service type.
	 * @param string $service_name Service name.
	 * @param string $access_token Access token returned by
	 *     site_callback() or retrieved from storage.
	 * @param string $access_token_secret Access token secret returned
	 *     by site_callback() or retrived. OAuth1.0 only.
	 * @param string $refresh_token Refresh token returned by
	 *     $this->route_byway_callback() or retrieved. OAuth2.0 only.
	 * @return OAuthCommon Instance of OAuth*Action instance on success.
	 *     Null otherwise.
	 */
	public function get_action_instance(
		string $service_type, string $service_name,
		string $access_token, string $access_token_secret=null,
		string $refresh_token=null
	) {
		$key = $service_type . '-' . $service_name;
		if (!isset($this->services[$key]))
			# key invalid
			return null;

		$consumer_key = $consumer_secret = $url_access_token = null;

		$srv = $this->services[$key];
		extract($srv);

		$act = $service_type == '10' ?
			new OAuth10Action(
				$consumer_key, $consumer_secret,
				$access_token, $access_token_secret
			) :
			new OAuth20Action(
				$consumer_key, $consumer_secret,
				$access_token, $refresh_token,
				$url_access_token
			);

		# use custom client for action instance
		if (method_exists($this, 'http_client_custom')) {
			$act->http_client_custom = function($kwargs) {
				return $this->http_client_custom($kwargs);
			};
		}
		return $act;
	}

	/**
	 * Profile fetcher stub.
	 *
	 * Use this to populate user bio after user is successfully
	 * authenticated.
	 *
	 * @param object $oauth_action Instance of OAuth action.
	 * @param string $service_type Service type.
	 * @param string $service_name Service name.
	 * @param array $kwargs Additional arguments.
	 * @return On successful authentication, a dict of the
	 *     form:
	 *     @code
	 *     (dict){
	 *         'uname': (string)uname,
	 *         'fname': (optional string)fname,
	 *         'email': (optional string)email,
	 *         'site': (optional string)site,
	 *     }
	 *     @endcode
	 * @codeCoverageIgnore
	 *
	 * @SuppressWarnings(PHPMD.UnusedFormalParameter)
	 */
	public function fetch_profile(
		OAuthCommon $oauth_action,
		string $service_type, string $service_name, array $kwargs=[]
	) {
		return [];
	}

	/**
	 * Middleware to add new user after successful authorization.
	 *
	 * This allow user to self-add themselves to the database with
	 * AuthManage::self_add_passwordless in the backend. Called by
	 * OAuthRouteDefault::route_byway_callback after successful
	 * OAuth site callback.
	 *
	 * @param string $service_type '10' for OAuth1, '20' for OAuth2.
	 * @param string $service_name Service nickname, e.g. 'github'.
	 * @param string $uname Username obtained by successful
	 *     OAuthManage::fetch_profile().
	 * @param string $access_token Access token.
	 * @param string $access_token_secret Access token secret, OAuth1
	 *     only.
	 * @param string $refresh_token Refresh token, OAuth2 only.
	 * @param array $profile Additional profile dict obtained by
	 *     successful OAuthManage::fetch_profile().
	 * @return string Session token.
	 * @throws Error when user is already signed in.
	 *     OAuthRouteDefault::route_byway_callback or equivalent must
	 *     stop this from happening.
	 * @see AuthManage::self_add_passwordless
	 * @see OAuthRouteDefault::route_byway_callback
	 */
	public function add_user(
		string $service_type, string $service_name, string $uname,
		string $access_token, string $access_token_secret=null,
		string $refresh_token=null, array $profile=[]
	) {
		# register passwordless or throw exception if user is in
		$udata = $this->_format_self_add_passwordless(
			$uname, $service_type, $service_name);

		$sql = self::$admin::$store;

		# save additional udata from profile retriever if exists
		$bio = [];
		foreach (['fname', 'email', 'site'] as $key) {
			if (isset($profile[$key])) {
				$val = $profile[$key];
				if (!is_string($val) && !is_numeric($val))
					continue;
				$bio[$key] = $profile[$key];
			}
		}
		if (isset($bio['email']))
			$bio['email_verified'] = 1;
		if ($bio)
			$sql->update('udata', $bio, [
				'uid' => $udata['uid']
			]);

		# save to oauth table
		$ins = [
			'sid' => $udata['sid'],
			'oname' => $service_name,
			'otype' => $service_type,
			'access' => $access_token,
		];
		if ($access_token_secret)
			$ins['access_secret'] = $access_token_secret;
		if ($refresh_token)
			$ins['refresh'] = $refresh_token;
		$sql->insert('uoauth', $ins);

		return $udata['token'];
	}

	private function _format_self_add_passwordless(
		string $uname, string $service_type, string $service_name
	) {
		# uname is urlencoded for safety
		$uname = rawurlencode($uname);

		# uservice is of the form 'oauth%service_type%[%service_name%]
		$uservice = sprintf(
			'oauth%s[%s]', $service_type, $service_name);

		# register passwordless
		$retval = $this->self_add_passwordless([
			'uname' => $uname,
			'uservice' => $uservice,
		]);
		if ($retval[0] == Error::USER_ALREADY_LOGGED_IN) {
			$msg = "User already signed in.";
			self::$logger->error("ZapOAuth: " . $msg);
			throw new Error(Error::USER_ALREADY_LOGGED_IN, $msg);
		}
		return $retval[1];
	}

	/**
	 * Get OAuth*Action instance from session token.
	 *
	 * Use this to initiate an OAuth connection and do next
	 * authenticated action with request() or refresh().
	 *
	 * @param string $session_token Session token received by
	 *     cookie or request header.
	 */
	public function get_action_from_session(string $session_token) {
		$tokens = $this->get_oauth_tokens($session_token);
		if (!$tokens)
			return null;
		return $this->get_action_instance(
			$tokens['otype'], $tokens['oname'], $tokens['access'],
			$tokens['access_secret'], $tokens['refresh']
		);
	}

}
