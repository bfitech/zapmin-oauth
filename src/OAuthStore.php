<?php


namespace BFITech\ZapAdmin;


use BFITech\ZapCore\Common;
use BFITech\ZapCore\Logger;
use BFITech\ZapStore\SQL;
use BFITech\ZapStore\SQLError;
use BFITech\ZapOAuth as zo;


class OAuthError extends \Exception {}


/**
 * OAuthStore class.
 *
 * This only deals with storage. Router activity is not allowed.
 */
abstract class OAuthStore extends AdminStore {

	/**
	 * Service register.
	 *
	 * Services are stored in a dict with keys of the form:
	 * $service_name . '-' . $service_type.
	 */
	private $oauth_service_configs = [];

	// There's no default facility to change these by default.
	// Only subclass can take advantage of this.
	/** Redirect URL after successful callback. */
	public $oauth_callback_ok_redirect = null;
	/** Redirect URL after failed callback. */
	public $oauth_callback_fail_redirect = null;

	/**
	 * Constructor.
	 *
	 * This takes parameters exactly the same with parent class.
	 * Only use this following workflow on a router. Other methods
	 * are sufficiently encapsulated.
	 *
	 * General workflow:
	 *
	 * 1. Instantiate OAuthRoute $so, let's call this super-oauth.
	 * 2. Create a profile callback, i.e. profile retriever when
	 *    authentication succeeds, which takes super-oauth as
	 *    parameter and returns a username on success.
	 * 3. Register services with $so->oauth_add_service() with
	 *    appropriate configuration. This includes profile callback
	 *    in 2).
	 * 4. Use route handler $so->route_byway_auth() for generating
	 *    access token.
	 * 5. Use route handler $so->route_byway_callback() for accepting
	 *    successful access token request.
	 * 6. Subsequent API requests need access (and access secret
	 *    tokens for OAuth1.0). These can be obtained with
	 *    $so->adm_get_oauth_tokens(), which takes zap session token
	 *    as parameter or in special case, null. e.g. when we
	 *    need to get token inside profile callback 2).
	 * 7. From super-oauth, we can instantiate the real oauth{1,2}
	 *    class with $ac = $so->oauth_get_action_instance(), taking
	 *    tokens provided by 6 as parameter(s). This instance
	 *    has $ac->request() method with which we can do requests to
	 *    the API service. For OAuth2.0, it also has $ac->refresh()
	 *    for token refresh.
	 *
	 * @see AdminStore.
	 * @note $expiration parameter is only used by parent to set
	 *     table-based default value for usess.expire. Byway has its
	 *     own expiration which is changeable by
	 *     $this->adm_set_byway_expiration().
	 */
	public function __construct(
		SQL $store, $force_create_table=null, Logger $logger=null
	) {
		# Use $this->adm_set_byway_expiration() to finetune expiration.

		$this->logger = $logger ? $logger : new Logger();
		$this->store = $store;
		$this->dbtype = $store->get_connection_params()['dbtype'];

		# check if udata table exists
		try {
			$test = $store->query("SELECT 1 FROM udata LIMIT 1");
		} catch(SQLError $e) {
			throw new OAuthError("Zapmin udata table not ready.");
		}
		# must execute parent constructor to initiate some props
		parent::__construct($store, null, null, $logger);

		$this->oauth_create_table($force_create_table);
	}

	/**
	 * Create OAuth session table.
	 *
	 * This table is not for authentication since it's done by
	 * $this->store->status(). This is to retrieve OAuth* tokens
	 * and use them for request or refresh.
	 */
	private function oauth_create_table($force_create_table) {
		$sql = $this->store;
		$logger = $this->logger;

		$logger->deactivate();
		try {
			$test = $sql->query("SELECT 1 FROM uoauth");
			$logger->activate();
			if (!$force_create_table)
				return;
		} catch (SQLError $e) {}
		$logger->activate();

		foreach([
			"DROP VIEW IF EXISTS v_uoauth;",
			"DROP TABLE IF EXISTS uoauth;",
		] as $drop) {
			if (!$sql->query_raw($drop)) {
				// @codeCoverageIgnoreStart
				$msg = "Cannot drop data:" . $sql->errmsg;
				$logger->error("OAuth: $msg");
				throw new OAuthStoreError($msg);
				// @codeCoverageIgnoreEnd
			}
		}

		$index = $sql->stmt_fragment('index');
		$engine = $sql->stmt_fragment('engine');
		$expire = $sql->stmt_fragment(
			'datetime', ['delta' => $this->adm_get_expiration()]);

		# Each row is associated with a session.sid. Associate the
		# two tables with $this->store->status() return value.
		$oauth_table = (
			"CREATE TABLE uoauth (" .
			"  aid %s," .
			"  sid INTEGER REFERENCES usess(sid) ON DELETE CASCADE," .
			"  oname VARCHAR(64)," .
			"  otype VARCHAR(12)," .
			"  access TEXT," .
			"  access_secret TEXT," .    # OAuth1.0 only
			"  refresh TEXT" .           # OAuth2.0 only
			") %s;"
		);
		$oauth_table = sprintf($oauth_table, $index, $engine);
		if (!$sql->query_raw($oauth_table)) {
			// @codeCoverageIgnoreStart
			$msg = "Cannot create uoauth table:" . $sql->errmsg;
			$logger->error("OAuth: $msg");
			throw new OAuthStoreError($msg);
			// @codeCoverageIgnoreEnd
		}

		$oauth_session_view = (
			"CREATE VIEW v_uoauth AS" .
			"  SELECT" .
			"    uoauth.*," .
			"    usess.token," .
			"    usess.expire" .
			"  FROM uoauth, usess" .
			"  WHERE" .
			"    uoauth.sid=usess.sid;"
		);
		if (!$sql->query_raw($oauth_session_view)) {
			// @codeCoverageIgnoreStart
			$msg = "Cannot create v_oauth view:" . $sql->errmsg;
			$logger->error("OAuth: $msg");
			throw new OAuthStoreError($msg);
			// @codeCoverageIgnoreEnd
		}
	}

	/**
	 * Get active OAuth* tokens given a session token.
	 *
	 * @param string $session_token Session token.
	 * @return dict|null Dict of tokens and oauth information of
	 *     current service.
	 */
	public function adm_get_oauth_tokens($session_token) {
		$sql = $this->store;
		$dtnow = $sql->stmt_fragment('datetime', ['delta' => 0]);
		$stmt = (
			"SELECT oname, otype, access, access_secret, refresh " .
			"FROM v_uoauth " .
			"WHERE token=? AND expire>%s " .
			"ORDER BY sid DESC LIMIT 1"
		);
		$stmt = sprintf($stmt, $dtnow);
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
	public function oauth_add_service(
		$service_type, $service_name,
		$consumer_key, $consumer_secret,
		$url_token, $url_token_auth, $url_access,
		$scope, $url_callback
	) {
		if (!in_array($service_type, ['10', '20']))
			throw new OAuthError(
				"Invalid service type: '$service_type'.");

		$key = $service_name . '-' . $service_type;
		if (isset($this->oauth_service_configs[$key]))
			return false;

		$this->oauth_service_configs[$key] = [
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
	}

	# super-oauth methods

	/**
	 * Instantiate OAuth*Permission class.
	 *
	 * @param string $service_type Service type as stored in config.
	 * @param string $service_name Service name as stored in config.
	 */
	public function oauth_get_permission_instance(
		$service_type, $service_name
	) {
		$key = $service_name . '-' . $service_type;
		if (!isset($this->oauth_service_configs[$key]))
			# key invalid
			return null;
		$conf = $this->oauth_service_configs[$key];
		extract($conf, EXTR_SKIP);
		if ($service_type == '10') {
			$perm = new zo\OAuth10Permission(
				$consumer_key, $consumer_secret,
				$url_request_token, $url_request_token_auth,
				$url_access_token, $url_callback
			);
		} else {
			$perm = new zo\OAuth20Permission(
				$consumer_key, $consumer_secret,
				$url_request_token_auth, $url_access_token,
				$url_callback, $scope
			);
		}
		if (method_exists($this, 'http_client')) {
			$perm->http_client_custom = function($kwargs) {
				return $this->http_client($kwargs);
			};
		}
		return $perm;
	}

	/**
	 * Instantiate OAuth*Action class.
	 *
	 * When succeeds, each instance has request() method that we
	 * can use to make any request. Especially for OAuth2.0, there's
	 * also refresh() method to refresh token when its access token
	 * is expired.
	 *
	 * @param string $service_type Service type as stored in config.
	 * @param string $service_name Service name as stored in config.
	 * @param string $access_token Access token returned by site_callback()
	 *     or retrieved from storage.
	 * @param string $access_token_secret Access token secret returned
	 *     by site_callback() or retrived. OAuth1.0 only.
	 * @param string $refresh_token Refresh token returned by
	 *     $this->route_byway_callback() or retrieved. OAuth2.0 only.
	 */
	public function oauth_get_action_instance(
		$service_type, $service_name,
		$access_token, $access_token_secret=null,
		$refresh_token=null
	) {
		$key = $service_name . '-' . $service_type;
		if (!isset($this->oauth_service_configs[$key]))
			# key invalid
			return null;
		$conf = $this->oauth_service_configs[$key];
		extract($conf, EXTR_SKIP);
		if ($service_type == '10') {
			$act = new zo\OAuth10Action(
				$conf['consumer_key'], $conf['consumer_secret'],
				$access_token, $access_token_secret
			);
		} else {
			$act = new zo\OAuth20Action(
				$conf['consumer_key'], $conf['consumer_secret'],
				$access_token, $refresh_token,
				$conf['url_access_token']
			);
		}
		if (method_exists($this, 'http_client')) {
			$act->http_client_custom = function($kwargs) {
				return $this->http_client($kwargs);
			};
		}
		return $act;
	}

	/**
	 * Default profile fetcher.
	 *
	 * Use this to populate user bio after user is successfully
	 * authenticated.
	 *
	 * @param object Instance of OAuth action.
	 * @param string $service_type Service type.
	 * @param string $service_name Service name.
	 * @param array $kwargs Additional arguments.
	 * @return dict On successful authentication, a dict of the
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
	 */
	public function oauth_fetch_profile(
		$oauth_action, $service_type, $service_name, $kwargs=[]
	) {
		return [];
	}


	public function oauth_add_user(
		$service_type, $service_name, $uname, $access_token,
		$access_token_secret=null, $refresh_token=null, $profile=[]
	) {
		# build passwordless account using obtained uname with uservice
		# having the form %service_name%[%service_type%]

		$uservice = sprintf('%s[%s]', $service_name, $service_type);
		$args['service'] = [
			'uname' => $uname,
			'uservice' => $uservice,
		];

		# register passwordless

		$retval = $this->adm_self_add_user_passwordless($args);
		if ($retval[0] !== 0)
			# saving data fails, most likely server error
			return [2];
			#return $this->_route_byway_failed();
		if (!isset($retval[1]) || !isset($retval[1]['token']))
			return [3];
			#return $this->_route_byway_failed();
		$udata = $retval[1];
		$session_token = $udata['token'];

		$sql = $this->store;

		# save additional udate from profile retriever if exists

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

		$sid = $retval[1]['sid'];
		# inserted data
		$ins = [
			'sid' => $sid,
			'oname' => $service_name,
			'otype' => $service_type,
			'access' => $access_token,
		];
		if ($access_token_secret)
			$ins['access_secret'] = $access_token_secret;
		if ($refresh_token)
			$ins['refresh'] = $refresh_token;
		$sql->insert('uoauth', $ins);

		return [0, $session_token];

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
	public function oauth_get_action_from_session($session_token) {
		$tokens = $this->adm_get_oauth_tokens($session_token);
		if (!$tokens)
			return null;
		return $this->oauth_get_action_instance(
			$tokens['otype'], $tokens['oname'], $tokens['access'],
			$tokens['access_secret'], $tokens['refresh']
		);
	}
}

