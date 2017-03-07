<?php


namespace BFITech\ZapOAuth;

use BFITech\ZapCore as zc;
use BFITech\ZapStore as zs;
use BFITech\ZapAdmin as za;


class OAuthError extends \Exception {}


/**
 * OAuthRoute class.
 */
class OAuthRoute extends za\AdminRoute {

	/**
	 * Service register.
	 *
	 * Services are stored in a dict with keys of the form:
	 * $service_name . '-' . $service_type.
	 */
	private $oauth_service_configs = [];

	# service
	private $service_name = null;
	private $service_type = null;

	# tokens
	private $access_token = null;
	private $access_token_secret = null;  # OAuth1.0 only
	private $refresh_token = null;        # OAuth2.0 only

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
	 *
	 * General workflow:
	 *
	 * 1. Instantiate OAuthRoute $o, let's call this super-oauth.
	 * 2. Create a profile callback, i.e. profile retriever when
	 *    authentication succeeds, which takes super-oauth as
	 *    parameter and returns a username on success.
	 * 3. Register services with $o->oauth_add_service() with
	 *    appropriate configuration. This includes profile callback
	 *    in 2).
	 * 4. Use route handler $o->route_byway_auth() for generating
	 *    access token.
	 * 5. Use route handler $o->route_byway_callback() for accepting
	 *    successful access token request.
	 * 6. Subsequent API requests need access (and access secret
	 *    tokens for OAuth1.0). These can be obtained with
	 *    $o->adm_get_oauth_tokens(), which takes zap session token
	 *    as parameter or in special case, null. e.g. when we
	 *    need to get token inside profile callback 2).
	 * 7. From super-oauth, we can instantiate the real oauth{1,2}
	 *    class with $c = $o->oauth_get_action_instance(), taking
	 *    tokens provided by 6 as parameter(s). This instance
	 *    has $c->request() method with which we can do requests to
	 *    the API service. For OAuth2.0, it also has $c->refresh()
	 *    for token refresh.
	 *
	 * @see BFITech\\ZapAdmin\\AdminRoute.
	 */
	public function __construct(
		$home_or_kwargs=null, $host=null, $shutdown=true,
		$dbargs=[], $expiration=null, $force_create_table=false,
		$token_name=null, $route_prefix=null,
		$core_instance=null, $store_instance=null
	) {
		if (is_array($home_or_kwargs)) {
			extract(zc\Common::extract_kwargs($home_or_kwargs, [
				'home' => null,
				'host' => null,
				'shutdown' => true,
				'dbargs' => [],
				'expiration' => null,
				'force_create_table' => false,
				'token_name' => null,
				'route_prefix' => null,
				'core_instance' => null,
				'store_instance' => null,
			]));
		} else {
			$home = $home_or_kwargs;
		}
		parent::__construct(
			$home, $host, $shutdown,
			$dbargs, $expiration, $force_create_table,
			$token_name, $route_prefix,
			$core_instance, $store_instance
		);

		$this->oauth_create_table($force_create_table);
	}

	/**
	 * Create OAuth session table.
	 *
	 * This table is not for authentication since it's done by
	 * self::$store->status(). This is to retrieve OAuth* tokens
	 * and use them for request or refresh.
	 */
	private function oauth_create_table($force_create_table) {
		$sql = self::$store;
		try {
			$test = $sql->query("SELECT 1 FROM uoauth");
			if (!$force_create_table)
				return;
		} catch (zs\SQLError $e) {}

		foreach([
			"DROP VIEW IF EXISTS v_uoauth;",
			"DROP TABLE IF EXISTS uoauth;",
		] as $drop) {
			if (!$sql->query_raw($drop))
				throw new za\AdminStoreError(
					"Cannot drop data:" . $sql->errmsg);
		}

		$index = $sql->stmt_fragment('index');
		$engine = $sql->stmt_fragment('engine');
		$expire = $sql->stmt_fragment(
			'datetime', ['delta' => $this->adm_get_expiration()]);

		# Each row is associated with a session.sid. Associate the
		# two tables with self::$store->status() return value.
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
		if (!$sql->query_raw($oauth_table))
			throw new za\AdminStoreError(
				"Cannot create uoauth table:" . $sql->errmsg);

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
		if (!$sql->query_raw($oauth_session_view))
			throw new AdminStoreError(
				"Cannot create v_oauth view:" . $sql->errmsg);
	}

	/**
	 * Get active OAuth* tokens.
	 *
	 * If session token is supplied, this will retrieve from
	 * database. Otherwise this will just dump current tokens in the
	 * instance regardless the value. Latter case might be useful
	 * when token has just been obtained, e.g. from within
	 * callback_fetch_profile in the config.
	 *
	 * @param string $session_token Session token.
	 * @return array Array of tokens and oauth information of
	 *     current service.
	 */
	public function adm_get_oauth_tokens($session_token=null) {
		if (!$session_token) {
			return [
				'oname' => $this->service_name,
				'otype' => $this->service_type,
				'access' => $this->access_token,
				'access_secret' => $this->access_token_secret,
				'refresh' => $this->refresh_token,
			];
		}
		$sql = self::$store;
		$dtnow = $sql->stmt_fragment('datetime');
		$stmt = (
			"SELECT oname, otype, access, access_secret, refresh " .
			"FROM v_oauth " .
			"WHERE token=? AND expire>%s " .
			"ORDER BY sid DESC LIMIT 1"
		);
		$stmt = sprintf($stmt, $dtnow);
		$result = $sql->query($stmt, [$session_token]);
		if ($result)
			return $result;
		return [
			'oname' => null,
			'otype' => null,
			'access' => null,
			'access_secret' => null,
			'refresh' => null,
		];
	}

	/**
	 * Register available services.
	 *
	 * @param string $consumer_key The key you obtain from the service.
	 * @param string $consumer_secret The secret you obtain along with
	 *     consumer key.
	 * @param string $service_name A nickname of the service, short
	 *     alphabetic lowercase, e.g.: github.
	 * @param string $service_type OAuth version, '10' or '20'.
	 * @param string $url_token Token request URL. Not used by OAuth2.0.
	 * @param string $url_token_auth Token request authentication URL.
	 * @param string $url_access Access token URL for callback URL.
	 * @param string $scope Access scope, service-independent.
	 * @param function $callback_fetch_profile A function which fetches
	 *     profile data after $this->route_byway_callback() succeeds. This
	 *     must return a dict with at least one key `uname`, or null with
	 *     fetching failed. This takes arguments:
	 *     - access_token, obtained by successful callback
	 *     - access_token_secret, 1.0 only
	 *     - current service configuration
	 *     - reference to $this, just so we can easily use static method
	 *       on it
	 * @param string $url_callback Optional callback URL. If left null,
	 *     the value will be inferred. Services usually require this
	 *     to be explicitly set according to what you register in there,
	 *     or else, they will return error at $this->route_byway_callback().
	 */
	public function oauth_add_service(
		$consumer_key, $consumer_secret,
		$service_name, $service_type,
		$url_token, $url_token_auth, $url_access,
		$scope, $callback_fetch_profile,
		$url_callback=null
	) {
		if (!in_array($service_type, ['10', '20']))
			throw new OAuthError(sprintf(
				"Invalid service type: '%s'.",
				$service_type));

		$key = $service_name . '-' . $service_type;
		if (isset($this->oauth_service_configs[$key]))
			return false;

		if (!$url_callback) {
			# default callback URL
			$url_callback = self::$core->get_host();
			$url_callback .= sprintf(
				'%sbyway/oauth/%s/%s/callback',
				$this->prefix, $service_type, $service_name);
		}

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
			'callback_fetch_profile' => $callback_fetch_profile,
		];
	}

	# super-oauth methods

	/**
	 * Instantiate OAuth*Permission class.
	 */
	private function oauth_get_permission_instance(
		$service_name, $service_type
	) {
		$this->service_name = $service_name;
		$this->service_type = $service_type;
		$key = $service_name . '-' . $service_type;
		if (!isset($this->oauth_service_configs[$key]))
			# key invalid
			return null;
		$conf = $this->oauth_service_configs[$key];
		extract($conf, EXTR_SKIP);
		if ($service_type == '10') {
			return new OAuth10Permission(
				$consumer_key, $consumer_secret,
				$url_request_token, $url_request_token_auth,
				$url_access_token, $url_callback
			);
		} elseif ($service_type == '20') {
			return new OAuth20Permission(
				$consumer_key, $consumer_secret,
				$url_request_token_auth, $url_access_token,
				$url_callback, $scope
			);
		}
		return null;
	}

	/**
	 * Instantiate OAuth*Action class.
	 *
	 * When succeeds, each instance has request() method that we
	 * can use to make any request. Especially for OAuth2.0, there's
	 * also refresh() method to refresh token when its access token
	 * is expired.
	 *
	 * @param string $service_name Service name as stored in config.
	 * @param string $service_type Service type as stored in config.
	 * @param string $access_token Access token returned by site_callback()
	 *     or retrieved from storage.
	 * @param string $access_token_secret Access token secret returned
	 *     by site_callback() or retrived. OAuth1.0 only.
	 * @param string $refresh_token Refresh token returned by
	 *     $this->route_byway_callback() or retrieved. OAuth2.0 only.
	 */
	public function oauth_get_action_instance(
		$service_name, $service_type,
		$access_token, $access_token_secret=null,
		$refresh_token=null
	) {
		$this->service_name = $service_name;
		$this->service_type = $service_type;
		$key = $service_name . '-' . $service_type;
		if (!isset($this->oauth_service_configs[$key]))
			# key invalid
			return null;
		$conf = $this->oauth_service_configs[$key];
		extract($conf, EXTR_SKIP);
		if ($service_type == '10') {
			return new OAuth10Action(
				$conf['consumer_key'], $conf['consumer_secret'],
				$access_token, $access_token_secret
			);
		} elseif ($service_type == '20') {
			return new OAuth20Action(
				$conf['consumer_key'], $conf['consumer_secret'],
				$access_token, $refresh_token,
				$conf['url_request_token_auth']
			);
		}
		return null;
	}

	# route handlers

	/**
	 * Route callback for OAuth* token request URL generator.
	 *
	 * @param array $args HTTP variables. This must contain sub-keys:
	 *     `service_type` and `service_name` in `params` key. Failing
	 *     to do so will throw exception.
	 */
	public function route_byway_auth($args) {
		$params = $args['params'];
		if (!zc\Common::check_dict($params,
			['service_name', 'service_type'])
		) {
			throw new OAuthError("Invalid path params.");
		}
		extract($params, EXTR_SKIP);

		$perm = $this->oauth_get_permission_instance(
			$service_name, $service_type);
		if (!$perm)
			# service unknown
			return zc\Header::pj([2, 0], 404);

		$url = $perm->get_access_token_url();
		if (!$url)
			# access token url not obtained
			return zc\Header::pj([2, 1], 404);
		return zc\Header::pj([0, $url]);
	}

	/**
	 * Wrapper for callback error handler.
	 */
	private function _route_byway_failed() {
		# fail redirect available
		if ($this->oauth_callback_fail_redirect)
			return self::$core->redirect(
				$this->oauth_callback_fail_redirect);
		# no redirect, let's call it server error
		return self::$core->abort(503);
	}

	/**
	 * Route callback for OAuth* URL callback.
	 *
	 * How unfortunate the namings are. First callback is Zap route
	 * callback method. The second is OAuth* URL callback.
	 *
	 * @param array $args HTTP variables. This must contain sub-keys:
	 *     `service_type` and `service_name` in `params` key.
	 */
	public function route_byway_callback($args) {
		$params = $args['params'];
		if (!zc\Common::check_dict($params,
			['service_name', 'service_type'])
		) {
			throw new OAuthError("Invalid path params.");
		}
		extract($params, EXTR_SKIP);

		$key = $service_name . '-' . $service_type;
		if (!isset($this->oauth_service_configs[$key]))
			# key invalid
			return null;
		$conf = $this->oauth_service_configs[$key];

		$perm = $this->oauth_get_permission_instance(
			$service_name, $service_type);
		if (!$perm)
			# service unknown
			return self::$core->abort(404);

		$ret = $perm->site_callback($args);
		if ($ret[0] !== 0)
			return $this->_route_byway_failed();
		extract($ret[1], EXTR_SKIP);

		if (!isset($access_token_secret))
			# OAuth1.0 only
			$access_token_secret = null;
		if (!isset($refresh_token))
			# OAuth2.0 only
			$refresh_token = null;

		$this->access_token = $access_token;
		$this->access_token_secret = $access_token_secret;
		$this->refresh_token = $refresh_token;

		# fetch profile, specific to each service

		$cb_profile = $conf['callback_fetch_profile'];
		$profile = $cb_profile($this);
		if (!$profile)
			# cannot fetch profile, most likely server error
			return $this->_route_byway_failed();

		# build passwordless account using obtained uname with uservice
		# having the form %service_name%[%service_type%]

		$uservice = sprintf('%s[%s]', $service_name, $service_type);
		$args['service'] = [
			'uname' => $profile['uname'],
			'uservice' => $uservice,
		];

		# register passwordless

		$retval = $this->adm_self_add_user_passwordless($args);
		if ($retval[0] !== 0)
			# saving data fails, most likely server error
			return $this->_route_byway_failed();
		if (!isset($retval[1]) || !isset($retval[1]['token']))
			return $this->_route_byway_failed();
		$nudata = $retval[1];
		$session_token = $nudata['token'];

		# save additional udate from profile retriever if exists
		$sql = self::$store;

		$updata = [];
		foreach (['fname', 'email', 'site'] as $key) {
			if (isset($profile[$key]))
				$updata[$key] = $profile[$key];
		}
		if (isset($updata['email']))
			$updata['email_verified'] = 1;
		if ($updata)
			$sql->update('udata', $updata, [
				'uid' => $nudata['uid']
			]);

		# save to oauth table

		$sid = $retval[1]['sid'];
		# inserted data
		$ins = [
			'sid' => $sid,
			'oname' => $this->service_name,
			'otype' => $this->service_type,
			'access' => $access_token,
		];
		if ($access_token_secret)
			$ins['access_secret'] = $access_token_secret;
		if ($refresh_token)
			$ins['refresh'] = $refresh_token;
		$sql->insert('uoauth', $ins);

		# always autologin on success

		/** @todo Parametrizable OAuth session duration. */
		$this->adm_set_user_token($session_token);
		setcookie(
			$this->adm_get_token_name(), $session_token,
			time() + (3600 * 24 * 7), '/');

		# success
		if ($this->oauth_callback_ok_redirect)
			# redirect
			return self::$core->redirect(
				$this->oauth_callback_ok_redirect);
		# or just go home
		return self::$core->redirect(self::$core->get_home());
	}
}

