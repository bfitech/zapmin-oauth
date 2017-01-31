<?php


namespace BFITech\ZapOAuth;

use BFITech\ZapAdmin as za;


class OAuthError extends \Exception {}

class OAuthRoute extends za\AdminRoute {

	/**
	 * Service register.
	 *
	 * Services are stored in a dict with keys of the form:
	 * $service_name . '-' . $service_type.
	 */
	private $oauth_service_configs = [];

	/**
	 * Constructor.
	 *
	 * This takes arguments exactly the same with parent class.
	 */
	public function __construct(
		$home=null, $host=null,
		$dbargs=[], $expiration=null, $force_create_table=false,
		$token_name=null, $route_prefix=null
	) {
		parent::__construct($home, $host,
			$dbargs, $expiration, $create_table,
			$token_name, $route_prefix);
	}

	/**
	 * Create OAuth session table.
	 *
	 * This table is not for authentication since it's done by
	 * self::$store->status(). This is to retrieve OAuth* tokens
	 * and use them for request or refresh.
	 */
	private function create_table($force_create_table) {
		$sql = self::$store->sql;
		try {
			$test = $sql->query("SELECT uid FROM udata LIMIT 1");
			if (!$force_create_table)
				return;
		} catch (\PDOException $e) {}

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
			'datetime', ['delta' => $this->expiration]);

		# Each row is associated with a session.sid. Associate the
		# two tables with self::$store->status() return value.
		$oauth_table = (
			"CREATE TABLE uoauth (" .
			"  aid %s," .
			"  sid INTEGER REFERENCES usess(sid) ON DELETE CASCADE," .
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
			"CREATE VIEW v_oauth AS" .
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
	 * Get active OAuth* tokens given a session token.
	 *
	 * @param string $session_token Session token.
	 */
	public function get_oauth_tokens($session_token) {
		$sql = self::$store->sql;
		$dtnow = $sql->stmt_fragment('datetime');
		$stmt = (
			"SELECT otype, access, access_secret, refresh " .
			"FROM v_oauth " .
			"WHERE token=? AND expire>%s " .
			"ORDER BY sid DESC LIMIT 1"
		);
		$stmt = sprintf($stmt, $dtnow);
		return $sql->query($stmt, [$session_token]);
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
	 * @param function $callback_fetch_profile A function that fetch
	 *     profile that passes callback URL. It takes arguments:
	 *     - access_token, obtained by successful callback
	 *     - access_token_secret, 1.0 only
	 *     - current service configuration
	 *     - current object referred by $this, just so we can easily
	 *       use static method in it
	 *     It must return an array that at least has one keys 'uname'.
	 * @param string $url_callback Optional callback URL. If left null,
	 *     the value will be inferred. Services usually require this
	 *     to be explicitly set according to what you register in there,
	 *     or else, they will return error at oauth_get_url().
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
		if (isset($this->service_configs[$key]))
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

	/**
	 * Instantiate OAuth*Permission class.
	 */
	private function oauth_get_permission_instance(
		$service_name, $service_type
	) {
		$key = $service_name . '-' . $service_type;
		if (!isset($this->oauth_service_configs[$key]))
			# key invalid
			return null;
		$conf = $this->oauth_service_configs[$key];
		extract($conf, EXTR_SKIP);
		if ($key == '10') {
			return new OAuth10Permission(
				$consumer_key, $consumer_secret,
				$url_request_token, $url_request_token_auth,
				$url_access_token, $url_callback
			);
		} elseif ($key == '20') {
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
	 *     site_callback() or retrieved. OAuth2.0 only.
	 */
	public function oauth_get_action_instance(
		$service_name, $service_type,
		$access_token, $access_token_secret=null,
		$refresh_token=null
	) {
		$key = $service_name . '-' . $service_type;
		if (!isset($this->oauth_service_configs[$key]))
			# key invalid
			return null;
		$conf = $this->oauth_service_configs[$key];
		extract($conf, EXTR_SKIP);
		if ($key == '10') {
			return new OAuth10Action(
				$conf['consumer_key'], $conf['consumer_secret'],
				$access_token, $access_token_secret
			);
		} elseif ($key == '20') {
			return new OAuth10Action(
				$conf['consumer_key'], $conf['consumer_secret'],
				$access_token, $refresh_token,
				$conf['url_request_token_auth']
			);
		}
		return null;
	}

	/**
	 * Route callback for OAuth* token request URL generator.
	 *
	 * @param array $args HTTP variables. This must contain sub-keys:
	 *     'service_type' and 'service_name' in 'params' key. Failing
	 *     to do so will throw exception.
	 */
	public function oauth_get_auth_url($args) {
		$params = $args['params'];
		extract($params, EXTR_SKIP);

		if (!self::$core->check_dict(
			$params, ['service_name', 'service_key'])
		)
			throw new OAuthError("Invalid path params.");

		$perm = $this->oauth_get_permission_instance(
			$service_name, $service_key);
		if (!$perm)
			# service unknown
			return $this->_json([2, 0], 404);

		$url = $perm->get_access_token_url();
		if (!$url)
			# access token url not obtained
			return $this->_json([2, 1], 404);
		return $this->_json([0, $url]);
	}

	/**
	 * Route callback for OAuth* URL callback.
	 *
	 * How unfortunate the namings are. First callback is Zap route
	 * callback method. The second is OAuth* URL callback.
	 *
	 * @param array $args HTTP variables. This must contain sub-keys:
	 *     'service_type' and 'service_name' in 'params' key.
	 */
	public function oauth_callback_url($args) {
		$params = $args['params'];
		extract($params, EXTR_SKIP);

		$perm = $this->oauth_get_permission_instance(
			$service_name, $service_key);
		if (!$perm)
			# service unknown
			return self::$core->abort(404);

		$ret = $perm->site_callback($args);
		if ($ret[0] !== 0) {
			# callback fail, let's call it server error
			return self::$core->abort(503);
		}
		extract($ret[1], EXTR_SKIP);

		if (!isset($access_token_secret))
			# OAuth1.0 only
			$access_token_secret = null;
		if (!isset($refresh_token))
			# OAuth2.0 only
			$refresh_token = null;

		# fetch profile, specific to each service

		$cb_profile = $conf[$key]['callback_fetch_profile'];
		$profile = $cb_profile($access_token, $access_token_secret,
			$conf[$key], $this);
		if (!$profile)
			# cannot fetch profile, most likely server error
			return self::$core->abort(503);

		# build passwordless account using obtained uname with uservice
		# having the form %service_name%[%service_type%]

		$uname = $profile['uname'];
		$uservice = sprintf('%s[%s]', $service_name, $service_type);
		$args['service'] = [
			'uname' => $uname,
			'uservice' => $uservice,
		];

		# save to udata

		$retval = $this->self_add_user_passwordless($args);
		if ($retval[0] !== 0)
			# saving data fails, most likely server error
			return self::$core->abort(503);
		if (!isset($retval[1]) || !isset($retval[1]['token']))
			return self::$core->abort(503);

		$session_token = $retval[1]['token'];

		# save to oauth table

		$sql = self::$store->sql;
		# $retval[1] currently doesn't have 'sid'. Query it first.
		if (!isset($retval[1]['sid'])) {
			$sid = $sql->query(
				"SELECT sid FROM usess WHERE token=? " .
				"ORDER BY sid DESC LIMIT 1",
				[$session_token])['sid'];
		} else {
			$sid = $retval[1]['sid'];
		}
		# inserted data
		$ins = ['sid' => $sid, 'access' => $access_token];
		if ($access_token_secret)
			$ins['access_secret'] = $access_token_secret;
		if ($refresh_token)
			$ins['refresh'] = $refresh_token;
		$sql->insert('oauth', $ins);

		# always autologin on success

		/** @todo Parametrizable OAuth session duration. */
		$this->set_user_token($session_token);
		setcookie(
			$this->get_token_name(), $token,
			time() + (3600 * 24 * 7), '/');

		# success, back home
		return self::$core->redirect('/');
	}
}

