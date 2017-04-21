<?php


namespace BFITech\ZapAdmin;


use BFITech\ZapCore\Common;
use BFITech\ZapCore\Router;
use BFITech\ZapCore\Logger;
use BFITech\ZapStore\SQL;


/**
 * OAuthRoute class.
 */
class OAuthRoute extends OAuthStore {

	/**
	 * Core instance.
	 */
	public $core;

	/**
	 * Token name.
	 *
	 * @fixme Must manually store here since adm_get_token_name()
	 *     unfortunately belongs to AdminRoute which is not
	 *     inherited by this class.
	 */
	public $token_name;

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
	 * @see AdminRoute.
	 */
	public function __construct(
		Router $core, SQL $store, $force_create_table=null,
		Logger $logger=null
	) {
		$this->core = $core;
		parent::__construct($store, $force_create_table, $logger);
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
		$core = $this->core;
		$params = $args['params'];
		if (!Common::check_idict($params,
			['service_name', 'service_type'])
		) {
			return $core::pj([2, 0], 404);
		}
		extract($params, EXTR_SKIP);

		$perm = $this->oauth_get_permission_instance(
			$service_type, $service_name);
		if (!$perm)
			# service unknown
			return $core::pj([2, 0], 404);

		$url = $perm->get_access_token_url();
		if (!$url)
			# access token url not obtained
			return $core::pj([2, 1], 404);
		return $core::pj([0, $url]);
	}

	/**
	 * Wrapper for callback error handler.
	 */
	private function _route_byway_failed() {
		$core = $this->core;
		# fail redirect available
		if ($this->oauth_callback_fail_redirect)
			return $core->redirect(
				$this->oauth_callback_fail_redirect);
		# no redirect, let's call it server error
		return $core->abort(503);
	}

	/**
	 * Route callback for OAuth* URL callback.
	 *
	 * How unfortunate the namings are. First callback is Zap route
	 * callback method. The second is OAuth* URL callback.
	 *
	 * @param dict $args Standard zap HTTP variables of the form:
	 *     @code
	 *     (dict){
	 *         'params': (dict){
	 *             'service_type': (string)service_type,
	 *             'service_name': (string)service_name,
	 *         }
	 *     }
	 *     @endcode
	 */
	public function route_byway_callback($args) {
		$core = $this->core;

		$params = $args['params'];
		if (!Common::check_idict($params,
			['service_name', 'service_type'])
		) {
			return $core->abort(404);
		}
		extract($params, EXTR_SKIP);

		$perm = $this->oauth_get_permission_instance(
			$service_type, $service_name);
		if (!$perm)
			# service unknown
			return $core->abort(404);

		$ret = $perm->site_callback($args);
		if ($ret[0] !== 0)
			return $this->_route_byway_failed();
		extract($ret[1], EXTR_SKIP);

		# save obtained tokens to properties

		if (!isset($access_token_secret))
			# OAuth1.0 only
			$access_token_secret = null;
		if (!isset($refresh_token))
			# OAuth2.0 only
			$refresh_token = null;

		$act = $this->oauth_get_action_instance(
			$service_type, $service_name, $access_token,
			$access_token_secret, $refresh_token);

		# fetch profile, specific to each service

		$profile = $this->oauth_fetch_profile($act,
			$service_type, $service_name);
		if (!$profile)
			return $this->_route_byway_failed();
		if (!isset($profile['uname']))
			return $this->_route_byway_failed();
		$uname = $profile['uname'];

		$rv = $this->oauth_add_user(
			$service_type, $service_name,
			$uname, $access_token, $access_token_secret,
			$refresh_token, $profile
		);
		if ($rv[0] !== 0)
			return $this->_route_byway_failed();

		$session_token = $rv[1];
		$expiration = $this->adm_get_byway_expiration();

		# always autologin on success

		$this->adm_set_user_token($session_token);
		# @fixme Proper token name getter.
		$token_name = $this->token_name
			? $this->token_name : 'zapoauth';
		$core::send_cookie($token_name, $session_token,
			$expiration, '/');

		# success
		if ($this->oauth_callback_ok_redirect)
			# redirect
			return $core->redirect($this->oauth_callback_ok_redirect);
		# or just go home
		return $core->redirect($core->get_home());
	}

	public function route($path, $callback, $method='GET') {
		$this->core->route($path, $callback, $method);
	}
}

