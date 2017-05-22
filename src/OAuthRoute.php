<?php


namespace BFITech\ZapAdmin;


use BFITech\ZapCore\Common;
use BFITech\ZapCore\Router;
use BFITech\ZapCore\Logger;
use BFITech\ZapStore\SQL;


/**
 * OAuthRoute class.
 *
 * @see ./tests/htdocs-test/index for usage.
 * @see AdminRoute.
 */
class OAuthRoute extends OAuthStore {

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
		extract($params);

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
		extract($params);

		$perm = $this->oauth_get_permission_instance(
			$service_type, $service_name);
		if (!$perm)
			# service unknown
			return $core->abort(404);

		$ret = $perm->site_callback($args);
		if ($ret[0] !== 0)
			return $this->_route_byway_failed();
		extract($ret[1]);

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


	/**
	 * Wrapper for $this->core->route().
	 *
	 * @param string $path Standard zap router path.
	 * @param callable $callback Standard zap router callback.
	 * @param string|array $method Standard zap router request
	 *     method(s).
	 */
	public function route($path, $callback, $method='GET') {
		$this->core->route($path, $callback, $method);
	}
}

