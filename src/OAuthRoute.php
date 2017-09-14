<?php


namespace BFITech\ZapAdmin;


use BFITech\ZapCore\Common;
use BFITech\ZapOAuth\OAuthError;


/**
 * OAuthRoute class.
 *
 * @see ./tests/htdocs-test/index for usage.
 * @see AdminRoute.
 */
class OAuthRoute extends OAuthStore {

	/**
	 * Route callback for OAuth* token request URL generator.
	 *
	 * @param array $args Router variables. This must contain sub-keys:
	 *     `service_type` and `service_name` in `params` key.
	 */
	public function route_byway_auth($args) {
		$service_type = $service_name = null;
		$core = $this->core;
		$params = $args['params'];
		if (!Common::check_idict($params,
			['service_type', 'service_name'])
		) {
			return $core::pj([OAuthError::INCOMPLETE_DATA], 404);
		}
		extract($params);

		$perm = $this->oauth_get_permission_instance(
			$service_type, $service_name);
		if (!$perm)
			# service unknown
			return $core::pj([OAuthError::SERVICE_UNKNOWN], 404);
		$perm = $this->oauth_finetune_permission($args, $perm);

		$url = $perm->get_access_token_url();
		if (!$url)
			# access token url not obtained
			return $core::pj([
				OAuthError::ACCESS_URL_MISSING], 503);
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
	 * How unfortunate the namings are. First callback is Router
	 * callback method. The second is OAuth* URL callback.
	 *
	 * @param dict $args Standard router HTTP variables of the form:
	 *     @code
	 *     (dict){
	 *         'params': (dict){
	 *             'service_type': (string)service_type,
	 *             'service_name': (string)service_name
	 *         }
	 *     }
	 *     @endcode
	 */
	public function route_byway_callback($args) {

		$core = $this->core;
		$logger = $this->logger;

		$params = $args['params'];
		if (!Common::check_idict($params,
			['service_name', 'service_type'])
		) {
			return $core->abort(404);
		}
		extract($params);

		$perm = $this->oauth_get_permission_instance(
			$service_type, $service_name);
		if (!$perm) {
			$logger->info(
				'ZapOAuth: user attempts to use unknown service.');
			return $core->abort(404);
		}
		$perm = $this->oauth_finetune_permission($args, $perm);

		// @todo Tell $this->_route_byway_failed to differ between
		// provider error, server error, or user rejects authentication.
		// This may be different from one provider to another.
		$ret = $perm->site_callback($args['get']);
		if ($ret[0] !== 0) {
			$logger->info(
				'ZapOAuth: access token not obtained from callback.');
			return $this->_route_byway_failed();
		}
		$logger->info(
				'ZapOAuth: Callback response: ' . json_encode($ret[1]));
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
		if (!$profile || !isset($profile['uname'])) {
			$logger->error('ZapOAuth: fetching profile failed.');
			return $this->_route_byway_failed();
		}
		$logger->debug(
			sprintf("ZapOAuth: fetch profile : %s.",
				json_encode($profile)));
		$uname = $profile['uname'];

		$session_token = $this->oauth_add_user(
			$service_type, $service_name,
			$uname, $access_token, $access_token_secret,
			$refresh_token, $profile
		);
		$expiration = $this->store->time() +
			$this->adm_get_byway_expiration();

		# always autologin on success

		$this->adm_set_user_token($session_token);
		$core->send_cookie($this->token_name, $session_token,
			$expiration, '/');
		$logger->debug(
			sprintf("ZapOAuth: set-cookie [%s] <- %s.",
				$this->token_name, $session_token));

		# success
		if ($this->oauth_callback_ok_redirect)
			# redirect
			return $core->redirect($this->oauth_callback_ok_redirect);
		# or just go home
		return $core->redirect($core->get_home());
	}

}
