<?php declare(strict_types=1);


namespace BFITech\ZapAdmin;


use BFITech\ZapCore\Common;
use BFITech\ZapOAuth\OAuthError;


/**
 * Default router callbacks.
 *
 * This is sufficient for functional OAuth authentication. See ./demo
 * for usage.
 */
class OAuthRouteDefault extends RouteAdmin {

	/**
	 * Route callback for OAuth* token request URL generator.
	 *
	 * @param array $args Router variables. This must contain sub-keys:
	 *     `service_type` and `service_name` in `params` key.
	 */
	public function route_byway_auth(array $args) {
		$core = self::$core;
		$log = self::$manage::$logger;

		# check params
		$params = $args['params'];
		if (!Common::check_idict($params,
			['service_type', 'service_name'])
		)
			return $core::pj([OAuthError::INCOMPLETE_DATA], 404);
		$service_type = $service_name = null;
		extract($params);

		# get permission instance
		$perm = self::$manage->get_permission_instance(
			$service_type, $service_name);
		if (!$perm) {
			# service unknown
			$log->info(sprintf(
				"ZapOAuth: Auth to unknown service: '%s-%s'",
				$service_type, $service_name));
			return $core::pj([OAuthError::SERVICE_UNKNOWN], 404);
		}
		$perm = self::$manage->finetune_permission($args, $perm);

		# get the access token
		$url = $perm->get_access_token_url();
		if (!$url)
			# access token url not obtained
			return $core::pj([OAuthError::ACCESS_URL_MISSING], 503);
		return $core::pj([0, $url]);
	}

	/** Wrapper for callback fail redirect. */
	private function _route_byway_failed() {
		$core = self::$core;
		$manage = self::$manage;
		# fail redirect available
		if ($manage->callback_fail_redirect)
			return $core->redirect($manage->callback_fail_redirect);
		# no redirect, let's call it server error
		return $core->abort(503);
	}

	/** Wrapper for callback ok redirect. */
	private function _route_byway_ok() {
		$core = self::$core;
		$manage = self::$manage;
		# ok redirect available
		if ($manage->callback_ok_redirect)
			return $core->redirect($manage->callback_ok_redirect);
		# go home otherwise
		return $core->redirect($core->get_home());
	}

	/**
	 * Route callback for OAuth* URL callback.
	 *
	 * How unfortunate the namings are. First callback is Router
	 * callback method. The second is OAuth* URL callback. This method
	 * must always redirect, whether the result is ok or fail.
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
	public function route_byway_callback(array $args) {
		$core = self::$core;
		$manage = self::$manage;
		$admin = $manage::$admin;
		$log = $manage::$logger;

		if ($manage->is_logged_in())
			# already signed in
			return $this->_route_byway_ok();

		# check params
		$params = $args['params'];
		if (!Common::check_idict($params,
			['service_name', 'service_type'])
		) {
			return $core->abort(404);
		}
		$service_type = $service_name = null;
		extract($params);

		# get permission instance
		$perm = $manage->get_permission_instance(
			$service_type, $service_name);
		if (!$perm) {
			# service unknown
			$log->info(sprintf(
				"ZapOAuth: Callback to unknown service: '%s-%s'",
				$service_type, $service_name));
			return $core->abort(404);
		}
		$perm = $manage->finetune_permission($args, $perm);

		# site callback
		// @todo Tell $this->_route_byway_failed to differ between
		// provider error, server error, or user rejecting
		// authentication. This may be different from one provider to
		// another.
		$ret = $perm->site_callback($args['get']);
		if ($ret[0] !== 0) {
			$log->info(
				'ZapOAuth: Callback has no access token.');
			return $this->_route_byway_failed();
		}
		$log->info(
			'ZapOAuth: Callback ok, response: ' . json_encode($ret[1]));
		extract($ret[1]);

		# save obtained tokens to properties
		if (!isset($access_token_secret))
			# OAuth1.0 only
			$access_token_secret = null;
		if (!isset($refresh_token))
			# OAuth2.0 only
			$refresh_token = null;

		# get action instance
		$act = $manage->get_action_instance(
			$service_type, $service_name, $access_token,
			$access_token_secret, $refresh_token);

		# use action instance to fetch profile, specific to each service
		$profile = $manage->fetch_profile(
			$act, $service_type, $service_name);
		if (!$profile || !isset($profile['uname'])) {
			$log->error('ZapOAuth: Fetching profile failed.');
			return $this->_route_byway_failed();
		}
		$log->debug(sprintf(
			"ZapOAuth: Profile fetched: %s.", json_encode($profile)));
		$uname = $profile['uname'];

		# add new user
		$session_token = $manage->add_user(
			$service_type, $service_name,
			$uname, $access_token, $access_token_secret,
			$refresh_token, $profile
		);

		# always autologin on success
		$expiration = $admin::$store->time() + $admin->get_expiration();
		self::$ctrl->set_token_value($session_token);
		$core::send_cookie($this->token_name, $session_token,
			$expiration, '/');
		// @todo Use this format on next zapcore.
		// $core::send_cookie_with_opts(
		// 	$this->token_name, $session_token, [
		// 		'path' => '/',
		// 		'expire' => $expiration,
		// 		'samesite' => 'Lax',
		// 	]);
		$log->debug(sprintf(
			"ZapOAuth: Set cookie: [%s -> %s].",
			$this->token_name, $session_token));

		# success
		return $this->_route_byway_ok();
	}

}
