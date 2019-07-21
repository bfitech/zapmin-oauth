<?php declare(strict_types=1);


namespace BFITech\ZapAdmin;


use BFITech\ZapCore\Common;
use BFITech\ZapCore\Router;
use BFITech\ZapOAuth\OAuthError;


/**
 * Default routers.
 *
 * This is usually sufficient for standard OAuth authentication.
 *
 * @see ./tests/htdocs-test/index for usage.
 * @see Route.
 */
class OAuthRouteDefault extends Route {

	/**
	 * Constructor.
	 *
	 * @param Router $core Router instance.
	 * @param AuthCtrl $ctrl AuthCtrl instance.
	 * @param AuthManage $manage AuthManage instance.
	 */
	public function __construct(
		Router $core, AuthCtrl $ctrl, OAuthManage $manage
	) {
		parent::__construct($core, $ctrl, $manage);
	}

	/**
	 * Route callback for OAuth* token request URL generator.
	 *
	 * @param array $args Router variables. This must contain sub-keys:
	 *     `service_type` and `service_name` in `params` key.
	 */
	public function route_byway_auth(array $args) {
		$service_type = $service_name = null;
		$core = self::$core;
		$params = $args['params'];
		if (!Common::check_idict($params,
			['service_type', 'service_name'])
		) {
			return $core::pj([OAuthError::INCOMPLETE_DATA], 404);
		}
		extract($params);

		$perm = self::$manage->get_permission_instance(
			$service_type, $service_name);
		if (!$perm)
			# service unknown
			return $core::pj([OAuthError::SERVICE_UNKNOWN], 404);
		$perm = $this->finetune_permission($args, $perm);

		$url = $perm->get_access_token_url();
		if (!$url)
			# access token url not obtained
			return $core::pj([OAuthError::ACCESS_URL_MISSING], 503);
		return $core::pj([0, $url]);
	}

	/**
	 * Wrapper for callback error handler.
	 */
	private function _route_byway_failed() {
		$core = self::$core;
		$manage = self::$manage;
		# fail redirect available
		if ($manage->callback_fail_redirect)
			return $core->redirect($manage->callback_fail_redirect);
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
	public function route_byway_callback(array $args) {

		$core = self::$core;
		$manage = self::$manage;
		$admin = self::$manage::$admin;
		$log = self::$ctrl::$logger;

		$params = $args['params'];
		if (!Common::check_idict($params,
			['service_name', 'service_type'])
		) {
			return $core->abort(404);
		}
		extract($params);

		$perm = $manage->get_permission_instance(
			$service_type, $service_name);
		if (!$perm) {
			$log->info('ZapOAuth: attempts to use unknown service.');
			return $core->abort(404);
		}
		$perm = $manage->finetune_permission($args, $perm);

		// @todo Tell $this->_route_byway_failed to differ between
		// provider error, server error, or user rejects authentication.
		// This may be different from one provider to another.
		$ret = $perm->site_callback($args['get']);
		if ($ret[0] !== 0) {
			$log->info(
				'ZapOAuth: access token not obtained from callback.');
			return $this->_route_byway_failed();
		}
		$log->info(
			'ZapOAuth: Callback response: ' . json_encode($ret[1]));
		extract($ret[1]);

		# save obtained tokens to properties

		if (!isset($access_token_secret))
			# OAuth1.0 only
			$access_token_secret = null;
		if (!isset($refresh_token))
			# OAuth2.0 only
			$refresh_token = null;

		// @codeCoverageIgnoreStart
		$act = $manage->get_action_instance(
			$service_type, $service_name, $access_token,
			$access_token_secret, $refresh_token);
		// @codeCoverageIgnoreEnd

		# fetch profile, specific to each service

		$profile = $manage->fetch_profile(
			$act, $service_type, $service_name);
		if (!$profile || !isset($profile['uname'])) {
			$log->error('ZapOAuth: fetching profile failed.');
			return $this->_route_byway_failed();
		}
		$log->debug(sprintf(
			"ZapOAuth: fetch profile : %s.", json_encode($profile)));
		$uname = $profile['uname'];

		// @codeCoverageIgnoreStart
		$session_token = $manage->add_user(
			$service_type, $service_name,
			$uname, $access_token, $access_token_secret,
			$refresh_token, $profile
		);
		// @codeCoverageIgnoreEnd
		$expiration = $admin::$store->time() + $admin->get_expiration();

		# always autologin on success

		self::$ctrl->set_token_value($session_token);
		$core->send_cookie($this->token_name, $session_token,
			$expiration, '/');
		$log->debug(sprintf(
			"ZapOAuth: set-cookie [%s] <- %s.",
			$this->token_name, $session_token));

		# success
		if ($manage->callback_ok_redirect)
			# redirect
			return $core->redirect($manage->callback_ok_redirect);
		# or just go home
		return $core->redirect($core->get_home());
	}

}
