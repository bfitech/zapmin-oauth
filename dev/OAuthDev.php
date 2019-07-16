<?php declare(strict_types=1);


namespace BFITech\ZapAdminDev;


use BFITech\ZapCore\Common;
use BFITech\ZapOAuth\OAuthError;
use BFITech\ZapAdmin\OAuthRouteDefault;


/**
 * OAuth routing for development.
 */
class OAuthRouteDev extends OAuthRouteDefault {

	/**
	 * Fake login.
	 *
	 * This provides a fake OAuth authentication without actually using
	 * a real OAuth server. Use this for development purpose only.
	 * `ZAPMIN_OAUTH_DEV` must be defined. GET request must contain a
	 * valid email address that's a superstring of OAuth service name.
	 * User fullname is generated based on this email address.
	 *
	 * @param array $args Router variables exactly the same with those
	 *     in OAuthRoute::route_byway_auth.
	 *
	 * @if TRUE
	 * @SuppressWarnings(PHPMD.CyclomaticComplexity)
	 * @SuppressWarnings(PHPMD.NPathComplexity)
	 * @endif
	 */
	public function route_fake_login(array $args) {
		$core = self::$core;
		$manage = self::$manage;

		# safeguard so that this won't leak to production
		if (!defined('ZAPMIN_OAUTH_DEV'))
			return $core->abort(404);

		$service_type = $service_name = null;
		$params = $args['params'];
		if (!Common::check_idict($params,
			['service_type', 'service_name'])
		) {
			return $core::pj([OAuthError::SERVICE_UNKNOWN], 404);
		}
		extract($params);

		if (self::$ctrl->get_user_data())
			return $core::pj([1], 401);

		if (!isset($args['get']['email']))
			return $core::pj([OAuthError::INCOMPLETE_DATA], 403);
		$email = $args['get']['email'];
		if (filter_var($email, FILTER_VALIDATE_EMAIL) === false)
			return $core::pj([OAuthError::INCOMPLETE_DATA], 403);

		# determine oauth provider based on email address, e.g.:
		# 'you@gmail.com' is valid for 'gmail' service.
		if (strpos($email, $service_name) === false)
			return $core::pj([OAuthError::SERVICE_UNKNOWN], 404);

		$perm = $manage->get_permission_instance(
			$service_type, $service_name);
		if (!$perm)
			# service unknown
			return $core::pj([OAuthError::SERVICE_UNKNOWN], 404);

		$uname = preg_replace("![^a-z0-9]!", '', $email);
		$access_token = md5($uname . $email . mt_rand());
		$access_token_secret = $service_type != '10' ? null :
			$access_token_secret = "xxx-" . $access_token;
		// @codeCoverageIgnoreStart
		$token = $manage->add_user(
			$service_type, $service_name,
			$uname, $access_token, $access_token_secret, null,
			[
				'fname' => ucfirst($uname) . " Sample",
				'email' => $email,
			]
		);
		// @codeCoverageIgnoreEnd
		self::$ctrl->set_token_value($token);

		$core::send_cookie(
			$this->token_name, $token, time() + (3600 * 6), '/');
		$redirect = $manage->callback_ok_redirect ?? '/';
		$core->redirect($redirect);
	}

	/**
	 * Fake status.
	 */
	public function route_fake_status() {
		return self::$core->pj(self::$ctrl->get_safe_user_data());
	}

}
