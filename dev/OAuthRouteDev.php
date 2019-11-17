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
	 *
	 * `ZAPMIN_OAUTH_DEV` must be defined. GET request must contain a
	 * valid email address that's a superstring of OAuth service name.
	 * User fullname is generated based on this email address.
	 *
	 * On success, it redirects to ok URL. On failure, it redirects
	 * to fail URL with query string containing `code` for supposed
	 * HTTP code and `errno` for the cause of error. Failure does not
	 * mirror actual OAuth failure.
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

		$fail_url = $manage->callback_fail_redirect;
		if (!$fail_url)
			$fail_url = $core->get_home();

		$fail = function($code, $errno) use($core, $fail_url) {
			return $core->redirect(
				$fail_url . "?code=$code&errno=$errno");
		};

		$service_type = $service_name = null;
		$params = $args['params'];
		if (!Common::check_idict($params,
			['service_type', 'service_name'])
		) {
			return $fail(404, OAuthError::SERVICE_UNKNOWN);
		}
		extract($params);

		if (self::$ctrl->get_user_data())
			# already signed in
			return $core::pj([1], 401);

		$email = $args['get']['email'] ?? null;
		if (
			!$email ||
			filter_var($email, FILTER_VALIDATE_EMAIL) === false
		)
			# invalid email
			return $fail(403, OAuthError::INCOMPLETE_DATA);

		# validate against oauth provider based on email address, e.g.:
		# 'you@gmail.com' is valid for 'gmail' service.
		if (strpos($email, $service_name) === false)
			return $fail(404, OAuthError::SERVICE_UNKNOWN);

		if (!$manage->get_permission_instance(
			$service_type, $service_name))
			# service unknown
			return $fail(404, OAuthError::SERVICE_UNKNOWN);

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
		$core->redirect(($manage->callback_ok_redirect ?? '/'));
	}

	/**
	 * Fake status.
	 */
	public function route_fake_status() {
		return self::$core::pj(self::$ctrl->get_safe_user_data());
	}

}
