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
	 * a real OAuth server. Use this for development purposes only.
	 * `ZAPMIN_OAUTH_DEV` must be defined for this callback to work.
	 *
	 * On success, the data section of JSON response contains ok URL to
	 * redirect to. On failure, the errno is >0 and the data is null.
	 * Failure does not mirror actual OAuth failure.
	 *
	 * @param array $args Router variables exactly the same with those
	 *     in OAuthRouteDefault::route_byway_auth. For successful fake
	 *     login, args must contain:
	 *     - `params`:
	 *       -  `service_type`: registered service type
	 *       -  `service_name`: registered service name
	 *     - `get`:
	 *       -  `email`: valid email address that's a superstring of
	 *          `service_name`; username and fullname is generated based
	 *          on this email address
	 */
	public function route_fake_login(array $args) {
		$core = self::$core;
		$manage = self::$manage;
		$redirect_ok = $manage->callback_ok_redirect ?? '/';

		# safeguard so that this won't leak to production
		if (!defined('ZAPMIN_OAUTH_DEV'))
			return $core->abort(404);

		$service_type = $service_name = null;
		$params = $args['params'];
		if (!Common::check_idict($params,
			['service_type', 'service_name'])
		)
			return $core::pj([OAuthError::SERVICE_UNKNOWN], 403);
		extract($params);

		if (self::$ctrl->get_user_data())
			# already signed in
			return $core::pj([0, $redirect_ok]);

		$email = $args['get']['email'] ?? '';
		$errno = $this->check_email($email, $service_name);
		if ($errno != 0)
			return $core::pj([$errno], 403);

		if (!$manage->get_permission_instance(
			$service_type, $service_name)
		)
			# service unknown
			return $core::pj([OAuthError::SERVICE_UNKNOWN], 403);

		$uname = preg_replace("![^a-z0-9]!", '', $email);
		$access_token = md5($uname . $email . mt_rand());
		$access_token_secret = $service_type != '10'
			? null : "xxx-" . $access_token;
		$token = $manage->add_user(
			$service_type, $service_name,
			$uname, $access_token, $access_token_secret, null,
			[
				'fname' => ucfirst($uname) . " Sample",
				'email' => $email,
			]
		);

		$core::send_cookie_with_opts(
			$this->token_name, $token, [
				'path' => '/',
				'expires' => time() + 3600,
				'httponly' => true,
				'samesite' => 'Lax',
			]);

		return $core::pj([0, $redirect_ok]);
	}

	private function check_email(string $email, string $service_name) {
		if (
			!$email ||
			filter_var($email, FILTER_VALIDATE_EMAIL) === false
		)
			# invalid email
			return OAuthError::INCOMPLETE_DATA;

		# validate against service name, e.g.: 'you@gmail.example.com'
		# is valid for 'gmail' service.
		if (strpos($email, $service_name) === false)
			return OAuthError::SERVICE_UNKNOWN;

		return 0;
	}

	/**
	 * Fake status.
	 */
	public function route_fake_status() {
		return self::$core::pj(self::$ctrl->get_safe_user_data());
	}

}
