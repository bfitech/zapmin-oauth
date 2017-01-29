<?php


namespace BFITech\ZapOAuth;

use BFITech\ZapAdmin as za;


class ZapOAuthError extends \Exception {}

class ZapOAuth extends za\AdminRouteDefault {

	private $oauth_service_configs = [];

	public function __construct(
		$home=null, $host=null,
		$dbargs=[], $expiration=null, $create_table=false,
		$token_name=null, $route_prefix=null
	) {
		parent::__construct($home, $host,
			$dbargs, $expiration, $create_table,
			$token_name, $route_prefix);

		# remove default _byway path
		#$this->delete_route('/byway', ['GET', 'POST']);

		# access token route
		$this->add_route(
			'/byway/oauth/<service_type>/<service_name>/auth',
			[$this, 'oauth_get_auth_url'], 'POST');

		# callback url route
		$this->add_route(
			'/byway/oauth/<service_type>/<service_name>/callback',
			[$this, 'oauth_callback_url'], 'GET');
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
	 *     the value will be inferred. Set this explicitly for testing
	 *     with different URLs.
	 */
	public function oauth_add_service(
		$consumer_key, $consumer_secret,
		$service_name, $service_type,
		$url_token, $url_token_auth, $url_access,
		$scope, $callback_fetch_profile,
		$url_callback=null
	) {
		if (!in_array($service_type, ['10', '20']))
			throw new ZapOAuthError(sprintf(
				"Invalid service type: '%s'.",
				$service_type));

		$key = $service_name . '-' . $service_type;
		if (isset($this->service_configs[$key]))
			return false;

		if (!$url_callback) {
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

	private function oauth_get_10_instance($key) {
		$conf = $this->oauth_service_configs[$key];
		extract($conf, EXTR_SKIP);
		return new OAuth10Permission(
			$consumer_key, $consumer_secret,
			$url_request_token, $url_request_token_auth,
			$url_access_token, $url_callback
		);
	}

	private function oauth_get_20_instance($key) {
		$conf = $this->oauth_service_configs[$key];
		extract($conf, EXTR_SKIP);
		return new OAuth20Permission(
			$consumer_key, $consumer_secret,
			$url_request_token_auth, $url_access_token,
			$url_callback, $scope
		);
	}

	protected function oauth_get_auth_url($args) {
		$params = $args['params'];
		extract($params, EXTR_SKIP);

		$key = $service_name . '-' . $service_type;
		if (!isset($this->oauth_service_configs[$key]))
			# key invalid
			return $this->_json([2, 0], 404);

		if ($service_type == '10') {
			$perm = $this->oauth_get_10_instance($key);
		} elseif ($service_type == '20') {
			$perm = $this->oauth_get_20_instance($key);
		} else {
			return $this->_json([2, 1], 404);
		}

		$url = $perm->get_access_token_url();
		if (!$url)
			# access token url not obtained
			return $this->_json([2, 2], 404);
		return $this->_json([0, $url]);
	}

	protected function oauth_callback_url($args) {
		$params = $args['params'];
		extract($params, EXTR_SKIP);

		$key = $service_name . '-' . $service_type;
		$conf = $this->oauth_service_configs;
		if (!isset($conf[$key]))
			# service unknown
			return self::$core->abort(404);

		if ($service_type == '10') {
			$perm = $this->oauth_get_10_instance($key);
		} elseif ($service_type == '20') {
			$perm = $this->oauth_get_20_instance($key);
		} else {
			return self::$core->abort(404);
		}
		$ret = $perm->site_callback($args);
		if ($ret[0] !== 0) {
			# callback fail, let's call it server error
			return self::$core->abort(503);
		}
		extract($ret[1], EXTR_SKIP);

		if (!isset($access_token_secret))
			# OAuth 2.0 doesn't need this.
			$access_token_secret = null;

		# fetch profile, specific to each service

		$cb_profile = $conf[$key]['callback_fetch_profile'];
		$profile = $cb_profile($access_token, $access_token_secret,
			$conf[$key], $this);
		if (!$profile)
			# cannot fetch profile, most likely server error
			return self::$core->abort(503);

		# build passwordless account

		$uname = $profile['uname'];
		$uservice = sprintf('%s[%s]', $service_name, $service_type);
		$args['service'] = [
			'uname' => $uname,
			'uservice' => $uservice,
		];

		# safe to udata

		$retval = $this->self_add_user_passwordless($args);
		if ($retval[0] !== 0)
			# saving data fails, most likely server error
			return self::$core->abort(503);
		if (!isset($retval[1]) || !isset($retval[1]['token']))
			return self::$core->abort(503);

		# alway autologin on success

		$token = $retval[1]['token'];
		$this->set_user_token($token);
		setcookie(
			$this->get_token_name(), $token,
			time() + (3600 * 24 * 7), '/');

		# success, back home
		return self::$core->redirect('/');
	}
}

