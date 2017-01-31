<?php


namespace BFITech\ZapOAuth;


class OAuthRouteDefault extends OAuthRoute {

	private $oauth_service_configs = [];

	public function __construct(
		$home=null, $host=null,
		$dbargs=[], $expiration=null, $create_table=false,
		$token_name=null, $route_prefix=null
	) {
		parent::__construct($home, $host,
			$dbargs, $expiration, $create_table,
			$token_name, $route_prefix);
	}

	/**
	 * Wrap self::$core->route().
	 */
	public function route($path, $callback, $method='GET') {
		self::$core->route($path, function($args) use($callback){
			$token_name = $this->get_token_name();
			if (isset($args['cookie'][$token_name])) {
				# cookie
				$this->set_user_token(
					$args['cookie'][$token_name]);
			} elseif (isset($args['header']['authorization'])) {
				# custom header
				$auth = explode(' ', $args['header']['authorization']);
				if ($auth[0] == $token_name) {
					$this->set_user_token($auth[1]);
				}
			}
			$callback($args);
		}, $method);
	}

	public function route_status($args) {
		return $this->pj($this->get_safe_user_data());
	}

	public function route_logout($args) {
		$retval = $this->logout($args);
		if ($retval[0] === 0)
			setcookie(
				$this->get_token_name(), '',
				time() - (3600 * 48), '/');
		return $this->pj($retval);
	}

	public function route_byway_auth($args) {
		return $this->pj($this->oauth_get_auth_url($args));
	}

	public function route_byway_callback($args) {
		$this->oauth_callback_url($args);
	}

}

