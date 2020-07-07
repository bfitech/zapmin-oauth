<?php


namespace Demo;


/**
 * OAuthRoute default with homepage and several authentication
 * facilities such as signing in and out.
 */
class OAuthRoute extends \BFITech\ZapAdmin\OAuthRouteDefault {

	/**
	 * GET: /
	 */
	public function route_home($args=null) {
		$mithril = '//cdnjs.cloudflare.com/ajax/libs/mithril/' .
			'2.0.4/mithril.min.js';
		self::$core::start_header(200, 30);
		echo <<<EOD
<!doctype html>
<html>
<head>
	<title>Test OAuth Client</title>
	<link href=./static/style.css rel=stylesheet>
</head>
<body>
<div id=wrap>
	<div id=box></div>
</div>
<script src=${mithril}></script>
<script src=./static/script.js></script>
EOD;
	}

	/**
	 * GET: /status
	 */
	public function route_status($args) {
		return self::$core::pj(self::$ctrl->get_safe_user_data());
	}

	/**
	 * GET|POST: /logout
	 */
	public function route_logout($args=null) {
		$core = self::$core;
		$udata = self::$ctrl->get_user_data();
		if (!$udata)
			return $core::pj([1, []], 403);
		self::$ctrl->logout();
		return $core::pj([0, []]);
	}

	/**
	 * POST: /refresh
	 *
	 * FIXME: Untested.
	 */
	public function route_refresh($args=null) {
		$core = self::$core;
		$udata = self::$ctrl->get_user_data();
		if (!$udata)
			return $core::pj([1, []], 403);
		$token = $udata['token'];
		$act = $this->oauth_get_action_from_session($token);
		$refresh_token = $act->refresh();

		// @todo: after refresh token?

		if (!$refresh_token)
			return $core::pj([1, []], 403);
		return $core::pj([0, $refresh_token]);
	}

	/**
	 * GET: /static/{path}
	 */
	public function route_static($args) {
		return self::$core->static_file(
			__DIR__ . '/static/' . $args['params']['path']);
	}

}
