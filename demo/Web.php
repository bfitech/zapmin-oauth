<?php


namespace Demo;


use BFITech\ZapCore\Logger;
use BFITech\ZapCore\Router;
use BFITech\ZapStore\SQLite3;
use BFITech\ZapAdmin\Admin;
use BFITech\ZapAdmin\AuthCtrl;


/**
 * Run the routes.
 */
class Web {

	private $zcore;

	public function __construct() {
		$this->init_zcore();
		$this->run();
	}

	private function init_zcore() {
		$datadir = __DIR__ . '/data';
		if (!is_dir($datadir))
			mkdir($ddatadir, 0755);

		$logger = new Logger(
			Logger::DEBUG, $datadir . '/zapmin-oauth.log');
		$core = (new Router)->config('logger', $logger);
		$store = new SQLite3(
			['dbname' => $datadir . '/zapmin-oauth.sq3'], $logger);

		$admin = new Admin($store, $logger);
		$admin
			->config('expire', 3600)
			->config('token_name', 'testing')
			->config('check_tables', true);
		$ctrl = new AuthCtrl($admin, $logger);
		$manage = new OAuthManage($admin, $logger);

		# config
		$cnfile = $datadir . '/config.json';
		if (!is_file($cnfile))
			copy(__DIR__ . '/config.json-sample', $cnfile);
		$config = json_decode(file_get_contents($cnfile));

		# add service
		# Make sure callback URLs in the configuration and on remote
		# server match.
		foreach ($config as $cfg)
			call_user_func_array([$manage, 'add_service'], $cfg);

		$this->zcore = new OAuthRoute($core, $ctrl, $manage);
	}

	private function make_routes() {
		return [
			['/',
				'route_home'],
			['/status',
				'route_status'],
			['/refresh',
				'route_refresh', 'POST'],
			['/logout',
				'route_logout', ['GET', 'POST']],
			['/byway/oauth/<service_type>/<service_name>/auth',
				'route_byway_auth', 'POST'],
			['/byway/oauth/<service_type>/<service_name>/callback',
				'route_byway_callback'],
			['/static/{path}',
				'route_static']
		];
	}

	private function run() {
		$zcore = $this->zcore;
		foreach ($this->make_routes() as $route) {
			$route[1] = [$zcore, $route[1]];
			if (count($route) < 3)
				$route[] = 'GET';
			if (count($route) < 4)
				$route[] = false;
			call_user_func_array([$zcore, 'route'], $route);
		}
	}

}
