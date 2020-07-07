<?php


namespace Demo;


use BFITech\ZapCore\Common;
use BFITech\ZapCore\Config;
use BFITech\ZapCore\ConfigError;
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
		if (!is_dir($datadir) && false === @mkdir($datadir, 0755))
			die(sprintf(
				"User '%s' cannot create directory '%s'.</pre>",
				Common::exec('whoami')[0], $datadir));

		$log = new Logger(
			Logger::DEBUG, $datadir . '/demo.log');
		$core = (new Router)->config('logger', $log);
		$sql = new SQLite3(
			['dbname' => $datadir . '/demo.sq3'], $log);

		# config file
		$cnfile = $datadir . '/config.json';
		if (!file_exists($cnfile))
			file_put_contents($cnfile, '[]');

		# check table status from config; this is shared between
		# Admin and OAuthManage
		$cnf = new Config($datadir . '/config.json');
		$check_table = true;
		try {
			$check_table = (bool)$cnf->get('check_table');
		} catch(ConfigError $err) {
			$cnf->add('check_table', true); 
		}

		# admin
		$admin = new Admin($sql, $log);
		$admin
			->config('expire', 3600)
			->config('token_name', 'testing')
			->config('check_tables', $check_table);

		# control
		$ctrl = new AuthCtrl($admin, $log);

		# manage
		$manage = (new OAuthManage($admin, $log))
			->config('check_table', $check_table);

		if ($check_table)
			# stop table checks
			$cnf->set('check_table', false);

		# read service file or copy from sample
		$srvfile = $datadir . '/services.json';
		if (!is_file($srvfile))
			copy(__DIR__ . '/services.json-sample', $srvfile);
		$services = Config::djson(file_get_contents($srvfile, true));

		# add services
		# Make sure callback URLs in the configuration and on remote
		# server match.
		foreach ($services as $service)
			call_user_func_array([$manage, 'add_service'], $service);

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
