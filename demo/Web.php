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
use BFITech\ZapAdminDev\OAuthRouteDev;


/**
 * Run the routes.
 */
class Web {

	private $zcore_real;
	private $zcore_fake;

	public function __construct() {
		$this->init();
		$this->run();
	}

	private function init() {
		$datadir = __DIR__ . '/data';
		if (!is_dir($datadir) && false === @mkdir($datadir, 0755))
			die(sprintf(
				"User '%s' cannot create directory '%s'.</pre>",
				Common::exec('whoami')[0], $datadir));

		$log = new Logger(
			Logger::DEBUG, $datadir . '/demo.log');
		$core = (new Router)
			->config('logger', $log);
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

		# real
		$this->zcore_real = new OAuthRoute($core, $ctrl, $manage);
		$this->zcore_real->srvfile = $srvfile;
		# fake
		define('ZAPMIN_OAUTH_DEV', 1);
		$this->zcore_fake = new OAuthRouteDev($core, $ctrl, $manage);
	}

	private function run() {
		$real = $this->zcore_real;
		$fake = $this->zcore_fake;

		foreach ([
			[$real, '/',
				'route_home'],
			[$real, '/status',
				'route_status'],
			[$real, '/refresh',
				'route_refresh', 'POST'],
			[$real, '/logout',
				'route_logout', ['GET', 'POST']],
			[$real, '/byway/oauth/<service_type>/<service_name>/auth',
				'route_byway_auth', 'POST'],
			[$real,
				'/byway/oauth/<service_type>/<service_name>/callback',
				'route_byway_callback'],
			[$real, '/static/{path}',
				'route_static'],
			[$real, '/services',
				'route_services'],
			[$fake, '/fake_login/<service_type>/<service_name>',
				'route_fake_login'],
		] as $rti) {
			if (count($rti) < 4)
				$rti[] = ['GET'];
			if (count($rti) < 5)
				$rti[] = false;
			list($zcore, $path, $cbname, $methods, $is_raw) = $rti;
			$zcore->route($path, [$zcore, $cbname], $methods, $is_raw);
		}
	}

}
