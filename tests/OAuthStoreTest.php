<?php


require_once(__DIR__ . '/OAuthFixture.php');


use PHPUnit\Framework\TestCase;
use BFITech\ZapCore\Logger;
use BFITech\ZapStore\SQLite3;
use BFITech\ZapAdmin\AdminStore;
use BFITech\ZapAdmin\OAuthStore;


class OAuthStoreConst extends OAuthStore {}

class AdminStoreTabConst extends AdminStore {}

class OAuthTest extends TestCase {

	protected static $sql;
	protected static $adm;
	protected static $logger;

	protected static $pwdless_uid;

	public static function setUpBeforeClass() {
		self::$logger = new Logger(Logger::ERROR, '/dev/null');
	}

	public function test_constructor() {
		$store = new SQLite3(
			['dbname' => ':memory:'], self::$logger);

		new AdminStoreTabConst($store);

		# new table including AdminStore table
		$adm = new OAuthStoreConst($store, false, self::$logger);
		$rv = $store->query(
			"SELECT uname FROM udata ORDER BY uid DESC LIMIT 1"
		)['uname'];
		$this->assertEquals($rv, 'root');

		/* @todo Not much to do. Delete this? */
	}

}

