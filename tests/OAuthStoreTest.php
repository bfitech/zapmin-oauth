<?php


require_once(__DIR__ . '/OAuthFixture.php');


use PHPUnit\Framework\TestCase;
use BFITech\ZapCore\Logger;
use BFITech\ZapStore\SQLite3;
use BFITech\ZapAdmin\OAuthStore;


class OAuthStoreConst extends OAuthStore {}


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
		$test_sql = "SELECT uname FROM udata ORDER BY uid DESC LIMIT 1";

		# new table including AdminStore table
		$adm = new OAuthStoreConst($store, null, false, self::$logger);
		$rv = $store->query($test_sql)['uname'];
		$this->assertEquals($rv, 'root');

		# add new user
		$store->insert('udata', ['uname' => 'john']);
		$rv = $store->query($test_sql)['uname'];
		$this->assertEquals($rv, 'john');

		# table completely recreated
		$adm = new OAuthStoreConst($store, null, true, self::$logger);
		$rv = $store->query($test_sql)['uname'];
		$this->assertEquals($rv, 'root');
	}

}

