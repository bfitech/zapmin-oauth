<?php


use BFITech\ZapCoreDev\RoutingDev;


/**
 * Minor patch to RoutingDev so we can chain from the return of
 * RoutingDev::request. See RoutingDevPatched of zapmin test.
 */
class RoutingDevPatched extends RoutingDev {

	public static $zcore;

	public function request(
         string $request_uri=null, string $request_method='GET',
         array $args=null, array $cookie=[]
	) {
		parent::request($request_uri, $request_method, $args, $cookie);
		return self::$zcore;
	}
}
