<?php


require(__DIR__ . '/../../vendor/autoload.php');

use BFITech\ZapOAuth as zo;


$oauth = new zo\ZapOAuth(null, null, [
	'dbtype'=>'sqlite3',
	'dbname' => '/mnt/ramdisk/zo.sq3',
], 3600);

function some_func($access_token, $access_token_secret,
	$conf, $oauth) {
	# dummy profile retriever
	return ['uname' => 'tester'];
}

# Make sure server config exists. Use sample to for a
# quick start.

$confl = __DIR__ . '/config.json';
if (!is_file($confl))
	die("Config not found.");
$config = json_decode(file_get_contents($confl));

# NOTE: Make sure callback URLs in the configuration and on
# remote server match.

# OAuth1.0, e.g. Twitter
$s10 = $config[0];
$oauth->oauth_add_service(
	$s10[0], $s10[1], $s10[2], $s10[3], $s10[4],
	$s10[5], $s10[6], $s10[7], $s10[8], $s10[9]
);

# OAuth2.0, e.g. Google
$s20 = $config[1];
$oauth->oauth_add_service(
	$s20[0], $s20[1], $s20[2], $s20[3], $s20[4],
	$s20[5], $s20[6], $s20[7], $s20[8], $s20[9]
);

$oauth::$core->route('/', function($args) use($oauth) {
	require('home.php');
	die();
});

$oauth->process_routes();

