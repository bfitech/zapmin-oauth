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

if (!is_file('config.json'))
	die("Config not found.");
$config = json_decode(file_get_contens('config.json'));

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
	$t10[0], $t10[1], $t10[2], $t10[3], $t10[4],
	$t10[5], $t10[6], $t10[7], $t10[8], $t10[9]
);

$oauth::$core->route('/', function($args) use($oauth) {
	require('home.php');
	die();
});

$oauth->process_routes();

