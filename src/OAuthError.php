<?php


namespace BFITech\ZapOAuth;


/**
 * Error class.
 */
class OAuthError extends \Exception {

	/** Missing input data. */
	const INCOMPLETE_DATA = 0x0100;

	/** Attempt to connect to unregistered service. */
	const SERVICE_UNKNOWN = 0x0101;

	/** Provider doesn't return HTTP 200. */
	const SERVICE_ERROR = 0x0102;

	/** Access URL not obtained, OAuth1.0. */
	const ACCESS_URL_MISSING =  0x0103;

	/** Token missing from parsed URL. */
	const TOKEN_MISSING = 0x0104;
}
