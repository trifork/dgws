package com.trifork.dgws;

public interface WhitelistChecker {
	/**
	 * Checks whether a user is whitelisted. cpr may be null, indicating that no cpr number was provided in the certificate.
	 * In this case, the user should only be considered whitelisted if all users with the given cvr number is whitelisted.
	 */
	boolean isUserWhitelisted(String whitelist, String cvr, String cpr);
	/**
	 * Check whether a system is whitelisted. 
	 */
	boolean isSystemWhitelisted(String whitelist, String cvr);
}
