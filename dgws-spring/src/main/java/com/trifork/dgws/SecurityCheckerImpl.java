package com.trifork.dgws;


import org.apache.log4j.Logger;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.Security;
import org.springframework.beans.factory.annotation.Autowired;

public class SecurityCheckerImpl implements SecurityChecker {
    private static Logger logger = Logger.getLogger(SecurityCheckerImpl.class);

    @Autowired(required = false)
    WhitelistChecker whitelistChecker;

    @Autowired 
    DgwsRequestContext dgwsRequestContext;

    public void validateHeader(String whitelist, int minAuthLevel, Security securityHeader) {
        if (whitelist != null && whitelist.trim().length() > 0) {
        	IdCardData idCardData = dgwsRequestContext.getIdCardData();
        	IdCardSystemLog systemLog = dgwsRequestContext.getIdCardSystemLog();
        	if(systemLog.getCareProviderIdType() != CareProviderIdType.CVR_NUMBER) {
        		throw new IllegalAccessError("Whitelist check failed: Care provider ID was not a CVR number but a " + systemLog.getCareProviderIdType());
        	}
            final String cvrNumber = systemLog.getCareProviderId();
            logger.debug("Extracted CVR=" + cvrNumber + " from saml:assertion");
            if(idCardData.getIdCardType() == IdCardType.SYSTEM) {
                if (!(whitelistChecker.isSystemWhitelisted(whitelist, cvrNumber))) {
                    logger.warn("whitelist check failed. System with cvrNumber=" + cvrNumber + " was not found in whitelist=" + whitelist);
                    throw new IllegalAccessError("cvrNumber=" + cvrNumber + " was not found in system whitelist=" + whitelist);
                }            
            }
            else if (idCardData.getIdCardType() == IdCardType.USER) {
            	IdCardUserLog userLog = dgwsRequestContext.getIdCardUserLog();
                if (!(whitelistChecker.isUserWhitelisted(whitelist, cvrNumber, userLog.cpr))) {
                    logger.warn("whitelist check failed. User with cvrNumber=" + cvrNumber + " and cpr number " + userLog.cpr + " was not found in whitelist=" + whitelist);
                    throw new IllegalAccessError("cvrNumber=" + cvrNumber + " and cpr number " + userLog.cpr +" was not found in user whitelist=" + whitelist);
                }            

            }
            else {
            	throw new IllegalAccessError("Whitelisting was required, but id card was not of type user or system");
            }
        }
        else {
            logger.debug("No whitelist checking");
        }
        final int authLevel = dgwsRequestContext.getIdCardData().getAuthenticationLevel();       
        if(authLevel < minAuthLevel){
        	logger.warn("Minimum auth level failed. Required " + minAuthLevel + " found " + authLevel);
        	throw new IllegalAccessError("Minimum auth level failed. Required " + minAuthLevel + " found " + authLevel);
        } else {
        	logger.debug("Auth when ok");
        }

        
    }
}