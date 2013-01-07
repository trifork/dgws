package com.trifork.dgws;

import static org.apache.commons.lang.StringUtils.isNotEmpty;

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
        if (isNotEmpty(whitelist)) {
        	IdCardSystemLog systemLog = dgwsRequestContext.getIdCardSystemLog();
        	if(systemLog.getCareProviderIdType() != CareProviderIdType.CVR_NUMBER) {
        		throw new IllegalAccessError("Whitelist check failed: Care provider ID was not a CVR number but a " + systemLog.getCareProviderIdType());
        	}
            final String cvrNumber = systemLog.getCareProviderId();
            logger.debug("Extracted CVR=" + cvrNumber + " from saml:assertion");
            if (!(whitelistChecker.getLegalCvrNumbers(whitelist).contains(cvrNumber))) {
                logger.warn("whitelist check failed. cvrNumber=" + cvrNumber + " was not found in whitelist=" + whitelist);
                throw new IllegalAccessError("cvrNumber=" + cvrNumber + " was not found in whitelist=" + whitelist);
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