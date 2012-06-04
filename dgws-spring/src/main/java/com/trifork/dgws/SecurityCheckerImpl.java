package com.trifork.dgws;

import oasis.names.tc.saml._2_0.assertion.Attribute;
import oasis.names.tc.saml._2_0.assertion.AttributeStatement;
import org.apache.commons.collections15.CollectionUtils;
import org.apache.commons.collections15.Predicate;
import org.apache.log4j.Logger;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.Security;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.Assert;

import static org.apache.commons.lang.StringUtils.isNotEmpty;

public class SecurityCheckerImpl implements SecurityChecker {
    private static Logger logger = Logger.getLogger(SecurityCheckerImpl.class);

    @Autowired(required = false)
    WhitelistChecker whitelistChecker;


    public void validateHeader(String whitelist, int minAuthLevel, Security securityHeader) {
        if (isNotEmpty(whitelist)) {
            final String cvrNumber = findCvrNumber(securityHeader);
            logger.debug("Extracted CVR=" + cvrNumber + " from saml:assertion");
            if (!(whitelistChecker.getLegalCvrNumbers(whitelist).contains(cvrNumber))) {
                logger.warn("whitelist check failed. cvrNumber=" + cvrNumber + " was not found in whitelist=" + whitelist);
                throw new IllegalAccessError("cvrNumber=" + cvrNumber + " was not found in whitelist=" + whitelist);
            }            
        }
        else {
            logger.debug("No whitelist checking");
        }
        final int authLevel = findAuthLevel(securityHeader);            
        if(authLevel < minAuthLevel){
        	logger.warn("Minimum auth level failed. Required " + minAuthLevel + " found " + authLevel);
        	throw new IllegalAccessError("Minimum auth level failed. Required " + minAuthLevel + " found " + authLevel);
        } else {
        	logger.debug("Auth when ok");
        }

        
    }

    private String findCvrNumber(Security securityHeader) {
        final AttributeStatement systemLog = CollectionUtils.find(securityHeader.getAssertion().getAttributeStatement(), new Predicate<AttributeStatement>() {
            public boolean evaluate(AttributeStatement attributeStatement) {
                return attributeStatement.getId().equals("SystemLog");
            }
        });
        Assert.notNull(systemLog, "No SystemLog AttributeStatement was found in saml:assertion");
        final Attribute careProviderId = CollectionUtils.find(systemLog.getAttribute(), new Predicate<Attribute>() {
            public boolean evaluate(Attribute attribute) {
                return attribute.getName().equals("medcom:CareProviderID");
            }
        });
        Assert.notNull(careProviderId, "No CareProviderID Attribute was found in SystemLog");
        return careProviderId.getAttributeValue();
    }
    
    private int findAuthLevel(Security securityHeader){
    	 final AttributeStatement idCardData = CollectionUtils.find(securityHeader.getAssertion().getAttributeStatement(), new Predicate<AttributeStatement>() {
             public boolean evaluate(AttributeStatement attributeStatement) {
                  return attributeStatement.getId().equals("IDCardData");
             }
         });
    	 
    	 Assert.notNull(idCardData, "No IdCardData AttributeStatement was found in saml:assertion");
         final Attribute authLevel = CollectionUtils.find(idCardData.getAttribute(), new Predicate<Attribute>() {
             public boolean evaluate(Attribute attribute) {
                 return attribute.getName().equals("sosi:AuthenticationLevel");
             }
         });
         Assert.notNull(authLevel, "No AuthenticationLevel Attribute was found in IdCardData");
    	return new Integer(authLevel.getAttributeValue());
    }
}