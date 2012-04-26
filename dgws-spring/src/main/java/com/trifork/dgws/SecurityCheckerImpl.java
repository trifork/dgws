package com.trifork.dgws;

import oasis.names.tc.saml._2_0.assertion.Attribute;
import oasis.names.tc.saml._2_0.assertion.AttributeStatement;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.Predicate;
import org.apache.log4j.Logger;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.Security;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.Assert;

public class SecurityCheckerImpl implements SecurityChecker {
    private static Logger logger = Logger.getLogger(SecurityCheckerImpl.class);
    @SuppressWarnings("SpringJavaAutowiringInspection should be wired by user")
    @Autowired
    WhitelistChecker whitelistChecker;


    public void validateHeader(String whitelist, Security securityHeader) {
        //TODO: validering af signature
        Assert.hasText(whitelist);

        final String cvrNumber = findCvrNumber(securityHeader);
        logger.debug("Extracted CVR=" + cvrNumber + " from saml:assertion");
        if (!(whitelistChecker.getLegalCvrNumbers(whitelist).contains(cvrNumber))) {
            throw new IllegalAccessError("cvrNumber=" + cvrNumber + " was not found in whitelist=" + whitelist);
        }
    }

    private String findCvrNumber(Security securityHeader) {
        final AttributeStatement systemLog = (AttributeStatement) CollectionUtils.find(securityHeader.getAssertion().getAttributeStatement(), new Predicate() {
            public boolean evaluate(Object object) {
                return ((AttributeStatement) object).getId().equals("SystemLog");
            }
        });
        Assert.notNull(systemLog, "No SystemLog AttributeStatement was found in saml:assertion");
        final Attribute careProviderId = (Attribute) CollectionUtils.find(systemLog.getAttribute(), new Predicate() {
            public boolean evaluate(Object object) {
                return ((Attribute) object).getName().equals("medcom:CareProviderID");
            }
        });
        Assert.notNull(careProviderId, "No CareProviderID Attribute was found in SystemLog");
        return careProviderId.getAttributeValue();
    }
}
