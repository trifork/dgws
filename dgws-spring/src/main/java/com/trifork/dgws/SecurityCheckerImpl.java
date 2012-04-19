package com.trifork.dgws;

import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.Security;
import org.springframework.beans.factory.annotation.Autowired;

public class SecurityCheckerImpl implements SecurityChecker {
    @SuppressWarnings("SpringJavaAutowiringInspection should be wired by user")
    @Autowired
    WhitelistChecker whitelistChecker;


    public void validateHeader(Security securityHeader) {

    }
}
