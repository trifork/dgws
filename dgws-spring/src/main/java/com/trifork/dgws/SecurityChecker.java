package com.trifork.dgws;

import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.Security;

public interface SecurityChecker {
    void validateHeader(Security securityHeader);
}
