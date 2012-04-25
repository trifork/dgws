package com.trifork.dgws;

import org.apache.log4j.Logger;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.Security;
import org.springframework.beans.factory.annotation.Autowired;
import com.trifork.dgws.util.*;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class SecurityCheckerImpl implements SecurityChecker {
    private static Logger logger = Logger.getLogger(SecurityCheckerImpl.class);
    @SuppressWarnings("SpringJavaAutowiringInspection should be wired by user")
    @Autowired
    WhitelistChecker whitelistChecker;


    public void validateHeader(String whitelist, Security securityHeader) {
        //TODO: validering af signature

        final String cvrNumber = findCvrNumber(securityHeader);
        if (!(whitelistChecker.getLegalCvrNumbers(whitelist).contains(cvrNumber))) {
            throw new IllegalAccessError("cvrNumber=" + cvrNumber + " was not found in whitelist=" + whitelist);
        }
    }

    private String findCvrNumber(Security securityHeader) {
        try {
            final byte[] certificateBytes = securityHeader.getAssertion().getSignature().getKeyInfo().getX509Data().getX509Certificate();
            final ByteArrayInputStream certificateInputStream = new ByteArrayInputStream(certificateBytes);
            final X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(certificateInputStream);
            final CertificateSubject certificateSubject = new CertificateSubject(certificate.getSubjectDN().toString());
            return certificateSubject.getCvrNumberString();
        } catch (CertificateException e) {
            throw new RuntimeException("Could not parse certificate from Security header", e);
        }
    }
}
