package com.trifork.dgws;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.Security;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import org.w3._2000._09.xmldsig.Signature;

import javax.xml.transform.stream.StreamSource;

import static java.util.Collections.singleton;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class SecurityCheckerImplTest {
    @InjectMocks
    SecurityCheckerImpl securityChecker = new SecurityCheckerImpl();

    @Mock
    WhitelistChecker whitelistChecker;

    Jaxb2Marshaller marshaller = new Jaxb2Marshaller();

    @Before
    public void setUp() throws Exception {
        securityChecker.whitelistChecker = whitelistChecker;
        marshaller.setClassesToBeBound(
                Security.class,
                Signature.class
        );
        marshaller.afterPropertiesSet();
    }

    @Test
    public void canValidateCvrFromCarProviderID() throws Exception {
        StreamSource source = new StreamSource(getClass().getResourceAsStream("/SecurityHeader1.xml"));
        final Security securityHeader = (Security) marshaller.unmarshal(source);
        assertNotNull(securityHeader);

        when(whitelistChecker.getLegalCvrNumbers("TestWhiteList")).thenReturn(singleton("25520041"));

        securityChecker.validateHeader("TestWhiteList", securityHeader);
    }

    @Test(expected = IllegalAccessError.class)
    public void willThrowAccessViolationOnIllegalCvr() throws Exception {
        StreamSource source = new StreamSource(getClass().getResourceAsStream("/SecurityHeader1.xml"));
        final Security securityHeader = (Security) marshaller.unmarshal(source);
        assertNotNull(securityHeader);

        when(whitelistChecker.getLegalCvrNumbers("TestWhiteList")).thenReturn(singleton("0"));

        securityChecker.validateHeader("TestWhiteList", securityHeader);
    }
}
