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
    
    @Mock 
    DgwsRequestContext dgwsRequestContext;

    Jaxb2Marshaller marshaller = new Jaxb2Marshaller();

    @Before
    public void setUp() throws Exception {
        marshaller.setClassesToBeBound(
                Security.class,
                Signature.class
        );
        marshaller.afterPropertiesSet();
    }

    @Test
    public void willNotWhitelistCheckIfCheckerIfProvided() throws Exception {
        StreamSource source = new StreamSource(getClass().getResourceAsStream("/SecurityHeader1.xml"));
        final Security securityHeader = (Security) marshaller.unmarshal(source);
        assertNotNull(securityHeader);

        when(dgwsRequestContext.getIdCardData()).thenReturn(new IdCardData(IdCardType.SYSTEM, 3));

        securityChecker.validateHeader("", 0, securityHeader);
        verify(whitelistChecker, never()).isSystemWhitelisted(any(String.class), any(String.class));
        verify(whitelistChecker, never()).isUserWhitelisted(any(String.class), any(String.class), any(String.class));
    }

    @Test
    public void canValidateCvrFromCarProviderID() throws Exception {
        StreamSource source = new StreamSource(getClass().getResourceAsStream("/SecurityHeader1.xml"));
        final Security securityHeader = (Security) marshaller.unmarshal(source);
        assertNotNull(securityHeader);

        when(dgwsRequestContext.getIdCardSystemLog()).thenReturn(new IdCardSystemLog("IT System", CareProviderIdType.CVR_NUMBER, "25520041", "Care provider name"));
        when(dgwsRequestContext.getIdCardData()).thenReturn(new IdCardData(IdCardType.SYSTEM, 3));
        when(whitelistChecker.isSystemWhitelisted("TestWhiteList", "25520041")).thenReturn(true);

        securityChecker.validateHeader("TestWhiteList", 0, securityHeader);
    }

    @Test(expected = IllegalAccessError.class)
    public void willThrowAccessViolationOnIllegalCvr() throws Exception {
        StreamSource source = new StreamSource(getClass().getResourceAsStream("/SecurityHeader1.xml"));
        final Security securityHeader = (Security) marshaller.unmarshal(source);
        assertNotNull(securityHeader);

        when(dgwsRequestContext.getIdCardData()).thenReturn(new IdCardData(IdCardType.SYSTEM, 3));
        when(dgwsRequestContext.getIdCardSystemLog()).thenReturn(new IdCardSystemLog("IT System", CareProviderIdType.CVR_NUMBER, "25520041", "Care provider name"));
        when(whitelistChecker.isSystemWhitelisted("TestWhiteList", "25520041")).thenReturn(false);

        securityChecker.validateHeader("TestWhiteList", 0, securityHeader);
    }
    
    @Test(expected = IllegalAccessError.class)
    public void willThrowAccessViolationOnWrongMinLevel() throws Exception {
        StreamSource source = new StreamSource(getClass().getResourceAsStream("/SecurityHeader2.xml"));
        when(dgwsRequestContext.getIdCardSystemLog()).thenReturn(new IdCardSystemLog("IT System", CareProviderIdType.CVR_NUMBER, "25520041", "Care provider name"));
        when(dgwsRequestContext.getIdCardData()).thenReturn(new IdCardData(IdCardType.SYSTEM, 2));
        final Security securityHeader = (Security) marshaller.unmarshal(source);
        assertNotNull(securityHeader);
 
        securityChecker.validateHeader("", 3, securityHeader);
    }
}