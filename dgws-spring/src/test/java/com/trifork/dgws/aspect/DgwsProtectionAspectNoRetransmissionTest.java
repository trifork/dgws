package com.trifork.dgws.aspect;

import static java.util.Arrays.asList;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import javax.xml.transform.Source;

import oasis.names.tc.saml._2_0.assertion.AssertionType;
import oasis.names.tc.saml._2_0.assertion.Attribute;
import oasis.names.tc.saml._2_0.assertion.AttributeStatement;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.Security;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.oxm.Unmarshaller;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.ws.soap.SoapHeader;
import org.springframework.ws.soap.SoapHeaderElement;

import com.trifork.dgws.MedcomRetransmission;
import com.trifork.dgws.MedcomRetransmissionRegister;
import com.trifork.dgws.ProtectedTarget;
import com.trifork.dgws.ProtectedTargetProxy;
import com.trifork.dgws.SecurityChecker;

import dk.medcom.dgws._2006._04.dgws_1_0.Header;
import dk.medcom.dgws._2006._04.dgws_1_0.Linking;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {DgwsProtectionAspectNoRetransmissionTest.TestContext.class})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
public class DgwsProtectionAspectNoRetransmissionTest {
    @Autowired @Qualifier("protectedTargetProxy")
    ProtectedTargetProxy protectedTargetProxy;

    @Autowired @Qualifier("protectedTargetMock")
    ProtectedTarget protectedTargetMock;

    @Autowired
    DgwsProtectionAspect aspect;

    @Autowired
    Unmarshaller unmarshaller;

    @SuppressWarnings("SpringJavaAutowiringInspection Supplied by user")
    @Autowired
    SecurityChecker securityChecker;

    private final SoapHeader soapHeader = mock(SoapHeader.class);

    @EnableAspectJAutoProxy(proxyTargetClass = true)
    public static class TestContext {
        @Bean
        public DgwsProtectionAspect dgwsProtectionAspect() {
            return new DgwsProtectionAspect();
        }

        @Bean
        public ProtectedTargetProxy protectedTargetProxy(ProtectedTarget protectedTargetMock) {
            return new ProtectedTargetProxy(protectedTargetMock);
        }

        @Bean
        public ProtectedTarget protectedTargetMock() {
            return mock(ProtectedTarget.class);
        }

        @Bean
        public Unmarshaller unmarshaller() {
            return mock(Unmarshaller.class);
        }

        @Bean
        public SecurityChecker securityChecker() {
            return mock(SecurityChecker.class);
        }

    }
    
    @Test
    public void willWorkWithoutRetransmission() throws Exception{
    	SoapHeaderElement soapHeaderElementHeader = mock(SoapHeaderElement.class);
        SoapHeaderElement soapHeaderElementSecurity = mock(SoapHeaderElement.class);
        Source sourceHeader = mock(Source.class);
        Source sourceSecurity = mock(Source.class);
        Header medcomHeader = createMedcomHeader("TEST");
        Security security = new Security();
        
        when(soapHeader.examineAllHeaderElements()).thenReturn(asList(soapHeaderElementHeader, soapHeaderElementSecurity).iterator());
        when(soapHeaderElementHeader.getSource()).thenReturn(sourceHeader);
        when(soapHeaderElementSecurity.getSource()).thenReturn(sourceSecurity);
        
        when(unmarshaller.unmarshal(sourceHeader)).thenReturn(medcomHeader);
        when(unmarshaller.unmarshal(sourceSecurity)).thenReturn(security);

        when(protectedTargetMock.publicHitMe(soapHeader)).thenReturn("HIT");
        
        assertEquals("HIT", protectedTargetProxy.publicHitMe(soapHeader));
        
        verify(protectedTargetMock).publicHitMe(soapHeader);
    }
    
    
    private Header createMedcomHeader(String messageID) {
        Header medcomHeader = new Header();
        Linking linking = new Linking();
        linking.setMessageID(messageID);
        medcomHeader.setLinking(linking);
        return medcomHeader;
    }
}
