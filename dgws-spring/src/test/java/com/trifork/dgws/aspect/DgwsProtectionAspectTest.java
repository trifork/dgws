package com.trifork.dgws.aspect;

import com.trifork.dgws.ProtectedTarget;
import com.trifork.dgws.ProtectedTargetProxy;
import dk.medcom.dgws._2006._04.dgws_1_0.Header;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ImportResource;
import org.springframework.oxm.Unmarshaller;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.ws.soap.SoapHeader;
import org.springframework.ws.soap.SoapHeaderElement;

import javax.xml.transform.Source;

import static java.util.Arrays.asList;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {DgwsProtectionAspectTest.TestContext.class})
public class DgwsProtectionAspectTest {
    @Autowired
    ProtectedTarget target;

    static ProtectedTarget targetMock;

    @Autowired
    DgwsProtectionAspect aspect;

    @Autowired
    Unmarshaller unmarshaller;

    private final SoapHeader soapHeader = mock(SoapHeader.class);

    @ImportResource("classpath:dk/trifork/dgws/dgws-protection.xml")
    public static class TestContext {
        @Bean
        public ProtectedTarget protectedTarget() {
            targetMock = mock(ProtectedTarget.class);
            return new ProtectedTargetProxy(targetMock);
        }

        @Bean
        public Unmarshaller unmarshaller() {
            return mock(Unmarshaller.class);
        }
    }

    @Test
    public void springWorks() throws Exception {
        assertNotNull(target);
        assertNotNull(aspect);
        assertNotNull(soapHeader);
    }

    @Test
    public void willThrowOnMissingSoapHeader() throws Exception {
        try {
            target.hitMe();
        } catch (IllegalArgumentException e) {
            assertEquals("Endpoint method does not contain a SoapHeader argument", e.getMessage());
            return;
        }
        fail("method did not throw IllegalArgumentException");
    }

    @Test
    public void willForwardCallToTarget() throws Exception {
        target.hitMe(soapHeader);

        verify(targetMock).hitMe(soapHeader);
    }

    @Test
    public void willNotAllowNullSoapHeader() throws Exception {

        target.hitMe(null);
    }

    @Test
    public void willNotForwardCallOnReplay() throws Exception {
        SoapHeaderElement soapHeaderElement = mock(SoapHeaderElement.class);
        Source source = mock(Source.class);
        Header medcomHeader = new Header();

        when(soapHeader.examineAllHeaderElements()).thenReturn(asList(soapHeaderElement).iterator());
        when(soapHeaderElement.getSource()).thenReturn(source);
        when(unmarshaller.unmarshal(source)).thenReturn(medcomHeader);

        target.hitMe(soapHeader);

        verify(soapHeader).examineAllHeaderElements();
        verify(soapHeaderElement).getSource();
        verify(unmarshaller).unmarshal(source);

    }
}
