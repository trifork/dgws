package com.trifork.dgws.aspect;

import com.trifork.dgws.MedcomReplay;
import com.trifork.dgws.MedcomReplayRegister;
import com.trifork.dgws.ProtectedTarget;
import com.trifork.dgws.ProtectedTargetProxy;
import dk.medcom.dgws._2006._04.dgws_1_0.Header;
import dk.medcom.dgws._2006._04.dgws_1_0.Linking;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ImportResource;
import org.springframework.oxm.Unmarshaller;
import org.springframework.test.annotation.DirtiesContext;
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
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
public class DgwsProtectionAspectTest {
    @Autowired @Qualifier("protectedTargetProxy")
    ProtectedTargetProxy protectedTargetProxy;

    @Autowired @Qualifier("protectedTargetMock")
    ProtectedTarget protectedTargetMock;

    @Autowired
    DgwsProtectionAspect aspect;

    @Autowired
    Unmarshaller unmarshaller;

    @Autowired
    MedcomReplayRegister medcomReplayRegister;

    private final SoapHeader soapHeader = mock(SoapHeader.class);

    @ImportResource("classpath:dk/trifork/dgws/dgws-protection.xml")
    public static class TestContext {
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
        public MedcomReplayRegister medcomReplayRegister() {
            return mock(MedcomReplayRegister.class);
        }
    }

    @Test
    public void springWorks() throws Exception {
        assertNotNull(protectedTargetProxy);
        assertTrue(protectedTargetProxy instanceof ProtectedTargetProxy);
        assertNotNull(aspect);
        assertNotNull(soapHeader);
    }

    @Test
    public void willThrowOnMissingSoapHeader() throws Exception {
        try {
            protectedTargetProxy.hitMe();
        } catch (IllegalArgumentException e) {
            assertEquals("Endpoint method does not contain a SoapHeader argument or it is null", e.getMessage());
            return;
        }
        fail("method did not throw IllegalArgumentException");
    }

    @Test
    public void willForwardCallToTargetAndStoreReplay() throws Exception {
        SoapHeaderElement soapHeaderElement = mock(SoapHeaderElement.class);
        Source source = mock(Source.class);
        Header medcomHeader = createMedcomHeader("TEST");

        when(soapHeader.examineAllHeaderElements()).thenReturn(asList(soapHeaderElement).iterator());
        when(soapHeaderElement.getSource()).thenReturn(source);
        when(unmarshaller.unmarshal(source)).thenReturn(medcomHeader);
        when(protectedTargetMock.hitMe(soapHeader)).thenReturn("HIT");

        assertEquals("HIT", protectedTargetProxy.hitMe(soapHeader));

        verify(soapHeader).examineAllHeaderElements();
        verify(soapHeaderElement).getSource();
        verify(unmarshaller).unmarshal(source);
        verify(protectedTargetMock).hitMe(soapHeader);
        verify(medcomReplayRegister).createReplay("TEST", "HIT");
    }

    @Test
    public void willNotAllowNullSoapHeader() throws Exception {
        try {
            protectedTargetProxy.hitMe(null);
        } catch (IllegalArgumentException e) {
            assertEquals("Endpoint method does not contain a SoapHeader argument or it is null", e.getMessage());
            return;
        }
        fail("Method did not throw IllegalArgumentException");
    }

    @Test
    public void willNotForwardCallOnReplay() throws Exception {
        SoapHeaderElement soapHeaderElement = mock(SoapHeaderElement.class);
        Source source = mock(Source.class);
        Header medcomHeader = createMedcomHeader("TEST");
        String expectedResponse = "Some replayable response";

        when(soapHeader.examineAllHeaderElements()).thenReturn(asList(soapHeaderElement).iterator());
        when(soapHeaderElement.getSource()).thenReturn(source);
        when(unmarshaller.unmarshal(source)).thenReturn(medcomHeader);
        when(medcomReplayRegister.getReplay("TEST")).thenReturn(new MedcomReplay("TEST", expectedResponse));

        assertEquals(expectedResponse, protectedTargetProxy.hitMe(soapHeader));

        verify(soapHeader).examineAllHeaderElements();
        verify(soapHeaderElement).getSource();
        verify(unmarshaller).unmarshal(source);
        verify(protectedTargetMock, never()).hitMe(soapHeader);
        verify(medcomReplayRegister, never()).createReplay("TEST", expectedResponse);
    }

    private Header createMedcomHeader(String messageID) {
        Header medcomHeader = new Header();
        Linking linking = new Linking();
        linking.setMessageID(messageID);
        medcomHeader.setLinking(linking);
        return medcomHeader;
    }
}
