package com.trifork.dgws;

import static org.junit.Assert.assertEquals;

import javax.xml.transform.stream.StreamSource;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.Security;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import org.w3._2000._09.xmldsig.Signature;

public class DgwsRequestContextDefaultTest {
	DgwsRequestContextDefault dgwsRequestContext = new DgwsRequestContextDefault();

    Jaxb2Marshaller marshaller = new Jaxb2Marshaller();

    @Before
    public void setupMarshaller() throws Exception {
        marshaller.setClassesToBeBound(
                Security.class,
                Signature.class
        );
        marshaller.afterPropertiesSet();
    }
    
    void setupSecurityHeader(String headerCanonicalPath) {
        StreamSource source = new StreamSource(getClass().getResourceAsStream(headerCanonicalPath));
        final Security securityHeader = (Security) marshaller.unmarshal(source);
        dgwsRequestContext.setSecurityThreadLocal(securityHeader);
    }
    
    @Test
    public void canParseIdCardData() {
    	setupSecurityHeader("/SecurityHeader1.xml");
    	IdCardData idCardData = dgwsRequestContext.getIdCardData();
    	assertEquals(IdCardType.USER, idCardData.getIdCardType());
    	assertEquals(4, idCardData.getAuthenticationLevel());
    }
    
    @Test
    public void canParseSystemLog() {
    	setupSecurityHeader("/SecurityHeader1.xml");
    	IdCardSystemLog systemLog = dgwsRequestContext.getIdCardSystemLog();
    	assertEquals("SOSITEST", systemLog.getItSystemName());
    	assertEquals("25520041", systemLog.getCareProviderId());
    	assertEquals(CareProviderIdType.CVR_NUMBER, systemLog.getCareProviderIdType());
    	assertEquals("TRIFORK SERVICES A/S // CVR:25520041", systemLog.getCareProviderName());
    }
    
    @Test
    public void canParseUserLog() {
    	setupSecurityHeader("/SecurityHeader1.xml");
    	IdCardUserLog userLog = dgwsRequestContext.getIdCardUserLog();
    	assertEquals("1111111118", userLog.cpr);
    	assertEquals("Lisbeth", userLog.givenName);
    	assertEquals("Schjerling", userLog.surname);
    	assertEquals("Doctor", userLog.role);
    }
    
    @After
    public void tearDown() {
    	dgwsRequestContext.securityThreadLocal.remove();
    }
}
