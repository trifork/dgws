package com.trifork.dgws.aspect;

import com.trifork.dgws.ProtectedTarget;
import com.trifork.dgws.ProtectedTargetProxy;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ImportResource;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.ws.soap.SoapHeader;

import static org.junit.Assert.*;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {DgwsProtectionAspectTest.TestContext.class})
public class DgwsProtectionAspectTest {
    @Autowired
    ProtectedTarget target;

    static ProtectedTarget targetMock;

    @Autowired
    DgwsProtectionAspect aspect;

    private final SoapHeader soapHeader = mock(SoapHeader.class);

    @ImportResource("classpath:dk/trifork/dgws/dgws-protection.xml")
    public static class TestContext {
        @Bean
        public ProtectedTarget protectedTarget() {
            targetMock = mock(ProtectedTarget.class);
            return new ProtectedTargetProxy(targetMock);
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

        verify(targetMock, atLeastOnce()).hitMe(soapHeader);
    }
}
