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

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {DgwsProtectionAspectTest.TestContext.class})
public class DgwsProtectionAspectTest {
    @Autowired
    ProtectedTarget target;

    ProtectedTarget targetMock;

    @Autowired
    DgwsProtectionAspect aspect;

    @ImportResource("classpath:dk/trifork/dgws/dgws-protection.xml")
    public static class TestContext {
        @Bean()
        public ProtectedTarget protectedTarget() {
            ProtectedTarget targetMock = mock(ProtectedTarget.class);
            return new ProtectedTargetProxy(targetMock);
        }
    }

    @Test
    public void springWorks() throws Exception {
        assertNotNull(target);
        assertNotNull(aspect);
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
}
