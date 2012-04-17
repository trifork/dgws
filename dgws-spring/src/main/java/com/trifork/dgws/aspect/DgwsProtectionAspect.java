package com.trifork.dgws.aspect;

import com.trifork.dgws.annotations.Protected;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import java.security.AccessControlException;

@Aspect
public class DgwsProtectionAspect implements ApplicationContextAware {

    private ApplicationContext applicationContext;

    @Before("@annotation(protectedAnnotation)")
    public void doAccessCheck(Protected protectedAnnotation) throws Throwable {
        System.out.println("\n########\n# HIT! #\n########\n");
        if (!protectedAnnotation.whitelist().equals("TEST")) {
            throw new AccessControlException("You are not whitelisted");
        }
        System.out.println("You are all clear");
    }

    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }
}
