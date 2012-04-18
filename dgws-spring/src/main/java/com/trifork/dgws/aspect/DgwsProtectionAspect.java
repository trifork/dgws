package com.trifork.dgws.aspect;

import com.trifork.dgws.annotations.Protected;
import dk.medcom.dgws._2006._04.dgws_1_0.Header;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.oxm.Unmarshaller;
import org.springframework.ws.soap.SoapHeader;
import org.springframework.ws.soap.SoapHeaderElement;

import java.util.Iterator;

@Aspect
public class DgwsProtectionAspect {
    @Autowired
    Unmarshaller unmarshaller;

    @Around("@annotation(protectedAnnotation)")
    public Object doAccessCheck(ProceedingJoinPoint pjp, Protected protectedAnnotation) throws Throwable {
        SoapHeader soapHeader = extractSoapHeader(pjp);

        final Header medcomHeader = unmarshalMedcomHeader(soapHeader);
        //TODO: medcom header replay
        System.out.println("medcomHeader = " + medcomHeader);

        return pjp.proceed(pjp.getArgs());
    }

    private Header unmarshalMedcomHeader(SoapHeader soapHeader) throws Exception {
        Iterator<SoapHeaderElement> it = soapHeader.examineAllHeaderElements();
        while (it.hasNext()) {
            SoapHeaderElement e = it.next();
            final Object o = unmarshaller.unmarshal(e.getSource());
            if (o instanceof Header) {
                return (Header) o;
            }
        }
        throw new IllegalStateException("Could not find any Medcom Header header element");
    }

    private SoapHeader extractSoapHeader(ProceedingJoinPoint pjp) {
        for (Object arg : pjp.getArgs()) {
            if (arg instanceof SoapHeader) {
                return (SoapHeader) arg;
            }
        }
        throw new IllegalArgumentException("Endpoint method does not contain a SoapHeader argument");
    }
}
