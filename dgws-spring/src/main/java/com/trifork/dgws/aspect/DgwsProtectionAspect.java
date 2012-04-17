package com.trifork.dgws.aspect;

import com.trifork.dgws.annotations.Protected;
import dk.medcom.dgws._2006._04.dgws_1_0.Header;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.ws.soap.SoapHeader;
import org.springframework.ws.soap.SoapHeaderElement;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import java.util.Iterator;

@Aspect
public class DgwsProtectionAspect {
    JAXBContext jc;
    Unmarshaller um;

    public DgwsProtectionAspect() throws Exception {
        jc = JAXBContext.newInstance("dk.medcom.dgws._2006._04.dgws_1_0");
        um = jc.createUnmarshaller();
    }

    @Around("@annotation(protectedAnnotation)")
    public Object doAccessCheck(ProceedingJoinPoint pjp, Protected protectedAnnotation) throws Throwable {
        SoapHeader soapHeader = extractSoapHeader(pjp);

        final Header medcomHeader = unmarshalMedcomHeader(soapHeader);
        //TODO: medcom header replay
        System.out.println("medcomHeader = " + medcomHeader);

        return pjp.proceed(pjp.getArgs());
    }

    private Header unmarshalMedcomHeader(SoapHeader soapHeader) throws JAXBException {
        Iterator<SoapHeaderElement> it = soapHeader.examineAllHeaderElements();
        while (it.hasNext()) {
            SoapHeaderElement e = it.next();
            return (Header) um.unmarshal(e.getSource());
        }
        return null;
    }

    private SoapHeader extractSoapHeader(ProceedingJoinPoint pjp) {
        SoapHeader soapHeader = null;
        for (Object arg : pjp.getArgs()) {
            if (arg instanceof SoapHeader) {
                soapHeader = (SoapHeader) arg;
                break;
            }
        }
        if (soapHeader == null) {
            throw new IllegalArgumentException("Endpoint method does not contain a SoapHeader argument");
        }
        return soapHeader;
    }
}
