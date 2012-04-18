package com.trifork.dgws.aspect;

import com.trifork.dgws.MedcomReplay;
import com.trifork.dgws.MedcomReplayRegister;
import com.trifork.dgws.annotations.Protected;
import dk.medcom.dgws._2006._04.dgws_1_0.Header;
import org.apache.log4j.Logger;
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
    private static final Logger logger = Logger.getLogger(DgwsProtectionAspect.class);

    @Autowired
    Unmarshaller unmarshaller;
    @Autowired
    MedcomReplayRegister medcomReplayRegister;

    @Around("@annotation(protectedAnnotation)")
    public Object doAccessCheck(ProceedingJoinPoint pjp, Protected protectedAnnotation) throws Throwable {
        SoapHeader soapHeader = extractSoapHeader(pjp);
        final Header medcomHeader = unmarshalMedcomHeader(soapHeader);

        String messageID = medcomHeader.getLinking().getMessageID();
        logger.debug("Received message with messageID=" + messageID);

        //TODO: access checking…

        MedcomReplay replay = medcomReplayRegister.getReplay(messageID);
        if (replay != null) {
            logger.info("Replaying message with messageID=" + replay.getMessageId());
            //TODO: check that pjp.proceed(pjp.getArgs()) has same return type
            return replay.getResponseMessage();
        }

        return pjp.proceed(pjp.getArgs());
    }

    private SoapHeader extractSoapHeader(ProceedingJoinPoint pjp) {
        /* TODO: Some decisions to make...
            1. Checking method arguments for a SoapHeader argument if no SoapHeader is found in pjp.getArgs() for a more precise error message, or
            2. Dig into Spring-ws to find the actual SoapHeader
        */
        for (Object arg : pjp.getArgs()) {
            if (arg instanceof SoapHeader) {
                return (SoapHeader) arg;
            }
        }
        throw new IllegalArgumentException("Endpoint method does not contain a SoapHeader argument or it is null");
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
}
