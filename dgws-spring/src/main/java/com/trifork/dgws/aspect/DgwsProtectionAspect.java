package com.trifork.dgws.aspect;

import com.trifork.dgws.MedcomRetransmission;
import com.trifork.dgws.MedcomRetransmissionRegister;
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

    @SuppressWarnings("SpringJavaAutowiringInspection should be wired by user")
    @Autowired
    Unmarshaller unmarshaller;

    @SuppressWarnings("SpringJavaAutowiringInspection should be wired by user")
    @Autowired
    MedcomRetransmissionRegister medcomRetransmissionRegister;

    @Around("@annotation(protectedAnnotation)")
    public Object doAccessCheck(ProceedingJoinPoint pjp, Protected protectedAnnotation) throws Throwable {
        SoapHeader soapHeader = extractSoapHeader(pjp);
        final Header medcomHeader = unmarshalMedcomHeader(soapHeader);

        String messageID = medcomHeader.getLinking().getMessageID();
        logger.debug("Received webservice request with messageID=" + messageID);

        //TODO: access checking…

        MedcomRetransmission retransmission = medcomRetransmissionRegister.getReplay(messageID);
        if (retransmission != null) {
            logger.info("Replaying message with messageID=" + retransmission.getMessageId() + ", shortcutting webservice request with response=" + retransmission.getResponseMessage().toString());
            //TODO: check that pjp.proceed(pjp.getArgs()) has same return type
            return retransmission.getResponseMessage();
        }

        Object responseMessage = pjp.proceed(pjp.getArgs());

        medcomRetransmissionRegister.createReplay(messageID, responseMessage);

        return responseMessage;
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
