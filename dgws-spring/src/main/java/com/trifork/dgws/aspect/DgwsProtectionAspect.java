package com.trifork.dgws.aspect;

import static org.springframework.util.CollectionUtils.findValueOfType;

import java.util.List;

import org.apache.log4j.Logger;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.Security;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.oxm.Unmarshaller;
import org.springframework.ws.soap.SoapHeader;

import com.trifork.dgws.MedcomRetransmission;
import com.trifork.dgws.MedcomRetransmissionRegister;
import com.trifork.dgws.SecurityChecker;
import com.trifork.dgws.annotations.Protected;
import com.trifork.dgws.sosi.SOSIException;
import com.trifork.dgws.sosi.SOSIFaultCode;
import com.trifork.dgws.util.DGWSUtil;

import dk.medcom.dgws._2006._04.dgws_1_0.Header;

@Aspect
public class DgwsProtectionAspect {
    private static final Logger logger = Logger.getLogger(DgwsProtectionAspect.class);

    @SuppressWarnings("SpringJavaAutowiringInspection should be wired by user")
    @Autowired
    Unmarshaller unmarshaller;

    @SuppressWarnings("SpringJavaAutowiringInspection should be wired by user")
    @Autowired(required=false)
    MedcomRetransmissionRegister medcomRetransmissionRegister;

    @Autowired
    SecurityChecker securityChecker;

    public DgwsProtectionAspect() {
        System.out.println("DgwsProtectionAspect.DgwsProtectionAspect");
    }

    @Around("@annotation(protectedAnnotation)")
    public Object doAccessCheck(ProceedingJoinPoint pjp, Protected protectedAnnotation) throws Throwable {
        SoapHeader soapHeader = extractSoapHeader(pjp);

        final List<Object> list = DGWSUtil.unmarshalHeaderElements(soapHeader, unmarshaller);
        final Header medcomHeader = findValueOfType(list, Header.class);
        final Security securityHeader = findValueOfType(list, Security.class);
        
        if(medcomHeader == null || medcomHeader.getLinking() == null || medcomHeader.getLinking().getMessageID() == null){
        	throw new SOSIException(SOSIFaultCode.missing_required_header, "medcom header is missing or invalid");
        }
        
        String messageID = medcomHeader.getLinking().getMessageID();
        logger.debug("Received webservice request with messageID=" + messageID);

        securityChecker.validateHeader(protectedAnnotation.whitelist(), protectedAnnotation.minAuthLevel(), securityHeader);

        if(medcomRetransmissionRegister != null){
			MedcomRetransmission retransmission = medcomRetransmissionRegister.getReplay(messageID);
			if (retransmission != null) {
				logger.info("Replaying message with messageID=" + retransmission.getMessageId() + ", shortcutting webservice request with response=" + retransmission.getResponseMessage().toString());
				// TODO: check that pjp.proceed(pjp.getArgs()) has same return type
				return retransmission.getResponseMessage();
			}
        }

        Object responseMessage = pjp.proceed(pjp.getArgs());

        if(medcomRetransmissionRegister != null) {
        	medcomRetransmissionRegister.createReplay(messageID, responseMessage);
        }

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

}
