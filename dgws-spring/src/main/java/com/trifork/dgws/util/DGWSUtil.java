package com.trifork.dgws.util;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.springframework.oxm.Unmarshaller;

import org.apache.log4j.Logger;
import org.springframework.ws.soap.SoapHeader;
import org.springframework.ws.soap.SoapHeaderElement;

import javax.xml.namespace.QName;

public class DGWSUtil {
    
    private static Logger logger = Logger.getLogger(DGWSUtil.class);
    
    public static List<Object> unmarshalHeaderElements(SoapHeader soapHeader, Unmarshaller unmarshaller) throws Exception {
        List<Object> result = new ArrayList<Object>();
        if(soapHeader == null) {
        	return result;
        }
        final Iterator<SoapHeaderElement> it = soapHeader.examineAllHeaderElements();
        while (it.hasNext()) {
            SoapHeaderElement element = it.next();
            try {
                result.add(unmarshaller.unmarshal(element.getSource()));
            } catch (Exception e) {
                StringBuilder detail = new StringBuilder();
                QName qName = element.getName();
                String prefix = qName.getPrefix();
                String nsUri = qName.getNamespaceURI();
                String localPart = qName.getLocalPart();
                detail.append(prefix).append(":").append(localPart).append(" xmlns:").append(prefix).append("=\"").append(nsUri).append("\"");

                logger.info("Unknown DGWS soapheader element, cannot unmarshal it [" + detail.toString() + "]");

            }
        }
        return result;
    }

}
