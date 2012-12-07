package com.trifork.dgws.util;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.springframework.oxm.Unmarshaller;

import org.apache.log4j.Logger;
import org.springframework.ws.soap.SoapHeader;
import org.springframework.ws.soap.SoapHeaderElement;

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
            } catch(Exception e) {
                logger.warn("Unknown DGWS soapheader element, cannot parse it ["+element+"]");
            }
        }
        return result;
    }

}
