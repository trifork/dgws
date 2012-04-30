package com.trifork.dgws.util;

import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.Security;
import org.springframework.ws.soap.SoapHeader;

public interface SecurityHelper {

    String getCpr(SoapHeader soapHeader);

    String getAttributeValue(SoapHeader soapHeader, String attributeStatementId, String attributeName);

    Security extractSecurity(SoapHeader soapHeader);
}
