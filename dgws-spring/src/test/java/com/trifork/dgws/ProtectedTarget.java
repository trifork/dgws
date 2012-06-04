package com.trifork.dgws;

import org.springframework.ws.soap.SoapHeader;

public interface ProtectedTarget {
    String hitMe();

    String hitMe(SoapHeader header);

    String publicHitMe(SoapHeader soapHeader);
    
    String hitMeAuth(SoapHeader soapHeader);
}
