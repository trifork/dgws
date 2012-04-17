package com.trifork.dgws;

import com.trifork.dgws.annotations.Protected;
import org.springframework.ws.soap.SoapHeader;

public interface ProtectedTarget {
    @Protected(whitelist = "TEST")
    boolean hitMe();

    @Protected(whitelist = "TEST")
    boolean hitMe(SoapHeader header);
}
