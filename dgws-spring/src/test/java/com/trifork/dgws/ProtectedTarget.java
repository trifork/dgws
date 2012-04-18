package com.trifork.dgws;

import com.trifork.dgws.annotations.Protected;
import org.springframework.ws.soap.SoapHeader;

public interface ProtectedTarget {
    String hitMe();

    String hitMe(SoapHeader header);
}
