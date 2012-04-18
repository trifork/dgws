package com.trifork.dgws;

import com.trifork.dgws.annotations.Protected;
import org.springframework.ws.soap.SoapHeader;

public class ProtectedTargetProxy implements ProtectedTarget {
    private ProtectedTarget target;

    public ProtectedTargetProxy() {
        //aop
    }

    public ProtectedTargetProxy(ProtectedTarget target) {
        this.target = target;
    }

    @Protected(whitelist = "TEST")
    public String hitMe() {
        return target.hitMe();
    }

    @Protected(whitelist = "TEST")
    public String hitMe(SoapHeader header) {
        return target.hitMe(header);
    }
}
