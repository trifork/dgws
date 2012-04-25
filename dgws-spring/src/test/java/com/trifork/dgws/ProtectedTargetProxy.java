package com.trifork.dgws;

import com.trifork.dgws.annotations.Protected;
import org.springframework.ws.soap.SoapHeader;

public class ProtectedTargetProxy implements ProtectedTarget {
    private ProtectedTarget target;

    @SuppressWarnings("UnusedDeclaration AOP")
    public ProtectedTargetProxy() { }

    public ProtectedTargetProxy(ProtectedTarget target) {
        this.target = target;
    }

    @Protected(whitelist = "Test Whitelist")
    public String hitMe() {
        return target.hitMe();
    }

    @Protected(whitelist = "Test Whitelist")
    public String hitMe(SoapHeader header) {
        return target.hitMe(header);
    }
}
