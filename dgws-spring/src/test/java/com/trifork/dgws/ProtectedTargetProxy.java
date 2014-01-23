package com.trifork.dgws;

import org.springframework.ws.soap.SoapHeader;

import com.trifork.dgws.annotations.Protected;

public class ProtectedTargetProxy implements ProtectedTarget {
    private ProtectedTarget target;

    @SuppressWarnings("UnusedDeclaration AOP")
    public ProtectedTargetProxy() { }

    public ProtectedTargetProxy(ProtectedTarget target) {
        this.target = target;
    }

    @Override
    @Protected(whitelist = "Test Whitelist")
    public String hitMe() {
        return target.hitMe();
    }

    @Override
    @Protected(whitelist = "Test Whitelist")
    public String hitMe(SoapHeader header) {
        return target.hitMe(header);
    }

    @Override
    @Protected
    public String publicHitMe(SoapHeader soapHeader) {
        return target.publicHitMe(soapHeader);
    }
    
    @Override
    @Protected(minAuthLevel=2)
    public String hitMeAuth(SoapHeader soapHeader) {
    	return target.hitMeAuth(soapHeader);
    }
}