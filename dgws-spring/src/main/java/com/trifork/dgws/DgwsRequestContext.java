package com.trifork.dgws;

public interface DgwsRequestContext {
    String getIdCardCpr();

    String getUserLogAttribute(String attributeName);
}
