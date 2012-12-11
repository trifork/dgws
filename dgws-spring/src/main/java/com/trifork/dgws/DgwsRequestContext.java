package com.trifork.dgws;

public interface DgwsRequestContext {
    String getIdCardCpr();
    IdCardUserLog getIdCardUserLog();
    String getUserLogAttribute(String attributeName);
}
