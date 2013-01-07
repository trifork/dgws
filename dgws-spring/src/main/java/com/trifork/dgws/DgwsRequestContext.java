package com.trifork.dgws;

public interface DgwsRequestContext {
	@Deprecated
    String getIdCardCpr();
	
	IdCardData getIdCardData();
    IdCardUserLog getIdCardUserLog();
    IdCardSystemLog getIdCardSystemLog();
    String getUserLogAttributeValue(String attributeName);
}
