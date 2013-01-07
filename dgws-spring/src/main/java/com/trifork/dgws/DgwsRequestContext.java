package com.trifork.dgws;

public interface DgwsRequestContext {
    /**
     * @deprecated use getUserLogAttributeValue("medcom:UserCivilRegistrationNumber") instead
     * @return
     */
	@Deprecated
    String getIdCardCpr();
	
	IdCardData getIdCardData();
    IdCardUserLog getIdCardUserLog();
    IdCardSystemLog getIdCardSystemLog();
    String getUserLogAttributeValue(String attributeName);
}
