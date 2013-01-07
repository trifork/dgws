package com.trifork.dgws;

public class IdCardSystemLog {

	private String itSystemName;
	private CareProviderIdType careProviderIdType;
	private String careProviderId;
	private String careProviderName;

	public IdCardSystemLog() {}
	
	public IdCardSystemLog(String itSystemName,
			CareProviderIdType careProviderIdType, String careProviderId,
			String careProviderName) {
				this.itSystemName = itSystemName;
				this.careProviderIdType = careProviderIdType;
				this.careProviderId = careProviderId;
				this.careProviderName = careProviderName;
	}

	public String getItSystemName() {
		return itSystemName;
	}

	public void setItSystemName(String itSystemName) {
		this.itSystemName = itSystemName;
	}

	public CareProviderIdType getCareProviderIdType() {
		return careProviderIdType;
	}

	public void setCareProviderIdType(CareProviderIdType careProviderIdType) {
		this.careProviderIdType = careProviderIdType;
	}

	public String getCareProviderId() {
		return careProviderId;
	}

	public void setCareProviderId(String careProviderId) {
		this.careProviderId = careProviderId;
	}

	public String getCareProviderName() {
		return careProviderName;
	}

	public void setCareProviderName(String careProviderName) {
		this.careProviderName = careProviderName;
	}
	
}
