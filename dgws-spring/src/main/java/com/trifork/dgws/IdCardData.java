package com.trifork.dgws;

public class IdCardData {

	private IdCardType idCardType;
	private int authenticationLevel;

	public IdCardData() {}
	
	public IdCardData(IdCardType idCardType, int authenticationLevel) {
		this.idCardType = idCardType;
		this.authenticationLevel = authenticationLevel;
	}

	public int getAuthenticationLevel() {
		return authenticationLevel;
	}

	public void setAuthenticationLevel(int authenticationLevel) {
		this.authenticationLevel = authenticationLevel;
	}

	public IdCardType getIdCardType() {
		return idCardType;
	}

	public void setIdCardType(IdCardType idCardType) {
		this.idCardType = idCardType;
	}

}
