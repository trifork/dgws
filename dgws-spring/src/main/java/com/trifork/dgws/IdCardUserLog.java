package com.trifork.dgws;

public class IdCardUserLog {
	public final String cpr;
	public final String givenName;
	public final String surname;
	public final String emailAddress;
	public final String role;
	public final String occupation;
	public final String authorisationCode;
	
	public IdCardUserLog(String cpr, String givenName, String surname,
			String emailAddress, String role, String occupation, String authorisationCode) {
		this.cpr = cpr;
		this.givenName = givenName;
		this.surname = surname;
		this.emailAddress = emailAddress;
		this.role = role;
		this.occupation = occupation;
		this.authorisationCode = authorisationCode;
	}
}
