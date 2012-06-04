package com.trifork.dgws.sosi;


public class SOSIException extends RuntimeException {
	private static final long serialVersionUID = -4454954608588946974L;
	private final SOSIFaultCode sosiFaultCode;

	public SOSIException(SOSIFaultCode sosiFaultCode, Exception e) {
		super(e);
		this.sosiFaultCode = sosiFaultCode;
	}
	
	public SOSIException(SOSIFaultCode sosiFaultCode, String message) {
		super(message);
		this.sosiFaultCode = sosiFaultCode;
	}
	
	public SOSIFaultCode getSOSIFaultCode() {
		return sosiFaultCode;
	}

}
