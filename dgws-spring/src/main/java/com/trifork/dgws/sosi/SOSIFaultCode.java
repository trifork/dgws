package com.trifork.dgws.sosi;

import javax.xml.namespace.QName;

import static org.springframework.ws.soap.server.endpoint.SoapFaultDefinition.CLIENT;
import static org.springframework.ws.soap.server.endpoint.SoapFaultDefinition.SERVER;

public enum SOSIFaultCode {
	
	// FaultCodes from "Den Gode WebService" v1.0:
	syntax_error(CLIENT),
	missing_required_header(CLIENT),
	security_level_failed(CLIENT),
	invalid_username_password(CLIENT),
	invalid_signature(CLIENT),
	invalid_idcard(CLIENT),
	invalid_certificate(CLIENT),
	expired_idcard(CLIENT),
	not_authorized(CLIENT),
	illegal_HTTP_method(CLIENT),
	nonrepudiation_not_supported(SERVER),
	
	// Custom FaultCodes:
	server_error(SERVER);
	
	// Implementation
	private QName soapFaultCode;
	private SOSIFaultCode(QName soapFaultCode) {
		this.soapFaultCode = soapFaultCode;
	}
	
	public QName getSoapFaultCode() {
		return soapFaultCode;
	}
}
