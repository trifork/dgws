package com.trifork.dgws.sosi;

import org.springframework.ws.soap.SoapFault;
import org.springframework.ws.soap.SoapFaultDetail;
import org.springframework.ws.soap.SoapFaultDetailElement;
import org.springframework.ws.soap.server.endpoint.AbstractSoapFaultDefinitionExceptionResolver;
import org.springframework.ws.soap.server.endpoint.SoapFaultDefinition;

import javax.xml.namespace.QName;

public class SOSIExceptionResolver extends AbstractSoapFaultDefinitionExceptionResolver {

	@Override
	protected SoapFaultDefinition getFaultDefinition(Object ep, Exception e) {
		if (!(e instanceof SOSIException)) 
			return null;
		
		SOSIException ex = (SOSIException) e; 
		
		SoapFaultDefinition def = new SoapFaultDefinition();
		def.setFaultCode(ex.getSOSIFaultCode().getSoapFaultCode());
		def.setFaultStringOrReason(ex.getMessage());
		
		return def;
	}

	@Override
	protected void customizeFault(Object endpoint, Exception ex, SoapFault fault) {
		SOSIException se = (SOSIException) ex;
		SoapFaultDetail detail = fault.addFaultDetail();
		SoapFaultDetailElement de = detail.addFaultDetailElement(new QName("http://www.medcom.dk/dgws/2006/04/dgws-1.0.xsd", "FaultCode"));
		de.addText(se.getSOSIFaultCode().name());
	}
}
