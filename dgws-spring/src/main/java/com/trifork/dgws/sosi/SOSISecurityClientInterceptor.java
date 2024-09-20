package com.trifork.dgws.sosi;

import static com.trifork.dgws.sosi.SOSISecurityInterceptor.DGWS_NS;

import java.time.Instant;
import java.util.UUID;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.ws.client.WebServiceClientException;
import org.springframework.ws.client.support.interceptor.ClientInterceptor;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.soap.SoapHeader;
import org.springframework.ws.soap.SoapHeaderElement;
import org.springframework.ws.soap.SoapMessage;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.trifork.unsealed.IdCard;
import com.trifork.unsealed.NsPrefixes;
import com.trifork.unsealed.XmlUtil;

/**
 * Client support for SOSI.
 * 
 * This adds a SOSI IDCard to a SOAP request.
 * 
 * The IDCard must be placed either in {@link SOSIContext} or in the {@link MessageContext}.
 * 
 * @author recht
 *
 */
public class SOSISecurityClientInterceptor implements ClientInterceptor, InitializingBean {

	public static final String ID_CARD = "SOSI_IDCard";
	public static final String FLOW_ID = "SOSI_FlowId";

	public boolean handleFault(MessageContext arg0) throws WebServiceClientException {
		return true;
	}

	@SuppressWarnings("serial")
	public boolean handleRequest(MessageContext ctx) throws WebServiceClientException {
		IdCard idCard = (IdCard) ctx.getProperty(ID_CARD);
		if (idCard == null)
			idCard = SOSIContext.getCard();
		if (idCard == null)
			return true;

		SOSIContext.setCard(null);

		SoapMessage soapMessage = (SoapMessage) ctx.getRequest();
		SoapHeader soapHeader = soapMessage.getSoapHeader();

		String flowId = UUID.randomUUID().toString();

		ctx.setProperty(FLOW_ID, flowId);

		try {
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setNamespaceAware(true); // Important for SOAP messages
			DocumentBuilder builder = factory.newDocumentBuilder();
			Document doc = builder.newDocument();
			
			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			Transformer transformer = transformerFactory.newTransformer();

			// Create wsse:Security header with IDCard and Created timestamp
			SoapHeaderElement securityHeaderElement = soapHeader.addHeaderElement(new QName(NsPrefixes.wsse.namespaceUri, "Security", NsPrefixes.wsse.name()));
			
			Element timestampElement = doc.createElementNS(NsPrefixes.wsu.namespaceUri, "Timestamp");
			Element createdElement = doc.createElementNS(NsPrefixes.wsu.namespaceUri, "Created");
			createdElement.setTextContent(XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(Instant.now()));
			timestampElement.appendChild(createdElement);

			transformer.transform(new DOMSource(timestampElement), securityHeaderElement.getResult());

			if (idCard != null) {
				transformer.transform(new DOMSource(idCard.getAssertion()), securityHeaderElement.getResult());
			}

			// Create medcom:Header header
			SoapHeaderElement medcomHeaderElement = soapHeader.addHeaderElement(new QName(DGWS_NS, "Header", "medcom"));
			Element securityLevelElement = doc.createElementNS(DGWS_NS, "medcom:SecurityLevel");
			securityLevelElement.setTextContent(idCard != null ? String.valueOf(idCard.getAuthLevel()) : "1");

			Element linkingElement = doc.createElementNS(DGWS_NS, "medcom:Linking");
			Element messageIdElement = doc.createElementNS(DGWS_NS, "medcom:MessageID");
			messageIdElement.setTextContent(UUID.randomUUID().toString());
			linkingElement.appendChild(messageIdElement);

			transformer.transform(new DOMSource(securityLevelElement), medcomHeaderElement.getResult());
			transformer.transform(new DOMSource(linkingElement), medcomHeaderElement.getResult());
		} catch (Exception e) {
			throw new WebServiceClientException("Unable to process SOSI request", e) {
			};
		}
		return true;
	}

	public boolean handleResponse(MessageContext arg0) throws WebServiceClientException {
		return true;
	}

	public void afterPropertiesSet() throws Exception {
		// Properties props = SignatureUtil.setupCryptoProviderForJVM();
		// vault = new EmptyCredentialVault();
		// federation = new SOSIFederation(props);
		// factory = new SOSIFactory(federation, vault, props);
	}

	@Override
	public void afterCompletion(MessageContext messageContext, Exception ex) throws WebServiceClientException {
	}

}
