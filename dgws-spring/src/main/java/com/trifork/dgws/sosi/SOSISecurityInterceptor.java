package com.trifork.dgws.sosi;

import static com.trifork.dgws.sosi.SOSIFaultCode.expired_idcard;
import static com.trifork.dgws.sosi.SOSIFaultCode.invalid_signature;
import static com.trifork.dgws.sosi.SOSIFaultCode.security_level_failed;
import static com.trifork.dgws.sosi.SOSIFaultCode.syntax_error;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.server.EndpointInterceptor;
import org.springframework.ws.server.endpoint.MethodEndpoint;
import org.springframework.ws.soap.SoapHeader;
import org.springframework.ws.soap.SoapHeaderElement;
import org.springframework.ws.soap.SoapMessage;
import org.springframework.ws.transport.context.TransportContext;
import org.springframework.ws.transport.context.TransportContextHolder;
import org.springframework.ws.transport.http.HttpServletConnection;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.trifork.unsealed.IdCard;
import com.trifork.unsealed.IdCardBuilder;
import com.trifork.unsealed.NsPrefixes;
import com.trifork.unsealed.ValidationException;
import com.trifork.unsealed.XmlUtil;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Handle SOSI level 4 requests.
 * 
 * Validates that a request contains a correct SOSI IDCard. After validation, the card is placed in {@link SOSIContext} where it can be accessed.
 *
 */
public class SOSISecurityInterceptor implements EndpointInterceptor, InitializingBean {
	public static final String SOSI_FACTORY = "sosi_factory";
	public static final String FLOW_ID = "sosi_flow";
	public static final String SOSI_METHOD_SKIPPED = "sosi_method_skipped";
	public static final String DGWS_NS = "http://www.medcom.dk/dgws/2006/04/dgws-1.0.xsd";
	public static final String DGWS_PREFIX = "medcom";
	public static final String FLOW_FINALIZED_SUCCESFULLY = "flow_finalized_succesfully";

	private static final String IDCARD_XPATH = "/" + NsPrefixes.soap.name() + ":Header/" + NsPrefixes.wsse.name() + ":Security/"
			+ NsPrefixes.saml.name() + ":Assertion";

	private static final String MESSAGE_ID_XPATH = "/" + NsPrefixes.soap.name() + ":Header/" + DGWS_PREFIX + ":Header/" + DGWS_PREFIX
			+ ":Linking/" + DGWS_PREFIX + ":MessageID";

	private static final Map<String, String> EXTRA_PREFIX_MAPPINGS = Map.of(
			"dgws", DGWS_NS);;

	private boolean isProduction = true;
	private static final Logger logger = LogManager.getLogger(SOSISecurityInterceptor.class);
	private List<String> skipMethods = new ArrayList<String>();
	private boolean canSkip = false;

	public boolean handleRequest(MessageContext ctx, Object endpoint) throws Exception {
		SOSIContext.setCard(null);

		try {
			SoapMessage soapMessage = (SoapMessage) ctx.getRequest();
			SoapHeader soapHeader = soapMessage.getSoapHeader();

			Source source = soapHeader.getSource();

			DOMResult domResult = new DOMResult();

			// Use a Transformer to convert the Source to a DOMResult
			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			Transformer transformer = transformerFactory.newTransformer();
			transformer.transform(source, domResult);

			XPathContext xPathContext = new XPathContext((Document) domResult.getNode(), EXTRA_PREFIX_MAPPINGS);

			Element samlAssertion = xPathContext.findElement(IDCARD_XPATH);
			Element messageIdElement = xPathContext.findElement(MESSAGE_ID_XPATH);
			String messageId = messageIdElement.getTextContent();

			IdCard idCard = new IdCardBuilder().assertion(samlAssertion).buildIdCard();

			idCard.validate();

			logger.debug("Received SOSI request: " + messageId);

			if (idCard.getAuthLevel() < 3) {
				throw new SOSIException(security_level_failed, "Authentication level 3 is required. Current level: " + idCard.getAuthLevel());
			}
			logger.debug("SOSI idcard: Level " + idCard.getAuthLevel() + ", System: " + idCard.getItSystemName() + ", User: "
					+ idCard.getSubjectName());

			// Log if request is not DGWS 1.0.1
			if (!"1.0.1".equals(idCard.getDGWSVersion())) {
				logger.warn("DGWS version was not 1.0.1, but " + idCard.getDGWSVersion());
			}

			SOSIContext.setCard(idCard);
			SOSIContext.setMessageId(messageId);

			// ctx.setProperty(FLOW_ID, requestHeader.getFlowID());

		} catch (ValidationException e) {
			logger.error("Invalid idcard received from " + getRemote(), e);
			if (canSkip && !isProduction) {
				logger.info("Skipping SOSI processing because of ValidationException");
				return true;
			}

			String operationName = getOperation(endpoint);
			if (skipMethods.contains(operationName)) {
				logger.info("Skipping SOSI processing because the call is " + operationName);
				ctx.setProperty(SOSI_METHOD_SKIPPED, true);
				return true;
			}

			throw new SOSIException(translateValidationException(e.getMessage()), e);
		}

		return true;
	}

	private SOSIFaultCode translateValidationException(String message) {
		if (message.toLowerCase().indexOf("signature") >= 0) {
			return invalid_signature;
		}
		if (message.toLowerCase().indexOf("not yet") >= 0) {
			return expired_idcard;
		}
		if (message.toLowerCase().indexOf("no longer") >= 0) {
			return expired_idcard;
		}
		if (message.toLowerCase().indexOf("syntax") >= 0) {
			return syntax_error;
		}

		return syntax_error;
	}

	private String getOperation(Object ep) {
		if (ep instanceof MethodEndpoint) {
			MethodEndpoint mep = (MethodEndpoint) ep;
			return mep.getMethod().getName();
		} else {
			return ep.toString();
		}
	}

	public boolean handleFault(MessageContext ctx, Object arg1) throws Exception {
		return handleResponse(ctx, arg1);
	}

	public boolean handleResponse(MessageContext ctx, Object arg1) throws Exception {
		String inResponseToMessageId = SOSIContext.getMessageId();

		SOSIContext.setCard(null);
		SOSIContext.setMessageId(null);

		if (!ctx.hasResponse())
			return true;

		SoapMessage soapMessage = (SoapMessage) ctx.getResponse();
		SoapHeader soapHeader = soapMessage.getSoapHeader();

		try {
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setNamespaceAware(true); // Important for SOAP messages
			DocumentBuilder builder = factory.newDocumentBuilder();
			Document doc = builder.newDocument();

			// Create wsse:Security header with Created timestamp
			SoapHeaderElement securityHeaderElement = soapHeader.addHeaderElement(new QName(NsPrefixes.wsse.namespaceUri, "Security", "wsse"));
			Element timestampElement = doc.createElementNS(NsPrefixes.wsu.namespaceUri, "Timestamp");
			Element createdElement = doc.createElementNS(NsPrefixes.wsu.namespaceUri, "Created");
			createdElement.setTextContent(XmlUtil.ISO_WITHOUT_MILLIS_FORMATTER.format(Instant.now()));
			timestampElement.appendChild(createdElement);

			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			Transformer transformer = transformerFactory.newTransformer();
			transformer.transform(new DOMSource(timestampElement), securityHeaderElement.getResult());

			// Create medcom:Header header
			SoapHeaderElement medcomHeaderElement = soapHeader.addHeaderElement(new QName(DGWS_NS, "Header", "medcom"));
			Element securityLevelElement = doc.createElementNS(DGWS_NS, "medcom:SecurityLevel");
			securityLevelElement.setTextContent("1");

			Element linkingElement = doc.createElementNS(DGWS_NS, "medcom:Linking");
			Element messageIdElement = doc.createElementNS(DGWS_NS, "medcom:MessageID");
			messageIdElement.setTextContent(UUID.randomUUID().toString());
			linkingElement.appendChild(messageIdElement);
			Element inResponseToMessageIdElement = doc.createElementNS(DGWS_NS, "medcom:InResponseToMessageID");
			inResponseToMessageIdElement.setTextContent(inResponseToMessageId);
			linkingElement.appendChild(inResponseToMessageIdElement);
			
			
			if (!soapMessage.hasFault()) {
				Element flowStatusElement = doc.createElementNS(DGWS_NS, "medcom:FlowStatus");
				flowStatusElement.setTextContent("flow_finalized_succesfully");
				transformer.transform(new DOMSource(flowStatusElement), medcomHeaderElement.getResult());
			}

			transformer.transform(new DOMSource(securityLevelElement), medcomHeaderElement.getResult());
			transformer.transform(new DOMSource(linkingElement), medcomHeaderElement.getResult());

		} catch (Exception e) {
			if (canSkip && !isProduction) {
				logger.warn("Got exception while processing SOSI response: " + e + ", continuing because CanSkipSosi=true and isProduction=false");
				return true;
			}
		}

		return true;
	}

	public void setProduction(boolean isProduction) {
		this.isProduction = isProduction;
	}

	public void setSkipMethods(List<String> skipMethods) {
		this.skipMethods = skipMethods;
	}

	public void setCanSkipSosi(boolean canSkip) {
		this.canSkip = canSkip;
	}

	private String getRemote() {
		TransportContext context = TransportContextHolder.getTransportContext();
		HttpServletConnection connection = (HttpServletConnection) context.getConnection();
		HttpServletRequest request = connection.getHttpServletRequest();
		return request.getRemoteAddr();
	}

	public void afterPropertiesSet() throws Exception {
	}

	public void afterCompletion(MessageContext messageContext, Object endpoint, Exception ex) throws Exception {
	}
}
