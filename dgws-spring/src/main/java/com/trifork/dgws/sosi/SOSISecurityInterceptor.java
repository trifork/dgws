package com.trifork.dgws.sosi;

import static com.trifork.dgws.sosi.SOSIFaultCode.expired_idcard;
import static com.trifork.dgws.sosi.SOSIFaultCode.invalid_signature;
import static com.trifork.dgws.sosi.SOSIFaultCode.security_level_failed;
import static com.trifork.dgws.sosi.SOSIFaultCode.syntax_error;

import java.util.ArrayList;
import java.util.Date;
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

import dk.sosi.seal.model.IDCard;
import dk.sosi.seal.model.ModelException;
import dk.sosi.seal.model.SystemIDCard;
import dk.sosi.seal.model.UserIDCard;
import dk.sosi.seal.model.UserInfo;
import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.modelbuilders.ModelBuildException;
import dk.sosi.seal.xml.XmlUtil;
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

import jakarta.servlet.http.HttpServletRequest;

/**
 * Handle SOSI level 4 requests.
 * <p>
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

	private static final String IDCARD_XPATH = "/" + NameSpaces.NS_SOAP + ":Header/" + NameSpaces.NS_WSSE + ":Security/"
			+ NameSpaces.NS_SAML + ":Assertion";

	private static final String MESSAGE_ID_XPATH = "/" + NameSpaces.NS_SOAP + ":Header/" + DGWS_PREFIX + ":Header/" + DGWS_PREFIX
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

			IDCard idCard;
			try {
				idCard = IDCard.from(samlAssertion);
			} catch (ModelBuildException | ModelException e) {
				throw new SOSIException(syntax_error, e);
			}

			if (!idCard.isValidInTime()) {
				throw new SOSIException(expired_idcard, "IDCard is not valid in time");
			}

			logger.debug("Received SOSI request: " + messageId);

			if (idCard.getAuthenticationLevel().getLevel() < 3) {
				throw new SOSIException(security_level_failed, "Authentication level 3 is required. Current level: " + idCard.getAuthenticationLevel().getLevel());
			}

			try {
				idCard.validateSignature();
			} catch (ModelException e) {
				throw new SOSIException(invalid_signature, e);
			}

			SystemIDCard systemIdCard = (SystemIDCard) idCard;
			UserInfo userInfo = idCard instanceof UserIDCard userIdCard ? userIdCard.getUserInfo() : null;
			logger.debug("SOSI idcard: Level " + idCard.getAuthenticationLevel().getLevel()
					+ ", System: " + systemIdCard.getSystemInfo().getITSystemName()
					+ ", User: " + (userInfo == null ? null : userInfo.getGivenName() + " " + userInfo.getSurName()));

			// Log if request is not DGWS 1.0.1
			if (!"1.0.1".equals(idCard.getVersion())) {
				logger.warn("DGWS version was not 1.0.1, but " + idCard.getVersion());
			}

			SOSIContext.setCard(idCard);
			SOSIContext.setMessageId(messageId);

			// ctx.setProperty(FLOW_ID, requestHeader.getFlowID());

			} catch (SOSIException e) {
				logger.error("Invalid idcard received from " + getRemote(), e);
				if (canSkip && !isProduction) {
					logger.info("Skipping SOSI processing because of invalid IDCard");
					return true;
				}

				String operationName = getOperation(endpoint);
				if (skipMethods.contains(operationName)) {
					logger.info("Skipping SOSI processing because the call is " + operationName);
					ctx.setProperty(SOSI_METHOD_SKIPPED, true);
					return true;
				}

				throw e;
			}

		return true;
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
			SoapHeaderElement securityHeaderElement = soapHeader.addHeaderElement(new QName(NameSpaces.WSSE_SCHEMA, "Security", NameSpaces.NS_WSSE));
			Element timestampElement = doc.createElementNS(NameSpaces.WSU_SCHEMA, "Timestamp");
			Element createdElement = doc.createElementNS(NameSpaces.WSU_SCHEMA, "Created");
			createdElement.setTextContent(XmlUtil.toXMLTimeStamp(new Date(), true));
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
