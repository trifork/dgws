package com.trifork.dgws.sosi;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.*;
import dk.sosi.seal.model.constants.DGWSConstants;
import dk.sosi.seal.model.constants.FlowStatusValues;
import dk.sosi.seal.modelbuilders.ModelBuildException;
import dk.sosi.seal.modelbuilders.SignatureInvalidModelBuildException;
import dk.sosi.seal.pki.SOSIFederation;
import dk.sosi.seal.pki.SOSITestFederation;
import dk.sosi.seal.vault.ClasspathCredentialVault;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.vault.EmptyCredentialVault;
import dk.sosi.seal.xml.XmlUtilException;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.ws.WebServiceMessage;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.server.EndpointInterceptor;
import org.springframework.ws.server.endpoint.MethodEndpoint;
import org.springframework.ws.soap.SoapFault;
import org.springframework.ws.soap.SoapFaultDetailElement;
import org.springframework.ws.soap.SoapHeader;
import org.springframework.ws.soap.SoapMessage;
import org.springframework.ws.transport.context.TransportContext;
import org.springframework.ws.transport.context.TransportContextHolder;
import org.springframework.ws.transport.http.HttpServletConnection;
import org.springframework.xml.transform.TransformerObjectSupport;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.servlet.http.HttpServletRequest;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import static com.trifork.dgws.sosi.SOSIFaultCode.*;

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

	private final Properties props = SignatureUtil.setupCryptoProviderForJVM();
	private SOSIFactory factory;
	private boolean isProduction = true;
	private static final Logger logger = Logger.getLogger(SOSISecurityInterceptor.class);
	private List<String> skipMethods = new ArrayList<String>();
	private boolean canSkip = false;
	private com.trifork.dgws.sosi.SOSISecurityInterceptor.MyTransformerFactory transformerFactory;
	
	public SOSIFactory getFactory() {
		if (factory == null) {
			// Setup SOSI factory
			if (isProduction) {
				SOSIFederation federation = new SOSIFederation(props);
				factory = new SOSIFactory(federation, new EmptyCredentialVault(), props);
			} else {
				CredentialVault cv = new ClasspathCredentialVault(props, "sts.keystore", "Test1234");
				SOSITestFederation federation = new SOSITestFederation(props);
				factory = new SOSIFactory(federation, cv, props);
			}
		}
		return factory;
	}
	
	public boolean handleRequest(MessageContext ctx, Object arg1) throws Exception {
		SOSIContext.setCard(null);

		String headerStr = sourceToString(getSource(ctx.getRequest()));
		try {
			RequestHeader requestHeader = getFactory().deserializeRequestHeader(headerStr);
			IDCard idc = requestHeader.getIDCard();
	
			if (!(idc instanceof UserIDCard)) {
				logger.error("Unable to process wrong id card type: " + idc.getClass());
				throw new SOSIException(invalid_idcard, "Only UserID cards can be used. Received type: " + idc.getClass());
			}
			Date now = new Date();
			
			if (!idc.isValidInTime()) {
				logger.error("ID card is not valid in time. " + idc.getExpiryDate() + ": " + idc.getCreatedDate() + ". My date: " + now + ", request: " + requestHeader.getCreationDate());
				throw new SOSIException(expired_idcard, "ID card is not valid in time. Timestamp: " + idc.getExpiryDate());
			}
			UserIDCard card = (UserIDCard) idc;
			logger.debug("Received SOSI request: " + requestHeader.getMessageID());
			
			if (card.getAuthenticationLevel() == null || card.getAuthenticationLevel().getLevel() < 3) {
				throw new SOSIException(security_level_failed, "Authentication level 3 is required. Current level: " + card.getAuthenticationLevel());
			}
			logger.debug("SOSI idcard: Level " + card.getAuthenticationLevel().getLevel() + ", System: " + card.getSystemInfo().getITSystemName() + ", User: " + card.getSignedByCertificate().getSubjectDN());
	
			// Log if request is not DGWS 1.0.1
			if (!DGWSConstants.VERSION_1_0_1.equals(requestHeader.getDGWSVersion())) {
				logger.warn("DGWS version was not "+DGWSConstants.VERSION_1_0_1+", but "+requestHeader.getDGWSVersion());
			}

			SOSIContext.setCard(card);
			SOSIContext.setMessageId(requestHeader.getMessageID());
			
			ctx.setProperty(FLOW_ID, requestHeader.getFlowID());
			ctx.setProperty(SOSI_FACTORY, getFactory());
			
		} catch (SignatureInvalidModelBuildException e) {
			logger.error("Invalid signature received from " + getRemote(), e);
			if (canSkip && !isProduction) {
				logger.info("Skipping SOSI processing because of SignatureInvalidModelBuildException");
				return true;
			}
			throw new SOSIException(invalid_signature, e);
		} catch (ModelBuildException e) {
			if (canSkip && !isProduction) {
				logger.info("Skipping SOSI processing because of ModelBuildException.");
				return true;
			}
			logger.error("Unable to process SOSI ID card", e);
			throw new SOSIException(syntax_error, e);
		} catch (XmlUtilException e) {
			String operationName = getOperation(arg1);
			if (skipMethods.contains(operationName)) {
				logger.info("Skipping SOSI processing because the call is "+operationName);
				ctx.setProperty(SOSI_METHOD_SKIPPED, true);
				return true;
			}
			if (canSkip && !isProduction) {
				logger.info("Skipping SOSI processing due to configuration: canSkipSosi=true and isProduction=false: " + e.getMessage());
				return true;
			}
			if (!hasIDCard(headerStr)) {
				logger.debug("Header has no IDCard", e);
				throw new SOSIException(missing_required_header, e);
			}
	
			logger.error("Unable to parse SOSI xml: " + e.getMessage(), e);
			throw new SOSIException(syntax_error, e);
		} catch (ModelException e) {
			logger.error("Unable to process SOSI ID card: " + e.getMessage(), e);
			if (canSkip && !isProduction) {
				logger.info("Skipping SOSI processing because of ModelBuildException.");
				return true;
			}
			throw new SOSIException(syntax_error, e);
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
		SOSIContext.setCard(null);
		SOSIContext.setMessageId(null);
		
		if (!ctx.hasResponse()) return true;

		SoapMessage msg = (SoapMessage) ctx.getResponse();

		try {
			Request request = factory.deserializeRequest(sourceToString(getSource(ctx.getRequest())));
			Reply reply;

			if (msg.hasFault()) {
				SoapFault fault = msg.getSoapBody().getFault();
				String faultCode = "Not defined - probably a validation error";
				if (fault != null) {
					if (fault.getFaultDetail() != null && fault.getFaultDetail().getDetailEntries().hasNext()) {
						SoapFaultDetailElement detail = (SoapFaultDetailElement) fault.getFaultDetail().getDetailEntries().next();
						faultCode = sourceToString(detail.getSource());
					} else {
						logger.error("fault.getDetail() or fault.getDetail().getFirstElement() returned null");
					}
				} else {
					logger.error("mc.getEnvelope().getBody().getFault() returned null");
				}
				reply = factory.createNewErrorReply(request, faultCode, fault.getFaultStringOrReason());
			} else {
				reply = factory.createNewReply(request, FlowStatusValues.FLOW_FINALIZED_SUCCESFULLY);
			}

			Document doc = reply.serialize2DOMDocument();
			Element header = (Element) doc.getElementsByTagNameNS("*", "Header").item(0);
			NodeList headers = header.getChildNodes();
			SoapHeader sh = msg.getSoapHeader();

			Transformer trans = TransformerFactory.newInstance().newTransformer();
			for (int i = 0; i < headers.getLength(); i++) {
				if (!(headers.item(i) instanceof Element)) continue;
				Element h = (Element) headers.item(i);
				trans.transform(new DOMSource(h), sh.getResult());
			}

			if (msg.hasFault()) {

			}
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
		HttpServletConnection connection = (HttpServletConnection )context.getConnection();
		HttpServletRequest request = connection.getHttpServletRequest();
		return request.getRemoteAddr();
	}
	
	private boolean hasIDCard(String headerStr) {
		// Note: this is just an indication whether the request contains an ID Card or not.
		// A better way would be to call a method on RequestHeader, eg hasIDCard(), but that
		// method does not exist.
		return headerStr.contains("saml:Assertion");
	}

	private Source getSource(WebServiceMessage message) {
		if (message instanceof SoapMessage) {
			SoapMessage soapMessage = (SoapMessage) message;
			return soapMessage.getEnvelope().getSource();
		} else {
			return null;
		}
	}

	public String sourceToString(Source source) throws TransformerException {
		if (source == null) {
			throw new NullPointerException("source cannot be null");
		}
		Transformer transformer = transformerFactory.createNonIndentingTransformer();
		StringWriter writer = new StringWriter();
		transformer.transform(source, new StreamResult(writer));
		return writer.toString();
	}

	public void afterPropertiesSet() throws Exception {
		transformerFactory = new MyTransformerFactory();
	}
	private static class MyTransformerFactory extends TransformerObjectSupport {
		public Transformer createNonIndentingTransformer() throws TransformerConfigurationException {
			Transformer transformer = getTransformerFactory().newTransformer();
			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			transformer.setOutputProperty(OutputKeys.INDENT, "no");
			return transformer;
		}
	}

    public void afterCompletion(MessageContext messageContext, Object endpoint, Exception ex) throws Exception {
    }
}
