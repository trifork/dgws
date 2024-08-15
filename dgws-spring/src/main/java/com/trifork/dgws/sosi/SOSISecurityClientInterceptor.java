package com.trifork.dgws.sosi;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.IDCard;
import dk.sosi.seal.model.Request;
import dk.sosi.seal.model.SignatureUtil;
import dk.sosi.seal.pki.SOSIFederation;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.vault.EmptyCredentialVault;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.ws.client.WebServiceClientException;
import org.springframework.ws.client.support.interceptor.ClientInterceptor;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.soap.SoapMessage;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import java.util.Properties;
import java.util.UUID;

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
	
	private SOSIFactory factory;
	private SOSIFederation federation;
	private CredentialVault vault;
	
	public boolean handleFault(MessageContext arg0) throws WebServiceClientException {
		return true;
	}

	@SuppressWarnings("serial")
	public boolean handleRequest(MessageContext ctx) throws WebServiceClientException {
		IDCard card = (IDCard) ctx.getProperty(ID_CARD);
		if (card == null) card = SOSIContext.getCard();
		if (card == null) return true;
		
		SOSIContext.setCard(null);
		
		SoapMessage sm = (SoapMessage) ctx.getRequest();
		
		String flowId = UUID.randomUUID().toString();
		Request req = factory.createNewRequest(false, flowId);
		req.setIDCard(card);
		ctx.setProperty(FLOW_ID, flowId);

		try {
			Transformer trans = TransformerFactory.newInstance().newTransformer();
			DOMResult res = new DOMResult();
			trans.transform(sm.getSoapBody().getPayloadSource(), res);

			Document body = (Document) res.getNode();
			req.setBody(body.getDocumentElement());

			Document doc = req.serialize2DOMDocument();
			Node header = doc.getElementsByTagNameNS("*", "Header").item(0);
			NodeList children = header.getChildNodes();
			for (int i = 0; i < children.getLength(); i++) {
				trans.transform(new DOMSource(children.item(i)), sm.getSoapHeader().getResult());
			}
			trans.transform(new DOMSource(doc.getElementsByTagNameNS("*", "Body").item(0).getFirstChild()), sm.getPayloadResult());
		} catch (Exception e) {
			throw new WebServiceClientException("Unable to process SOSI request", e) {};
		}
		return true;
	}

	public boolean handleResponse(MessageContext arg0) throws WebServiceClientException {
		return true;
	}
	
	public void afterPropertiesSet() throws Exception {
		Properties props = SignatureUtil.setupCryptoProviderForJVM();
		vault = new EmptyCredentialVault();
		federation = new SOSIFederation(props);
		factory = new SOSIFactory(federation, vault, props);
	}

	@Override
	public void afterCompletion(MessageContext messageContext, Exception ex) throws WebServiceClientException {
	}

}
