package com.trifork.dgws.sosi;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;

import dk.sosi.seal.model.AuthenticationLevel;
import dk.sosi.seal.model.UserIDCard;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.ws.context.DefaultMessageContext;
import org.springframework.ws.soap.SoapMessage;
import org.w3c.dom.Document;

class SOSISecurityClientInterceptorTest {
	private static SOSITestSupport support;

	private SOSISecurityClientInterceptor interceptor;

	@BeforeAll
	static void setupClass() throws Exception {
		support = new SOSITestSupport();
	}

	@BeforeEach
	void setup() {
		interceptor = new SOSISecurityClientInterceptor();
	}

	@AfterEach
	void tearDown() {
		SOSIContext.setCard(null);
		SOSIContext.setMessageId(null);
	}

	@Test
	void handleRequestWithoutIdCardLeavesRequestUnchanged() throws Exception {
		DefaultMessageContext context = support.requestContext(support.emptySoapEnvelope());

		assertTrue(interceptor.handleRequest(context));

		Document document = ((SoapMessage) context.getRequest()).getDocument();
		assertNull(context.getProperty(SOSISecurityClientInterceptor.FLOW_ID));
		assertEquals(0, support.elementCount(document, SOSITestSupport.WSSE_NS, "Security"));
		assertEquals(0, support.elementCount(document, SOSISecurityInterceptor.DGWS_NS, "Header"));
	}

	@Test
	void handleRequestAddsHeadersFromMessageContextIdCard() throws Exception {
		UserIDCard idCard = support.signedUserIdCard();
		DefaultMessageContext context = support.requestContext(support.emptySoapEnvelope());
		context.setProperty(SOSISecurityClientInterceptor.ID_CARD, idCard);

		assertTrue(interceptor.handleRequest(context));

		Document document = ((SoapMessage) context.getRequest()).getDocument();
		assertEquals(1, support.elementCount(document, SOSITestSupport.WSSE_NS, "Security"));
		assertEquals(1, support.elementCount(document, SOSITestSupport.WSU_NS, "Timestamp"));
		assertEquals(1, support.elementCount(document, SOSITestSupport.WSU_NS, "Created"));
		assertEquals(1, support.elementCount(document, SOSITestSupport.SAML_NS, "Assertion"));
		assertEquals(String.valueOf(idCard.getAuthenticationLevel().getLevel()), support.text(document, SOSISecurityInterceptor.DGWS_NS, "SecurityLevel"));
		assertNotNull(UUID.fromString(support.text(document, SOSISecurityInterceptor.DGWS_NS, "MessageID")));
		assertNotNull(UUID.fromString((String) context.getProperty(SOSISecurityClientInterceptor.FLOW_ID)));
	}

	@Test
	void handleRequestUsesSosiContextCardAndClearsIt() throws Exception {
		SOSIContext.setCard(support.signedUserIdCard());
		DefaultMessageContext context = support.requestContext(support.emptySoapEnvelope());

		assertTrue(interceptor.handleRequest(context));

		Document document = ((SoapMessage) context.getRequest()).getDocument();
		assertEquals(1, support.elementCount(document, SOSITestSupport.WSSE_NS, "Security"));
		assertEquals(1, support.elementCount(document, SOSISecurityInterceptor.DGWS_NS, "Header"));
		assertNull(SOSIContext.getCard());
	}

	@Test
	void handleRequestPrefersMessageContextIdCardOverSosiContextCard() throws Exception {
		UserIDCard contextCard = support.signedUserIdCard(AuthenticationLevel.MOCES_TRUSTED_USER);
		SOSIContext.setCard(support.signedUserIdCard(AuthenticationLevel.VOCES_TRUSTED_SYSTEM));
		DefaultMessageContext context = support.requestContext(support.emptySoapEnvelope());
		context.setProperty(SOSISecurityClientInterceptor.ID_CARD, contextCard);

		assertTrue(interceptor.handleRequest(context));

		Document document = ((SoapMessage) context.getRequest()).getDocument();
		assertEquals(String.valueOf(contextCard.getAuthenticationLevel().getLevel()), support.text(document, SOSISecurityInterceptor.DGWS_NS, "SecurityLevel"));
		assertNull(SOSIContext.getCard());
	}

	@Test
	void handleResponseHandleFaultAndAfterCompletionAreNoOps() throws Exception {
		DefaultMessageContext context = support.requestContext(support.emptySoapEnvelope());

		assertTrue(interceptor.handleResponse(context));
		assertTrue(interceptor.handleFault(context));
		assertDoesNotThrow(() -> interceptor.afterCompletion(context, null));
	}
}
