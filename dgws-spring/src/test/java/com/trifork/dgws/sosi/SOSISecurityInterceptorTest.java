package com.trifork.dgws.sosi;

import static com.trifork.dgws.sosi.SOSIFaultCode.expired_idcard;
import static com.trifork.dgws.sosi.SOSIFaultCode.invalid_signature;
import static com.trifork.dgws.sosi.SOSIFaultCode.missing_required_header;
import static com.trifork.dgws.sosi.SOSIFaultCode.syntax_error;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.Security;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import dk.sosi.seal.model.AuthenticationLevel;
import dk.sosi.seal.model.SystemIDCard;
import dk.sosi.seal.model.UserIDCard;
import dk.sosi.seal.pki.Federation;
import dk.sosi.seal.pki.SOSIFederation;
import dk.sosi.seal.pki.SOSITestFederation;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.ws.context.DefaultMessageContext;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.soap.SoapMessage;
import org.springframework.ws.transport.context.DefaultTransportContext;
import org.springframework.ws.transport.http.HttpServletConnection;
import org.springframework.ws.transport.context.TransportContextHolder;
import org.w3c.dom.Document;

class SOSISecurityInterceptorTest {
	private static SOSITestSupport support;

	private SOSISecurityInterceptor interceptor;

	@BeforeAll
	static void setupClass() throws Exception {
		support = new SOSITestSupport();

		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getRemoteAddr()).thenReturn("127.0.0.1");
		HttpServletConnection connection = mock(HttpServletConnection.class);
		when(connection.getHttpServletRequest()).thenReturn(request);
		TransportContextHolder.setTransportContext(new DefaultTransportContext(connection));
	}

	@BeforeEach
	void setup() {
		interceptor = new SOSISecurityInterceptor();
		interceptor.setFederation(support.trustedFederation());
	}

	@AfterEach
	void tearDown() {
		SOSIContext.setCard(null);
		SOSIContext.setMessageId(null);
	}

	@Test
	void seal3SignedIdCardUsesSha1Algorithms() {
		String idCardXml = support.signedIdCardXml();

		assertTrue(idCardXml.contains(SOSITestSupport.RSA_SHA1));
		assertTrue(idCardXml.contains(SOSITestSupport.SHA1));
	}

	@Test
	void defaultXmlDsigPolicyAllowsSeal3Sha1() {
		String policy = Security.getProperty(SOSITestSupport.DSIG_POLICY);

		assertFalse(policy.contains("disallowAlg " + SOSITestSupport.RSA_SHA1), policy);
		assertFalse(policy.contains("disallowAlg " + SOSITestSupport.SHA1), policy);
	}

	@Test // In case the local JVM security policy has disallowed rsa-sha1 / sha1 this will fail
	void handleRequestAcceptsValidSeal3IdCard() throws Exception {
		String messageId = UUID.randomUUID().toString();

		assertTrue(handleRequest(support.signedIdCardXml(), messageId));

		assertNotNull(SOSIContext.getCard());
		assertEquals(messageId, SOSIContext.getMessageId());
	}

	@Test
	void handleRequestAcceptsValidSystemIdCard() throws Exception {
		String messageId = UUID.randomUUID().toString();

		assertTrue(handleRequest(support.signedSystemIdCardXml(), messageId));

		assertInstanceOf(SystemIDCard.class, SOSIContext.getCard());
		assertFalse(SOSIContext.getCard() instanceof UserIDCard);
		assertEquals(messageId, SOSIContext.getMessageId());
	}

	@Test
	void handleRequestClearsPreviousContextBeforeProcessing() {
		SOSIContext.setCard(support.signedUserIdCard());
		SOSIContext.setMessageId("stale");

		assertThrows(SOSIException.class, () -> handleRequest(support.testResource("SecurityHeader1.xml"), "expired"));

		assertNull(SOSIContext.getCard());
		assertNull(SOSIContext.getMessageId());
	}

	@Test
	void handleRequestMapsExpiredIdCardBeforeSignatureValidation() {
		SOSIException e = assertThrows(SOSIException.class, () -> handleRequest(support.testResource("SecurityHeader1.xml"), "expired"));

		assertEquals(expired_idcard, e.getSOSIFaultCode());
	}

	@Test
	void handleRequestMapsUnsignedLowAuthLevelToInvalidSignature() {
		String idCardXml = support.unsignedIdCardXml(AuthenticationLevel.USERNAME_PASSWORD_AUTHENTICATION);

		SOSIException e = assertThrows(SOSIException.class, () -> handleRequest(idCardXml, "low-auth"));

		assertEquals(invalid_signature, e.getSOSIFaultCode());
	}

	@Test
	void handleRequestMapsBrokenSignature() {
		String idCardXml = support.signedIdCardXml().replace("IT-System", "Other-System");

		SOSIException e = assertThrows(SOSIException.class, () -> handleRequest(idCardXml, "broken-signature"));

		assertEquals(invalid_signature, e.getSOSIFaultCode());
	}

	@Test
	void handleRequestRejectsCardSignedByUntrustedCertificate() throws Exception {
		interceptor.setFederation(support.untrustedFederation());

		SOSIException e = assertThrows(SOSIException.class, () -> handleRequest(support.signedIdCardXml(), "untrusted"));

		assertEquals(invalid_signature, e.getSOSIFaultCode());
		assertNull(SOSIContext.getCard());
	}

	@Test
	void handleRequestMapsMalformedIdCardToSyntaxError() {
		String idCardXml = support.signedIdCardXml().replaceAll("<saml:Conditions[^>]*/>|<saml:Conditions.*?</saml:Conditions>", "");

		SOSIException e = assertThrows(SOSIException.class, () -> handleRequest(idCardXml, "no-conditions"));

		assertEquals(syntax_error, e.getSOSIFaultCode());
	}

	@Test
	void malformedIdCardIsSkippedWhenCanSkipAndNotProduction() throws Exception {
		interceptor.setCanSkipSosi(true);
		interceptor.setProduction(false);
		String idCardXml = support.signedIdCardXml().replaceAll("<saml:Conditions[^>]*/>|<saml:Conditions.*?</saml:Conditions>", "");

		assertTrue(handleRequest(idCardXml, "no-conditions"));
	}

	@Test
	void afterPropertiesSetBuildsOcesFederationByDefault() throws Exception {
		SOSISecurityInterceptor interceptor = new SOSISecurityInterceptor();
		interceptor.afterPropertiesSet();
		assertInstanceOf(SOSIFederation.class, interceptor.getFederation());
	}

	@Test
	void afterPropertiesSetBuildsTestFederationWhenNotProduction() throws Exception {
		SOSISecurityInterceptor interceptor = new SOSISecurityInterceptor();
		interceptor.setProduction(false);
		interceptor.afterPropertiesSet();
		assertInstanceOf(SOSITestFederation.class, interceptor.getFederation());
	}

	@Test
	void afterPropertiesSetKeepsInjectedFederation() throws Exception {
		Federation injected = support.trustedFederation();
		SOSISecurityInterceptor interceptor = new SOSISecurityInterceptor();
		interceptor.setFederation(injected);
		interceptor.afterPropertiesSet();
		assertSame(injected, interceptor.getFederation());
	}

	@Test
	void handleRequestFailsClosedWithoutFederation() {
		assertThrows(IllegalStateException.class, () -> new SOSISecurityInterceptor().handleRequest(support.requestContext(support.emptySoapEnvelope()), "endpoint"));
	}

	@Test
	void handleRequestRejectsMissingIdCard() {
		SOSIException e = assertThrows(SOSIException.class, () -> handleRequest("", "message-id"));

		assertEquals(missing_required_header, e.getSOSIFaultCode());
		assertNull(SOSIContext.getCard());
	}

	@Test
	void handleRequestRejectsMissingMessageId() throws Exception {
		String xml = support.soapEnvelope(support.signedIdCardXml(), "message-id").replace("<medcom:MessageID>message-id</medcom:MessageID>", "");
		MessageContext context = support.requestContext(xml);

		SOSIException e = assertThrows(SOSIException.class, () -> interceptor.handleRequest(context, "endpoint"));

		assertEquals(missing_required_header, e.getSOSIFaultCode());
		assertNull(SOSIContext.getMessageId());
	}

	@Test
	void invalidIdCardIsSkippedWhenCanSkipAndNotProduction() throws Exception {
		interceptor.setCanSkipSosi(true);
		interceptor.setProduction(false);

		assertTrue(interceptor.handleRequest(expiredIdCardRequest(), "endpoint"));

		assertNull(SOSIContext.getCard());
	}

	@Test
	void invalidIdCardIsNotSkippedInProduction() {
		interceptor.setCanSkipSosi(true);
		interceptor.setProduction(true);

		SOSIException e = assertThrows(SOSIException.class, () -> interceptor.handleRequest(expiredIdCardRequest(), "endpoint"));

		assertEquals(expired_idcard, e.getSOSIFaultCode());
	}

	@Test
	void invalidIdCardIsNotSkippedWhenCanSkipIsFalse() {
		interceptor.setCanSkipSosi(false);
		interceptor.setProduction(false);

		assertThrows(SOSIException.class, () -> interceptor.handleRequest(expiredIdCardRequest(), "endpoint"));
	}

	@Test
	void invalidIdCardIsSkippedForSkipMethodAndFlagged() throws Exception {
		interceptor.setSkipMethods(List.of("endpoint"));
		MessageContext context = expiredIdCardRequest();

		assertTrue(interceptor.handleRequest(context, "endpoint"));

		assertEquals(true, context.getProperty(SOSISecurityInterceptor.SOSI_METHOD_SKIPPED));
		assertNull(SOSIContext.getCard());
	}

	@Test
	void invalidIdCardIsNotSkippedForOtherMethod() throws Exception {
		interceptor.setSkipMethods(List.of("otherEndpoint"));
		MessageContext context = expiredIdCardRequest();

		assertThrows(SOSIException.class, () -> interceptor.handleRequest(context, "endpoint"));
		assertNull(context.getProperty(SOSISecurityInterceptor.SOSI_METHOD_SKIPPED));
	}

	@Test
	void unsignedLowAuthLevelIsSkippedLikeAnyInvalidIdCard() throws Exception {
		interceptor.setCanSkipSosi(true);
		interceptor.setProduction(false);
		String idCardXml = support.unsignedIdCardXml(AuthenticationLevel.USERNAME_PASSWORD_AUTHENTICATION);

		assertTrue(handleRequest(idCardXml, "low-auth"));

		assertNull(SOSIContext.getCard());
	}

	private MessageContext expiredIdCardRequest() throws Exception {
		return support.requestContext(support.soapEnvelope(support.testResource("SecurityHeader1.xml"), "expired"));
	}

	private boolean handleRequest(String idCardXml, String messageId) throws Exception {
		return interceptor.handleRequest(support.requestContext(support.soapEnvelope(idCardXml, messageId)), "endpoint");
	}

	@Test
	void handleResponseAddsDgwsReplyHeadersAndClearsContext() throws Exception {
		String requestId = UUID.randomUUID().toString();
		SOSIContext.setCard(support.signedUserIdCard());
		SOSIContext.setMessageId(requestId);
		DefaultMessageContext context = support.requestContext(support.emptySoapEnvelope());
		context.setResponse(support.messageFactory().createWebServiceMessage());

		assertTrue(interceptor.handleResponse(context, "endpoint"));

		Document document = ((SoapMessage) context.getResponse()).getDocument();
		assertEquals(requestId, support.text(document, SOSISecurityInterceptor.DGWS_NS, "InResponseToMessageID"));
		assertEquals("1", support.text(document, SOSISecurityInterceptor.DGWS_NS, "SecurityLevel"));
		assertEquals("flow_finalized_succesfully", support.text(document, SOSISecurityInterceptor.DGWS_NS, "FlowStatus"));
		assertNull(SOSIContext.getCard());
		assertNull(SOSIContext.getMessageId());
	}

	@Test
	void handleFaultOmitsSuccessfulFlowStatusAndClearsContext() throws Exception {
		SOSIContext.setCard(support.signedUserIdCard());
		SOSIContext.setMessageId("request-id");
		DefaultMessageContext context = support.requestContext(support.emptySoapEnvelope());
		context.setResponse(support.messageFactory().createWebServiceMessage());
		((SoapMessage) context.getResponse()).getSoapBody().addClientOrSenderFault("Invalid request", Locale.ENGLISH);

		assertTrue(interceptor.handleFault(context, "endpoint"));

		Document document = ((SoapMessage) context.getResponse()).getDocument();
		assertEquals(0, support.elementCount(document, SOSISecurityInterceptor.DGWS_NS, "FlowStatus"));
		assertEquals("request-id", support.text(document, SOSISecurityInterceptor.DGWS_NS, "InResponseToMessageID"));
		assertNull(SOSIContext.getCard());
		assertNull(SOSIContext.getMessageId());
	}

	@Test
	void handleResponseWithoutResponseClearsContext() throws Exception {
		SOSIContext.setCard(support.signedUserIdCard());
		SOSIContext.setMessageId("request-id");
		DefaultMessageContext context = support.requestContext(support.emptySoapEnvelope());

		assertTrue(interceptor.handleResponse(context, "endpoint"));

		assertNull(SOSIContext.getCard());
		assertNull(SOSIContext.getMessageId());
		assertFalse(context.hasResponse());
	}
}
