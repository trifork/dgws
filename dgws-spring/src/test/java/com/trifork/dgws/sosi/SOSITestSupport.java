package com.trifork.dgws.sosi;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import javax.xml.parsers.DocumentBuilderFactory;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.AuthenticationLevel;
import dk.sosi.seal.model.CareProvider;
import dk.sosi.seal.model.Request;
import dk.sosi.seal.model.SystemIDCard;
import dk.sosi.seal.model.UserIDCard;
import dk.sosi.seal.model.UserInfo;
import dk.sosi.seal.model.constants.SubjectIdentifierTypeValues;
import dk.sosi.seal.pki.Federation;
import dk.sosi.seal.pki.DistinguishedName;
import dk.sosi.seal.pki.SignatureProviderFactory;
import dk.sosi.seal.vault.CredentialPair;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.vault.CredentialVaultException;
import dk.sosi.seal.xml.XmlUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.ws.context.DefaultMessageContext;
import org.springframework.ws.soap.saaj.SaajSoapMessageFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

final class SOSITestSupport {
	static final String DSIG_POLICY = "jdk.xml.dsig.secureValidationPolicy";
	static final String RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
	static final String SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";
	static final String SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
	static final String WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
	static final String WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

	private final SOSIFactory sosiFactory;
	private final SaajSoapMessageFactory messageFactory;

	SOSITestSupport() throws Exception {
		sosiFactory = new SOSIFactory(new TestCredentialVault(), System.getProperties());
		messageFactory = new SaajSoapMessageFactory();
		messageFactory.afterPropertiesSet();
	}

	Federation trustedFederation() {
		return federation(sosiFactory.getCredentialVault().getSystemCredentialPair().getCertificate());
	}

	Federation untrustedFederation() throws Exception {
		return federation(new TestCredentialVault().getSystemCredentialPair().getCertificate());
	}

	private Federation federation(X509Certificate trustedSts) {
		return new Federation(new java.util.Properties(), null) {
			@Override
			public boolean isValidSTSCertificate(X509Certificate certificate) {
				return trustedSts.equals(certificate);
			}

			@Override
			protected boolean subjectDistinguishedNameMatches(DistinguishedName subjectDistinguishedName) {
				return false;
			}
		};
	}

	SaajSoapMessageFactory messageFactory() {
		return messageFactory;
	}

	UserIDCard signedUserIdCard() {
		return signedUserIdCard(AuthenticationLevel.MOCES_TRUSTED_USER);
	}

	UserIDCard signedUserIdCard(AuthenticationLevel authenticationLevel) {
		UserIDCard idCard = unsignedUserIdCard(authenticationLevel);
		Request request = sosiFactory.createNewRequest(false, "flow");
		request.setIDCard(idCard);
		idCard.sign(request.serialize2DOMDocument(), SignatureProviderFactory.fromCredentialVault(sosiFactory.getCredentialVault()));
		return idCard;
	}

	SystemIDCard signedSystemIdCard() {
		CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "11111111", "Trifork");
		X509Certificate certificate = sosiFactory.getCredentialVault().getSystemCredentialPair().getCertificate();
		SystemIDCard idCard = sosiFactory.createNewSystemIDCard("IT-System", careProvider, AuthenticationLevel.VOCES_TRUSTED_SYSTEM, null, null, certificate, null);
		Request request = sosiFactory.createNewRequest(false, "flow");
		request.setIDCard(idCard);
		idCard.sign(request.serialize2DOMDocument(), SignatureProviderFactory.fromCredentialVault(sosiFactory.getCredentialVault()));
		return idCard;
	}

	String signedSystemIdCardXml() {
		return stripXmlDeclaration(XmlUtil.node2String(signedSystemIdCard().serialize2DOMDocument(sosiFactory, XmlUtil.createEmptyDocument())));
	}

	String signedIdCardXml() {
		return signedIdCardXml(AuthenticationLevel.MOCES_TRUSTED_USER);
	}

	String signedIdCardXml(AuthenticationLevel authenticationLevel) {
		return stripXmlDeclaration(XmlUtil.node2String(signedUserIdCard(authenticationLevel).serialize2DOMDocument(sosiFactory, XmlUtil.createEmptyDocument())));
	}

	String unsignedIdCardXml(AuthenticationLevel authenticationLevel) {
		return stripXmlDeclaration(XmlUtil.node2String(unsignedUserIdCard(authenticationLevel).serialize2DOMDocument(sosiFactory, XmlUtil.createEmptyDocument())));
	}

	DefaultMessageContext requestContext(String xml) throws Exception {
		return new DefaultMessageContext(messageFactory.createWebServiceMessage(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8))), messageFactory);
	}

	String soapEnvelope(String assertionXml, String messageId) {
		return """
				<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
						xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
						xmlns:medcom="http://www.medcom.dk/dgws/2006/04/dgws-1.0.xsd">
					<soapenv:Header>
						<wsse:Security>%s</wsse:Security>
						<medcom:Header>
							<medcom:SecurityLevel>4</medcom:SecurityLevel>
							<medcom:Linking><medcom:MessageID>%s</medcom:MessageID></medcom:Linking>
						</medcom:Header>
					</soapenv:Header>
					<soapenv:Body/>
				</soapenv:Envelope>
				""".formatted(assertionXml, messageId);
	}

	String emptySoapEnvelope() {
		return """
				<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
					<soapenv:Header/>
					<soapenv:Body/>
				</soapenv:Envelope>
				""";
	}

	String testResource(String name) throws Exception {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		Document document = factory.newDocumentBuilder().parse(getClass().getResourceAsStream("/" + name));
		Element assertion = (Element) document.getElementsByTagNameNS(SAML_NS, "Assertion").item(0);
		return stripXmlDeclaration(XmlUtil.node2String(assertion));
	}

	String text(Document document, String namespace, String localName) {
		return document.getElementsByTagNameNS(namespace, localName).item(0).getTextContent();
	}

	int elementCount(Document document, String namespace, String localName) {
		return document.getElementsByTagNameNS(namespace, localName).getLength();
	}

	private UserIDCard unsignedUserIdCard(AuthenticationLevel authenticationLevel) {
		CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "11111111", "Trifork");
		UserInfo userInfo = new UserInfo("1111111118", "Anders", "Andersen", null, null, "Doctor", null);
		return sosiFactory.createNewUserIDCard("IT-System", userInfo, careProvider, authenticationLevel, "user", "password", null, null);
	}

	private String stripXmlDeclaration(String xml) {
		return xml.replaceFirst("^\\s*<\\?xml[^>]*>\\s*", "");
	}

	private static class TestCredentialVault implements CredentialVault {
		private final CredentialPair credentialPair;

		TestCredentialVault() throws Exception {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			credentialPair = new CredentialPair(certificate(keyPair), keyPair.getPrivate());
		}

		@Override
		public boolean isTrustedCertificate(X509Certificate certificate) {
			return credentialPair.getCertificate().equals(certificate);
		}

		@Override
		public CredentialPair getSystemCredentialPair() {
			return credentialPair;
		}

		@Override
		public void setSystemCredentialPair(CredentialPair credentialPair) throws CredentialVaultException {
			throw new CredentialVaultException("Test vault is immutable");
		}

		@Override
		public KeyStore getKeyStore() {
			return null;
		}

		private static X509Certificate certificate(KeyPair keyPair) throws Exception {
			Instant now = Instant.now();
			X500Name subject = new X500Name("CN=Seal3 Test,O=Trifork,C=DK");
			JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
					subject,
					BigInteger.valueOf(now.toEpochMilli()),
					Date.from(now.minus(1, ChronoUnit.DAYS)),
					Date.from(now.plus(365, ChronoUnit.DAYS)),
					subject,
					keyPair.getPublic()
			);
			return new JcaX509CertificateConverter().getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate())));
		}
	}
}
