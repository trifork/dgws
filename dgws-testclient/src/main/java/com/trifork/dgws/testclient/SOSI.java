package com.trifork.dgws.testclient;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Element;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.AuthenticationLevel;
import dk.sosi.seal.model.CareProvider;
import dk.sosi.seal.model.IDCard;
import dk.sosi.seal.model.SecurityTokenRequest;
import dk.sosi.seal.model.SignatureUtil;
import dk.sosi.seal.model.UserInfo;
import dk.sosi.seal.model.constants.SubjectIdentifierTypeValues;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.vault.GenericCredentialVault;
import dk.sosi.seal.xml.XmlUtil;
import com.trifork.dgws.testclient.Helper.ServiceException;

/**
 *
 */
public class SOSI {


        public static IDCard getIDCardElement(boolean sign, SOSIFactory factory, CredentialVault vault, PersonAndCertificate person) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
                SignatureException, IOException, ServiceException, ParserConfigurationException {
            CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, person.getCvr(), "test");
            UserInfo userInfo = new UserInfo(person.getCpr(), person.getFirstName(), person.getLastName(), person.getEmail(), "test user", "Doctor", "000");
            IDCard card = factory.createNewUserIDCard("SOSITEST", userInfo, careProvider, AuthenticationLevel.MOCES_TRUSTED_USER, null, null, person.getCertificate(), null);
            if (sign) {
                card = signIdCard(factory, vault, card, person);
            }
            return card;
        }

        public static IDCard signIdCard(SOSIFactory factory, CredentialVault vault, IDCard card, PersonAndCertificate person)
                throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException,
                IOException, ServiceException {
            SecurityTokenRequest req = factory.createNewSecurityTokenRequest();
            req.setIDCard(card);

            byte[] bytesForSigning = req.getIDCard().getBytesForSigning(req.serialize2DOMDocument());

            Signature jceSign = Signature.getInstance("SHA1withRSA", SignatureUtil.getCryptoProvider(SignatureUtil.setupCryptoProviderForJVM(), SOSIFactory.PROPERTYNAME_SOSI_CRYPTOPROVIDER_SHA1WITHRSA));
            //PrivateKey key = vault.getSystemCredentialPair().getPrivateKey();
            jceSign.initSign(person.getPrivateKey());
            jceSign.update(bytesForSigning);
            String signature = XmlUtil.toBase64(jceSign.sign());

            req.getIDCard().injectSignature(signature, person.getCertificate());

            String xml = XmlUtil.node2String(req.serialize2DOMDocument(), false, true);

            String res = null;
            try {
                res = Helper.sendRequest("http://pan.certifikat.dk/sts/services/SecurityTokenService", "", xml, true);
            } catch (ServiceException e) {
                // Hack to support SOAP Faults
                testForSoapFaultAndThrowSoapFaultException(e.getMessage(), xml);
                throw e;
            }

            // Hack to support SOAP Faults
            testForSoapFaultAndThrowSoapFaultException(res, xml);

            SecurityTokenRequest stRes = factory.deserializeSecurityTokenRequest(res);
            card = stRes.getIDCard();
            return card;
        }

        private static void testForSoapFaultAndThrowSoapFaultException(String res, String requestXml) {
            int faultIndex = res.indexOf("<faultstring>");
            if (faultIndex >= 0) {
                System.err.println("Failed request:\n\n" + requestXml + "\n\n");
                int faultEndIndex = res.indexOf("</faultstring>");
                String msg = res.substring(faultIndex + 13, faultEndIndex);
                throw new RuntimeException(msg);
                //throw new SoapFaultException(msg);
            }
        }

        public static String getIDCard(boolean sign, SOSIFactory factory, CredentialVault vault, PersonAndCertificate person) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
                SignatureException, IOException, ServiceException, ParserConfigurationException {

            IDCard card = getIDCardElement(sign, factory, vault, person);

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);

            Element cardElement = card.serialize2DOMDocument(factory, dbf.newDocumentBuilder().newDocument());
            String cardXML = XmlUtil.node2String(cardElement, false, true);
            return cardXML;
        }

        public static PersonAndCertificate getTestPersonAndCertificate(CredentialVault vault) {
            PersonAndCertificate person = new PersonAndCertificate("Fornavn", "Efternavn", //
                                                                   "username@somedomain.dk", "2006271866", "25520041", vault.getSystemCredentialPair().getCertificate(), //
                                                                   vault.getSystemCredentialPair().getPrivateKey());
            return person;
        }

        public static List<X509Certificate> getAllCertificatesFromVault(GenericCredentialVault vault) throws Exception {
            List<X509Certificate> certificates = new ArrayList<X509Certificate>();
            Enumeration<String> aliases = vault.getKeyStore().aliases();
            while (aliases.hasMoreElements()) {
                certificates.add((X509Certificate)vault.getKeyStore().getCertificate(aliases.nextElement()));
            }
            return certificates;
        }

//	public static List<String> getAllCertificateAliasesFromVault(GenericCredentialVault vault) throws Exception {
//		List<String> certificates = new ArrayList<String>();
//		Enumeration<String> aliases = vault.getKeyStore().aliases();
//		while (aliases.hasMoreElements()) {
//			certificates.add((X509Certificate)vault.getKeyStore().getCertificate(aliases.nextElement()));
//		}
//		return certificates;
//	}


}
