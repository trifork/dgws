package com.trifork.dgws.testclient;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.SignatureUtil;
import dk.sosi.seal.model.constants.FlowStatusValues;
import dk.sosi.seal.pki.SOSITestFederation;
import dk.sosi.seal.vault.FileBasedCredentialVault;
import dk.sosi.seal.vault.GenericCredentialVault;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.apache.log4j.Logger;
import org.joda.time.format.ISODateTimeFormat;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;

import java.io.File;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Properties;
import java.util.UUID;

/**
 *
 */
public class DGWSRequestHelper {

    private static final Logger logger = Logger.getLogger(DGWSRequestHelper.class);

    public static final String PROPERTY_SOAPACTION = "soapaction";

    private String serviceEndpoint;

    private Resource keystore;
    private String keystorePassword;
    private String keystoreAlias;

    private static GenericCredentialVault vault;
    private static SOSIFactory factory;
    private static Properties props;
    private static SOSITestFederation federation;
    private boolean whitelistingHeaderEnabled = false;

    // MessageID (both WSA and medcom header). Null means generate new.
    private String messageID = null;

    // SDSD System Header
    @Value("${sdsd.system.owner.name}")
    private String systemOwnerName;

    @Value("${sdsd.system.name}")
    private String systemName;

    @Value("${sdsd.system.version}")
    private String systemVersion;

    @Value("${sdsd.org.responsible.name}")
    private String orgResponsibleName;

    @Value("${sdsd.org.using.name}")
    private String orgUsingName;

    @Value("${sdsd.org.using.id.name.format}")
    private String orgUsingIdNameFormat;

    @Value("${sdsd.org.using.id.value}")
    private String orgUsingIdValue;

    @Value("${sdsd.requested.role}")
    private String requestedRole;

    @Value("${soapaction:}")
    private String soapAction;

    @Required
    public void setKeystore(Resource keystore) {
        this.keystore = keystore;
    }
    @Required
    public void setKeystorePassword(String keystorePassword) {
        this.keystorePassword = keystorePassword;
    }
    @Required
    public void setServiceEndpoint(String serviceEndpoint) {
        this.serviceEndpoint = serviceEndpoint;
    }
    @Required
    public void setKeystoreAlias(String keystoreAlias) {
        this.keystoreAlias = keystoreAlias;
    }

    public void setWhitelistingHeaderEnabled(boolean enabled) {
        this.whitelistingHeaderEnabled = enabled;
    }



    public void init() throws IOException {
        props = SignatureUtil.setupCryptoProviderForJVM();

        if (!keystore.exists()) {
            throw  new RuntimeException("Keystore '"+keystore.getURI() +"' could not be found");
        }

//        vault = new FileBasedCredentialVault(props, keystore, keystorePassword);
        vault = new InputStreamCredentialVault(props, keystore.getInputStream(), keystorePassword);
        federation = new SOSITestFederation(props);
        factory = new SOSIFactory(federation, vault, props);
    }

    private String getMedcomRequestHeader(String messageId, String flowId) {
        return "      <Header xmlns=\"http://www.medcom.dk/dgws/2006/04/dgws-1.0.xsd\">\n" +
                "         <SecurityLevel>1</SecurityLevel>\n" +
                "         <TimeOut>1440</TimeOut>\n" +
                "         <Linking>\n" +
                "            <FlowID>" + flowId + "</FlowID>\n" +
                "            <MessageID>" + messageId + "</MessageID>\n" +
                "         </Linking>\n" +
                "         <FlowStatus>" + FlowStatusValues.FLOW_RUNNING + "</FlowStatus>\n" +
                "         <Priority>RUTINE</Priority>\n" +
                "         <RequireNonRepudiationReceipt>no</RequireNonRepudiationReceipt>\n" +
                "      </Header>\n";
    }

    private String getSecurityElement() throws Exception {
        return SECURITY_OPEN + getSamlAssertion() + SECURITY_CLOSE;
    }

    private String getSamlAssertion() throws Exception {

        PrivateKey key = (PrivateKey) vault.getKeyStore().getKey(keystoreAlias, keystorePassword.toCharArray());
        X509Certificate cert = (X509Certificate) vault.getKeyStore().getCertificate(keystoreAlias);

        PersonAndCertificate personAndCertificate = new PersonAndCertificate("Muhamad", "Danielsen", "muhamad@somedomain.dk", "2006271866", orgUsingIdValue, cert, key);
        return getSosiIdCard(personAndCertificate);
    }

    private String getSosiIdCard(PersonAndCertificate person) throws Exception {
        String idCard = SOSI.getIDCard(true, factory, vault, person);
        // This code formats the XML nicely, but then the signature validation fails...
        // String formattedXml = XmlFormatter.formatXml(idCard);
        int index = idCard.indexOf("?>");
        if (index > 0 && idCard.length() > index + 2) {
            idCard = idCard.substring(index + 2);
        }
        return idCard;
    }

    public String getSoapEnvelope(String body) throws Exception {
        StringBuilder soapRequest = new StringBuilder();
        soapRequest
                .append(SOAP_ENV_OPEN)
                .append(SOAP_HEADER_OPEN)
                .append(getHeaderElements())
                .append(SOAP_HEADER_CLOSE)
                .append(SOAP_BODY_OPEN)
                .append(body)
                .append(SOAP_BODY_CLOSE)
                .append(SOAP_ENV_CLOSE);
        return soapRequest.toString();
    }

    private String getHeaderElements() throws Exception {
        String messageId = UUID.randomUUID().toString().replaceAll("-", "");
        String flowId = UUID.randomUUID().toString().replaceAll("-", "");
        return getSecurityElement() + getMedcomRequestHeader(messageId, flowId) + ONBEHALFOF_HEADER + getWhitelistingHeaderEnabled();
    }

    /**
     * Whitelisting header is optional - the content is controlled by the whitelisting.header property defined in config.properties
     * @return empty string if whitelisting.header=false, else a valid whitelisting header will be returned
     */
    private String getWhitelistingHeaderEnabled() {
        String header = "";
        if (whitelistingHeaderEnabled) {
            header = "       <ns1:WhiteListingHeader>\n" +
                    "         <ns:SystemOwnerName>" + systemOwnerName + "</ns:SystemOwnerName>\n" +
                    "         <ns:SystemName>" + systemName + "</ns:SystemName>\n" +
                    "         <ns:SystemVersion>" + systemVersion + "</ns:SystemVersion>\n" +
                    "         <ns:OrgResponsibleName>" + orgResponsibleName + "</ns:OrgResponsibleName>\n" +
                    "         <ns:OrgUsingID NameFormat=\"" + orgUsingIdNameFormat + "\">" + orgUsingIdValue + "</ns:OrgUsingID>\n" +
                    "         <ns:RequestedRole>" + requestedRole + "</ns:RequestedRole>\n" +
                    "      </ns1:WhiteListingHeader>\n";
        }
        return header;
    }

    public String makeRequest(String body) throws Exception {
        configure();

        if (soapAction != null && soapAction.trim().length() > 0) {
            postMethod.addRequestHeader("SOAPAction", soapAction);
        }

        postMethod.setRequestEntity(new StringRequestEntity(getSoapEnvelope(body), "text/xml", "UTF-8"));

        StringBuilder headerLog = new StringBuilder("");
        headerLog.append("URI: ").append(postMethod.getURI()).append("\n");
        headerLog.append("Headers: \n");
        for (Header header : postMethod.getRequestHeaders()) {
            headerLog.append("\t").append(header.getName()).append(": ").append(header.getValue()).append("\n");
        }
        logger.info(headerLog.toString());

        int status = client.executeMethod(postMethod);
        logger.info("Result: " + postMethod.getStatusLine().toString());

        String response = postMethod.getResponseBodyAsString();
        if (status != HttpStatus.SC_OK) {
            throw new RuntimeException("Soap request for URI '"+postMethod.getURI()+"' failed - status '"+status+": "+postMethod.getStatusText()+"': \n" + response);
        }
        return response;

    }

    protected PostMethod postMethod;
    protected HttpClient client;

    private void configure() {
        postMethod = new PostMethod(serviceEndpoint);
        postMethod.addRequestHeader("Content-Type", "text/xml");
        postMethod.addRequestHeader("Accept", "text/xml,application/xml;q=0.9");

        client = new HttpClient();
        client.getParams().setParameter("http.useragent", "DGWS Test Client");
        client.getParams().setParameter("http.connection.timeout", new Integer(5000));
    }

    private final String SOAP_ENV_OPEN = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ns=\"http://www.sdsd.dk/dgws/2010/08\" xmlns:ns1=\"http://www.sdsd.dk/dgws/2012/06\" xmlns:ns2=\"http://vaccinationsregister.dk/schemas/2010/07/01\">\n";
    private final String SOAP_HEADER_OPEN = "   <soapenv:Header>\n";

    private final String SOAP_BODY_OPEN = "   <soapenv:Body>\n";
    private final String SOAP_BODY_CLOSE = "   </soapenv:Body>\n";

    private final String SOAP_ENV_CLOSE = "</soapenv:Envelope>";

    private static final String ONBEHALFOF_HEADER = "";
    private final String SECURITY_OPEN = "      <Security xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">\n" +
            "         <Timestamp xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">\n" +
            "            <Created>" + ISODateTimeFormat.dateTimeNoMillis().print(System.currentTimeMillis()) + "</Created>\n" +
            "         </Timestamp>\n";
    //datetime format 2010-09-23T12:18:04Z


    private final String SECURITY_CLOSE = "      </Security>\n";
    private final String SOAP_HEADER_CLOSE = "   </soapenv:Header>\n";

}
