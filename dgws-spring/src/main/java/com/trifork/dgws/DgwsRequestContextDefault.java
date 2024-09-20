package com.trifork.dgws;

import static org.springframework.util.CollectionUtils.findValueOfType;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import oasis.names.tc.saml._2_0.assertion.Attribute;
import oasis.names.tc.saml._2_0.assertion.AttributeStatement;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.Security;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.oxm.Unmarshaller;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.server.EndpointInterceptor;
import org.springframework.ws.soap.SoapHeader;
import org.springframework.ws.soap.SoapMessage;

import com.trifork.dgws.util.DGWSUtil;

public class DgwsRequestContextDefault implements DgwsRequestContext, EndpointInterceptor {
    private static Logger logger = LogManager.getLogger(DgwsRequestContextDefault.class);
    ThreadLocal<Security> securityThreadLocal = new ThreadLocal<Security>();
    @Autowired
    Unmarshaller unmarshaller;

    @SuppressWarnings("serial")
    private static final Map<String, CareProviderIdType> careProviderNameFormatMap = new HashMap<String, CareProviderIdType>() {
        {
            put("medcom:cvrnumber", CareProviderIdType.CVR_NUMBER);
            put("medcom:pnumber", CareProviderIdType.P_NUMBER);
            put("medcom:ynumber", CareProviderIdType.Y_NUMBER);
            put("medcom:skscode", CareProviderIdType.SKS_CODE);
        }
    };

    @SuppressWarnings("serial")
    private static final Map<String, IdCardType> idCardTypeMap = new HashMap<String, IdCardType>() {
        {
            put("user", IdCardType.USER);
            put("system", IdCardType.SYSTEM);
        }
    };

    public IdCardUserLog getIdCardUserLog() {
        String cpr = getUserLogAttributeValue("medcom:UserCivilRegistrationNumber");
        String givenName = getUserLogAttributeValue("medcom:UserGivenName");
        String surname = getUserLogAttributeValue("medcom:UserSurName");
        String emailAddress = getUserLogAttributeValue("medcom:UserEmailAddress");
        String role = getUserLogAttributeValue("medcom:UserRole");
        String occupation = getUserLogAttributeValue("medcom:UserOccupation");
        String authorisationCode = getUserLogAttributeValue("medcom:UserAuthorizationCode");
        return new IdCardUserLog(cpr, givenName, surname, emailAddress, role, occupation, authorisationCode);
    }

    public IdCardSystemLog getIdCardSystemLog() {
        String itSystemName = getSystemLogAttributeValue("medcom:ITSystemName");
        Attribute careProviderIdAttribute = findAttribute("SystemLog", "medcom:CareProviderID");
        String careProviderId = careProviderIdAttribute.getAttributeValue();
        String careProviderIdNameFormat = careProviderIdAttribute.getNameFormat();
        CareProviderIdType careProviderIdType = careProviderNameFormatMap.get(careProviderIdNameFormat);
        String careProviderName = getSystemLogAttributeValue("medcom:CareProviderName");
        return new IdCardSystemLog(trim(itSystemName), careProviderIdType, trim(careProviderId), trim(careProviderName));
    }

    private String trim(String str) {
        return str == null ? null : str.trim();
    }

    public IdCardData getIdCardData() {
        AttributeStatement idCardData = findAttributeStatement(securityThreadLocal.get().getAssertion().getAttributeStatement(), "IDCardData");
        int authenticationLevel = Integer.parseInt(findAttribute(idCardData, "sosi:AuthenticationLevel").getAttributeValue());
        String idCardTypeString = findAttribute(idCardData, "sosi:IDCardType").getAttributeValue();
        IdCardType idCardType = idCardTypeMap.get(idCardTypeString);
        return new IdCardData(idCardType, authenticationLevel);
    }

    @Deprecated
    public String getIdCardCpr() {
        return getUserLogAttributeValue("medcom:UserCivilRegistrationNumber");
    }

    public AttributeStatement findAttributeStatement(List<AttributeStatement> statements, final String attributeStatementId) {
        return statements.stream()
                .filter(attributeStatement -> attributeStatement.getId().equals(attributeStatementId))
                .findFirst()
                .orElse(null);
    }

    public Attribute findAttribute(AttributeStatement statement, final String attributeName) {
        return statement.getAttribute().stream()
                .filter(attribute -> attribute.getName().equals(attributeName))
                .findFirst().orElse(null);
    }

    public Attribute findAttribute(String attributeStatementId, String attributeName) {
        AttributeStatement statement = findAttributeStatement(securityThreadLocal.get().getAssertion().getAttributeStatement(), attributeStatementId);
        if (statement == null) {
            return null;
        }
        return findAttribute(statement, attributeName);
    }

    public String getUserLogAttributeValue(final String attributeName) {

        final Attribute attribute = findAttribute("UserLog", attributeName);
        if (attribute != null) {
            logger.debug("Found user attribute value" + attributeName + "=" + attribute.getAttributeValue() + " in header");
            return attribute.getAttributeValue();
        } else {
            return null;
        }
    }

    public String getSystemLogAttributeValue(final String attributeName) {
        final Attribute attribute = findAttribute("SystemLog", attributeName);
        if (attribute != null) {
            logger.debug("Found system attribute value" + attributeName + "=" + attribute.getAttributeValue() + " in header");
            return attribute.getAttributeValue();
        } else {
            return null;
        }
    }

    void setSecurityThreadLocal(Security security) {
        securityThreadLocal.set(security);
    }

    void setSecurityThreadLocal(SoapHeader soapHeader) throws Exception {
        List<Object> headerElements = DGWSUtil.unmarshalHeaderElements(soapHeader, unmarshaller);
        Security securityHeader = findValueOfType(headerElements, Security.class);
        setSecurityThreadLocal(securityHeader);
    }

    public boolean handleRequest(MessageContext messageContext, Object o) throws Exception {
        if (messageContext.getRequest() instanceof SoapMessage) {
            SoapHeader soapHeader = ((SoapMessage) messageContext.getRequest()).getSoapHeader();
            setSecurityThreadLocal(soapHeader);
        }
        return true;
    }

    public boolean handleResponse(MessageContext messageContext, Object o) throws Exception {
        return true;
    }

    public boolean handleFault(MessageContext messageContext, Object o) throws Exception {
        return true;
    }

    public void afterCompletion(MessageContext messageContext, Object o, Exception e) throws Exception {
        securityThreadLocal.remove();
    }

}
