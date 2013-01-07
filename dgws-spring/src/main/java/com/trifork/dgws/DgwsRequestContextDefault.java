package com.trifork.dgws;

import static org.springframework.util.CollectionUtils.findValueOfType;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import oasis.names.tc.saml._2_0.assertion.Attribute;
import oasis.names.tc.saml._2_0.assertion.AttributeStatement;

import org.apache.commons.collections15.CollectionUtils;
import org.apache.commons.collections15.Predicate;
import org.apache.log4j.Logger;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.Security;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.oxm.Unmarshaller;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.server.EndpointInterceptor;
import org.springframework.ws.soap.SoapHeader;
import org.springframework.ws.soap.SoapMessage;

import com.trifork.dgws.util.DGWSUtil;

import dk.sosi.seal.model.constants.SubjectIdentifierTypeValues;

public class DgwsRequestContextDefault implements DgwsRequestContext, EndpointInterceptor {
    private static Logger logger = Logger.getLogger(DgwsRequestContextDefault.class);
    ThreadLocal<Security> securityThreadLocal = new ThreadLocal<Security>();
    @Autowired
    Unmarshaller unmarshaller;
    
    @SuppressWarnings("serial")
	private static final Map<String, CareProviderIdType> careProviderNameFormatMap = new HashMap<String, CareProviderIdType>() {{
    	put(SubjectIdentifierTypeValues.CVR_NUMBER, CareProviderIdType.CVR_NUMBER);
    	put(SubjectIdentifierTypeValues.P_NUMBER, CareProviderIdType.P_NUMBER);
    	put(SubjectIdentifierTypeValues.Y_NUMBER, CareProviderIdType.Y_NUMBER);
    	put(SubjectIdentifierTypeValues.SKS_CODE, CareProviderIdType.SKS_CODE);
    }};

	private static final Map<String, IdCardType> idCardTypeMap = new HashMap<String, IdCardType>() {{
    	put("user", IdCardType.USER);
    	put("system", IdCardType.SYSTEM);
    }};

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
    
    private String trim(String toBeTrimmed) {
    	if(toBeTrimmed == null) {
    		return null;
    	}
    	return toBeTrimmed.trim();
    }
    
    public IdCardSystemLog getIdCardSystemLog() {
    	String itSystemName = getSystemLogAttributeValue("medcom:ITSystemName");
    	Attribute careProviderIdAttribute = findAttribute("SystemLog", "medcom:CareProviderID");
    	String careProviderId = careProviderIdAttribute.getAttributeValue();
    	String careProviderIdNameFormat = careProviderIdAttribute.getNameFormat();
    	CareProviderIdType  careProviderIdType= careProviderNameFormatMap.get(careProviderIdNameFormat);
    	String careProviderName = getSystemLogAttributeValue("medcom:CareProviderName");
    	return new IdCardSystemLog(trim(itSystemName), careProviderIdType, trim(careProviderId), trim(careProviderName));
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
        return CollectionUtils.find(statements, new Predicate<AttributeStatement>() {
            public boolean evaluate(AttributeStatement attributeStatement) {
                return attributeStatement.getId().equals(attributeStatementId);
            }
        });
    }
    
    public Attribute findAttribute(AttributeStatement statement, final String attributeName) {
        return CollectionUtils.find(statement.getAttribute(), new Predicate<Attribute>() {
            public boolean evaluate(Attribute attribute) {
                return attribute.getName().equals(attributeName);
            }
        });
    }
    
    public Attribute findAttribute(String attributeStatementId, String attributeName) {
    	AttributeStatement statement = findAttributeStatement(securityThreadLocal.get().getAssertion().getAttributeStatement(), attributeStatementId);
    	if(statement == null) {
    		return null;
    	}
    	return findAttribute(statement, attributeName);
    }
    
    public String getUserLogAttributeValue(final String attributeName) {
    	
        final Attribute attribute = findAttribute("UserLog", attributeName);
        if(attribute != null) {
	        logger.debug("Found user attribute value" + attributeName + "=" + attribute.getAttributeValue() + " in header");
	        return attribute.getAttributeValue();
        }
        else {
        	return null;
        }
    }
    
    public String getSystemLogAttributeValue(final String attributeName) {
        final Attribute attribute = findAttribute("SystemLog", attributeName);
        if(attribute != null) {
	        logger.debug("Found system attribute value" + attributeName + "=" + attribute.getAttributeValue() + " in header");
	        return attribute.getAttributeValue();
        }
        else {
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
