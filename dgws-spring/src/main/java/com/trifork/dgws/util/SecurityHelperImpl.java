package com.trifork.dgws.util;

import oasis.names.tc.saml._2_0.assertion.Attribute;
import oasis.names.tc.saml._2_0.assertion.AttributeStatement;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.Predicate;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.Security;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.oxm.Unmarshaller;
import org.springframework.ws.soap.SoapHeader;
import org.springframework.ws.soap.SoapHeaderElement;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static org.springframework.util.CollectionUtils.findValueOfType;

public class SecurityHelperImpl implements SecurityHelper {
    @SuppressWarnings("SpringJavaAutowiringInspection Should be wired by user")
    @Autowired
    Unmarshaller unmarshaller;

    public String getCpr(SoapHeader soapHeader) {
        return getAttributeValue(soapHeader, "UserLog", "medcom:UserCivilRegistrationNumber");
    }

    public String getAttributeValue(SoapHeader soapHeader, final String attributeStatementId, final String attributeName) {
        Security security = extractSecurity(soapHeader);

        AttributeStatement attributeStatement = (AttributeStatement) CollectionUtils.find(
                security.getAssertion().getAttributeStatement(),
                new Predicate() {
                    public boolean evaluate(Object object) {
                        return ((AttributeStatement) object).getId().equals(attributeStatementId);
                    }
                });
        Attribute attribute = (Attribute) CollectionUtils.find(
                attributeStatement.getAttribute(),
                new Predicate() {
                    public boolean evaluate(Object object) {
                        return ((Attribute) object).getName().equals(attributeName);
                    }
                });

        return attribute.getAttributeValue();
    }

    public Security extractSecurity(SoapHeader soapHeader) {
        List elements = new ArrayList();
        Iterator<SoapHeaderElement> it = soapHeader.examineAllHeaderElements();
        try {
            while (it.hasNext()) {
                elements.add(unmarshaller.unmarshal(it.next().getSource()));
            }
        } catch (IOException e) {
            throw new RuntimeException("Could not unmarshal SOAP header element", e);
        }
        return findValueOfType(elements, Security.class);
    }
}
