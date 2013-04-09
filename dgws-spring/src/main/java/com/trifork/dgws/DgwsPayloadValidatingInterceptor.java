package com.trifork.dgws;

import com.trifork.dgws.sosi.SOSIFaultCode;
import org.springframework.ws.WebServiceMessage;
import org.springframework.ws.client.WebServiceTransformerException;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.soap.*;
import org.springframework.ws.soap.server.endpoint.interceptor.AbstractFaultCreatingValidatingInterceptor;
import org.xml.sax.SAXParseException;

import javax.xml.namespace.QName;
import javax.xml.transform.*;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.StringReader;
import java.io.StringWriter;


/**
 * Configurable Spring-WS DGWS payload validating interceptor.  This interceptor will create DGWS 1.0 compliat SOAP fault element with a medcom:FaultCode with a value of either SOSIFaultCode.request_payload_validation_error or SOSIFaultCode.response_payload_validation_error.
 * <p/>
 * <p/>
 * By default the interceptor will validate both request and the response.
 * The default behavior is that Validation failures will cause a SoapFault if the request does not validate.
 * If the response does not validate the validation errors will be logged by default, but no Soap Fault will be returned.
 * <p/>
 * To change the default behavior call setCreateFaultWhenRequestNotValid and setCreateFaultWhenResponseNotValid.
 * <p/>
 * The detail element will contain a list of the validation errors if getAddValidationErrorDetail is true (the default).
 * If you need to change how the detail element is populated with the validation errors you can overwrite the method handleDetailElement and populate the element as desired.
 * <p/>
 * Call @{link AbstractFaultCreatingValidatingInterceptor.setDetailElementName} to specify the QName of the Detail element containing the error message.
 */
public class DgwsPayloadValidatingInterceptor extends AbstractFaultCreatingValidatingInterceptor {

    private static final String REQUEST = "request";
    private static final String RESPONSE = "response";

    private boolean createFaultWhenRequestNotValid = true;
    private boolean createFaultWhenResponseNotValid = false;

    @Override
    protected Source getValidationRequestSource(WebServiceMessage request) {
        return transformSourceToStreamSourceWithStringReader(request.getPayloadSource());
    }

    @Override
    protected Source getValidationResponseSource(WebServiceMessage response) {
        return transformSourceToStreamSourceWithStringReader(response.getPayloadSource());
    }

    protected Source transformSourceToStreamSourceWithStringReader(Source notValidatableSource) {
        final Source source;
        try {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();

            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION,
                                          "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "no");
            StringWriter writer = new StringWriter();
            transformer.transform(notValidatableSource, new StreamResult(
                    writer));

            String transformed = writer.toString();
            StringReader reader = new StringReader(transformed);
            source = new StreamSource(reader);

        } catch (TransformerException transformerException) {
            throw new WebServiceTransformerException(
                    "Could not convert the source to a StreamSource with a StringReader",
                    transformerException);
        }

        return source;
    }

    /**
     * Template method that is called when the response message contains validation errors. This implementation logs all
     * errors, returns <code>false</code>, and creates a {@link org.springframework.ws.soap.SoapBody#addClientOrSenderFault(String, java.util.Locale) client or
     * sender} {@link org.springframework.ws.soap.SoapFault}, adding a {@link org.springframework.ws.soap.SoapFaultDetail} with all errors if the
     * <code>addValidationErrorDetail</code> property is <code>true</code>.
     *
     * @param messageContext the message context
     * @param errors         the validation errors
     * @return <code>true</code> to continue processing the request, <code>false</code> (the default) otherwise
     */
    @Override
    protected boolean handleResponseValidationErrors(MessageContext messageContext, SAXParseException[] errors) {
        addValidationErrorDetails(RESPONSE, messageContext, errors, getCreateFaultWhenResponseNotValid());
        return false;
    }


    /**
     * Template method that is called when the request message contains validation errors. This implementation logs all
     * errors, returns <code>false</code>, and creates a {@link org.springframework.ws.soap.SoapBody#addClientOrSenderFault(String, java.util.Locale) client or
     * sender} {@link org.springframework.ws.soap.SoapFault}, adding a {@link org.springframework.ws.soap.SoapFaultDetail} with all errors if the
     * <code>addValidationErrorDetail</code> property is <code>true</code>.
     *
     * @param messageContext the message context
     * @param errors         the validation errors
     * @return <code>true</code> to continue processing the request, <code>false</code> (the default) otherwise
     */
    @Override
    protected boolean handleRequestValidationErrors(MessageContext messageContext, SAXParseException[] errors)
            throws TransformerException {
        addValidationErrorDetails(REQUEST, messageContext, errors, getCreateFaultWhenRequestNotValid());
        return false;
    }

    private void addValidationErrorDetails(String type, MessageContext messageContext, SAXParseException[] errors, boolean createFault) {
        for (SAXParseException error : errors) {
            logger.warn("XML validation error on " + type + ": " + error.getMessage());
            if (logger.isDebugEnabled()) {
                Source source = null;
                if (REQUEST.equals(type)) {
                    source = messageContext.getRequest().getPayloadSource();
                } else if (RESPONSE.equals(type)) {
                    source = messageContext.getResponse().getPayloadSource();
                }

                logger.debug("Payload: " + source);
            }
        }

        if (createFault && messageContext.getResponse() instanceof SoapMessage) {
            SoapMessage response = (SoapMessage) messageContext.getResponse();
            SoapBody body = response.getSoapBody();
            SoapFault fault = body.addClientOrSenderFault(getFaultStringOrReason(), getFaultStringOrReasonLocale());
            if (getAddValidationErrorDetail()) {
                SoapFaultDetail detail = fault.addFaultDetail();
                SoapFaultDetailElement de1 = detail.addFaultDetailElement(new QName("http://www.medcom.dk/dgws/2006/04/dgws-1.0.xsd", "FaultCode", "medcom"));
                if (REQUEST.equals(type)) {
                    de1.addText(SOSIFaultCode.request_payload_validation_error.name());
                } else if (RESPONSE.equals(type)) {
                    de1.addText(SOSIFaultCode.response_payload_validation_error.name());
                }

                handleDetailElement(errors, detail);
            }
        }
    }

    protected void handleDetailElement(SAXParseException[] errors, SoapFaultDetail detail) {
        SoapFaultDetailElement de2 = detail.addFaultDetailElement(getDetailElementName());
        StringBuilder errorMessage = new StringBuilder();
        for (SAXParseException error : errors) {
            errorMessage.append(error.getMessage()).append("\n");
        }
        de2.addText(errorMessage.toString());
    }

    public boolean getCreateFaultWhenResponseNotValid() {
        return createFaultWhenResponseNotValid;
    }

    public boolean isCreateFaultWhenResponseNotValid() {
        return createFaultWhenResponseNotValid;
    }

    public void setCreateFaultWhenResponseNotValid(boolean createFaultWhenResponseNotValid) {
        this.createFaultWhenResponseNotValid = createFaultWhenResponseNotValid;
    }

    public boolean getCreateFaultWhenRequestNotValid() {
        return createFaultWhenRequestNotValid;
    }

    public boolean isCreateFaultWhenRequestNotValid() {
        return createFaultWhenRequestNotValid;
    }

    public void setCreateFaultWhenRequestNotValid(boolean createFaultWhenRequestNotValid) {
        this.createFaultWhenRequestNotValid = createFaultWhenRequestNotValid;
    }
}
