package com.trifork.dgws;

public class MedcomRetransmission {
    private final String messageId;
    private final Object responseMessage;

    public MedcomRetransmission(String messageId, Object responseMessage) {
        this.messageId = messageId;
        this.responseMessage = responseMessage;
    }

    public String getMessageId() {
        return messageId;
    }

    public Object getResponseMessage() {
        return responseMessage;
    }
}
