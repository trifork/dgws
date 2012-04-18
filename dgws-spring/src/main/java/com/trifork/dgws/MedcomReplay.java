package com.trifork.dgws;

public class MedcomReplay {
    private final String messageId;
    private final Object responseMessage;

    public MedcomReplay(String messageId, Object responseMessage) {
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
