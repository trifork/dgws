package com.trifork.dgws;

public interface MedcomRetransmissionRegister {
    /**
     * Will return null if no replay is found
     * @param messageId message id
     * @return MedcomRetransmission containing a replayable message or null, if no message is found
     */
    MedcomRetransmission getReplay(String messageId);

    void createReplay(String messageID, Object responseMessage);
}
