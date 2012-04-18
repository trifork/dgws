package com.trifork.dgws;

public interface MedcomReplayRegister {
    /**
     * Will return null if no replay is found
     * @param messageId
     * @return MedcomReplay containing a replayable message or null, if no message is found
     */
    MedcomReplay getReplay(String messageId);
}
