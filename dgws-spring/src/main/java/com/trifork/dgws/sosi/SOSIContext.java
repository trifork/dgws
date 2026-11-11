package com.trifork.dgws.sosi;

import dk.sosi.seal.model.IDCard;

public class SOSIContext {
	
	private static final ThreadLocal<IDCard> card = new ThreadLocal<IDCard>();
	private static final ThreadLocal<String> messageId = new ThreadLocal<String>();
	
	public static IDCard getCard() {
		return card.get();
	}
	
	public static String getMessageId() {
		return messageId.get();
	}

	public static void setCard(IDCard card) {
		SOSIContext.card.set(card);
	}

	public static void setMessageId(String messageId) {
		SOSIContext.messageId.set(messageId);
	}

}
