package com.trifork.dgws.sosi;

import com.trifork.unsealed.IdCard;

public class SOSIContext {
	
	private static final ThreadLocal<IdCard> card = new ThreadLocal<IdCard>();
	private static final ThreadLocal<String> messageId = new ThreadLocal<String>();
	
	public static IdCard getCard() {
		return card.get();
	}
	
	public static String getMessageId() {
		return messageId.get();
	}

	public static void setCard(IdCard card) {
		SOSIContext.card.set(card);
	}

	public static void setMessageId(String messageId) {
		SOSIContext.messageId.set(messageId);
	}

}
