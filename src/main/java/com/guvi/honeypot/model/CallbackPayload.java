package com.guvi.honeypot.model;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class CallbackPayload {
    private String sessionId;
    private boolean scamDetected;
    private int totalMessagesExchanged;
    private ExtractedIntelligence extractedIntelligence;
    private String agentNotes;
}
