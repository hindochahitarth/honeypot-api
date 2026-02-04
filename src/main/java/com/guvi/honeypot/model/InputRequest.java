package com.guvi.honeypot.model;

import lombok.Data;
import java.util.List;
import java.util.Map;

@Data
public class InputRequest {
    private String sessionId;
    private Message message;
    private List<Message> conversationHistory;
    private Map<String, Object> metadata;
}
