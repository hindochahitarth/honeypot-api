package com.guvi.honeypot.model;

import lombok.Data;

@Data
public class SessionData {
    private String sessionId;
    private Intelligence intelligence = new Intelligence();
    private boolean scamDetected = false;
    private long startTime = System.currentTimeMillis();
}
