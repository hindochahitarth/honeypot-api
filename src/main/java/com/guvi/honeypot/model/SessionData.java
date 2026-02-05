package com.guvi.honeypot.model;

import lombok.Data;
import java.util.concurrent.atomic.AtomicBoolean;

@Data
public class SessionData {
    private String sessionId;
    private Intelligence intelligence = new Intelligence();
    private boolean scamDetected = false;
    private AtomicBoolean callbackSent = new AtomicBoolean(false);
    private long startTime = System.currentTimeMillis();

    public AtomicBoolean getCallbackSent() {
        return callbackSent;
    }
}
