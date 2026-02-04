package com.guvi.honeypot.controller;

import com.guvi.honeypot.model.InputRequest;
import com.guvi.honeypot.model.Message;
import com.guvi.honeypot.service.HoneyPotService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
public class HoneyPotController {

    private final HoneyPotService honeyPotService;
    private static final String API_KEY = "SECRET123";

    public HoneyPotController(HoneyPotService honeyPotService) {
        this.honeyPotService = honeyPotService;
    }

    @PostMapping("/honeypot")
    public ResponseEntity<Map<String, Object>> handleHoneypot(
            @RequestHeader(value = "x-api-key", required = false) String apiKey,
            @RequestBody(required = false) Map<String, Object> requestBody) {

        // 1. Strict Authentication
        if (!API_KEY.equals(apiKey)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        // 2. Permissive Input Handling (No 400s)
        if (requestBody == null) {
            requestBody = new HashMap<>();
        }

        // 3. Manual Mapping to keep Service Logic (Best Effort)
        InputRequest serviceRequest = new InputRequest();
        
        // Session
        Object sessionIdObj = requestBody.get("sessionId");
        serviceRequest.setSessionId(sessionIdObj != null ? sessionIdObj.toString() : "unknown-session-" + System.currentTimeMillis());

        // Message
        Message message = new Message();
        Object msgObj = requestBody.get("message");
        if (msgObj instanceof Map) {
            Map<?, ?> msgMap = (Map<?, ?>) msgObj;
            message.setText(msgMap.get("text") != null ? msgMap.get("text").toString() : "");
            message.setSender(msgMap.get("sender") != null ? msgMap.get("sender").toString() : "unknown");
        } else {
            // Fallback if message is just a string or missing
            message.setText("Hello"); 
            message.setSender("unknown");
        }
        serviceRequest.setMessage(message);
        serviceRequest.setConversationHistory(Collections.emptyList());
        serviceRequest.setMetadata(Collections.emptyMap());

        // 4. Call Service Logic
        // We ignore the ApiResponse object's structure and just take the reply string
        // to Ensure we strictly match the user's requested output format.
        String replyText = honeyPotService.processRequest(serviceRequest).getReply();

        // 5. Build Strict Response
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("reply", replyText);

        return ResponseEntity.ok(response);
    }
}
