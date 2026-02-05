package com.guvi.honeypot.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
public class HoneyPotController {

    private static final String API_KEY = "SECRET123";

    @PostMapping("/honeypot")
    public ResponseEntity<Map<String, Object>> handleHoneypot(
            @RequestHeader(value = "x-api-key", required = false) String apiKey,
            @RequestBody(required = false) Map<String, Object> requestBody) {

        // 1. Strict Authentication
        if (!API_KEY.equals(apiKey)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        // 2. Request Body Handling (Accept ANY valid JSON, do not validate)
        // We do absolutely nothing with the body, as requested.
        // Just ensuring we don't crash if it's null.
        if (requestBody == null) {
            requestBody = new HashMap<>();
        }

        // 3. Prepare Human-like Response
        String replyText = "Hello! I have received your message. I am an AI agent designed to assist you.";

        // 4. Build Strict Response JSON
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("reply", replyText);

        // Required nested message object
        Map<String, String> messageNode = new HashMap<>();
        messageNode.put("text", replyText);
        response.put("message", messageNode);

        return ResponseEntity.ok(response);
    }
}
