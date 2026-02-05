package com.guvi.honeypot.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.guvi.honeypot.model.ApiResponse;
import com.guvi.honeypot.model.InputRequest;
import com.guvi.honeypot.model.Message;
import com.guvi.honeypot.service.HoneyPotService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
@Slf4j
public class HoneyPotController {

    private static final String API_KEY = "SECRET123";

    @Autowired
    private HoneyPotService honeyPotService;

    @Autowired
    private ObjectMapper objectMapper;

    @PostMapping("/honeypot")
    public ResponseEntity<ApiResponse> handleHoneypot(
            @RequestHeader(value = "x-api-key", required = false) String apiKey,
            @RequestBody(required = false) Map<String, Object> requestBody) {

        // 1. Strict Authentication
        if (!API_KEY.equals(apiKey)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        // 2. Request Body Handling (Accept ANY valid JSON)
        if (requestBody == null) {
            requestBody = new HashMap<>();
        }

        // Convert permissive Map to typed InputRequest for internal logic
        InputRequest request;
        try {
            request = objectMapper.convertValue(requestBody, InputRequest.class);
        } catch (IllegalArgumentException e) {
            // If conversion fails, create a safe empty request to avoid 400
            request = new InputRequest();
            request.setSessionId(UUID.randomUUID().toString()); // safe fallback
        }

        // Ensure nested objects are not null to prevent NPEs in service
        if (request.getMessage() == null) {
            request.setMessage(new Message());
        }
        
        // Ensure sessionId exists (critical for ConcurrentHashMap)
        if (request.getSessionId() == null || request.getSessionId().isEmpty()) {
            request.setSessionId(UUID.randomUUID().toString());
        }

        // 3. Process Logic
        ApiResponse response = honeyPotService.processRequest(request);

        return ResponseEntity.ok(response);
    }
}
