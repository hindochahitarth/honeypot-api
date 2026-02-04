package com.guvi.honeypot.controller;

import com.guvi.honeypot.model.ApiResponse;
import com.guvi.honeypot.model.InputRequest;
import com.guvi.honeypot.service.HoneyPotService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class HoneyPotController {

    private final HoneyPotService honeyPotService;
    private static final String API_KEY = "SECRET123";

    public HoneyPotController(HoneyPotService honeyPotService) {
        this.honeyPotService = honeyPotService;
    }

    @PostMapping("/honeypot")
    public ResponseEntity<ApiResponse> handleHoneypot(
            @RequestHeader(value = "x-api-key", required = false) String apiKey,
            @RequestBody InputRequest request) {
        
        if (!API_KEY.equals(apiKey)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        if (request.getSessionId() == null || request.getMessage() == null) {
            return ResponseEntity.badRequest().build();
        }

        ApiResponse response = honeyPotService.processRequest(request);
        return ResponseEntity.ok(response);
    }
}
