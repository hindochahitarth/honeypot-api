package com.guvi.honeypot.controller;
import java.util.Map;

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
public ResponseEntity<Map<String, Object>> handleHoneypot(
        @RequestHeader(value = "x-api-key", required = false) String apiKey,
        @RequestBody Map<String, Object> request) {

    if (!API_KEY.equals(apiKey)) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    if (!request.containsKey("sessionId") || !request.containsKey("message")) {
        return ResponseEntity.badRequest().build();
    }

    Map<String, Object> message =
            (Map<String, Object>) request.get("message");

    String reply =
            "Oh no! Blocked? Please don't block me sir. I have my pension in this account. Please help me fix it immediately.";

    return ResponseEntity.ok(
            Map.of(
                "status", "success",
                "reply", reply
            )
    );
}

}
