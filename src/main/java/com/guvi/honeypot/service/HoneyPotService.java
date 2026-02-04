package com.guvi.honeypot.service;

import com.guvi.honeypot.model.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.*;

@Service
@Slf4j
public class HoneyPotService {

    private final Map<String, SessionData> sessions = new ConcurrentHashMap<>();
    private final RestTemplate restTemplate = new RestTemplate();
    private static final String GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult";

    // Scam keywords
    private static final Set<String> SCAM_KEYWORDS = Set.of("urgent", "verify", "upi", "blocked", "otp", "kyc", "lottery", "prize", "bank");

    // Regex
    private static final Pattern UPI_PATTERN = Pattern.compile("[a-zA-Z0-9.\\-_]{2,256}@[a-zA-Z]{2,64}");
    private static final Pattern PHONE_PATTERN = Pattern.compile("(\\+91[\\-\\s]?)?[6-9]\\d{9}");
    private static final Pattern URL_PATTERN = Pattern.compile("https?://(www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b([-a-zA-Z0-9()@:%_\\+.~#?&//=]*)");

    public ApiResponse processRequest(InputRequest request) {
        String sessionId = request.getSessionId();
        SessionData session = sessions.computeIfAbsent(sessionId, k -> {
            SessionData s = new SessionData();
            s.setSessionId(sessionId);
            return s;
        });

        String incomingText = request.getMessage().getText() != null ? request.getMessage().getText().toLowerCase() : "";
        
        // 1. Detect Scam
        if (!session.isScamDetected()) {
            for (String keyword : SCAM_KEYWORDS) {
                if (incomingText.contains(keyword)) {
                    session.setScamDetected(true);
                    log.info("Scam detected for session: {}", sessionId);
                    break;
                }
            }
        }

        // 2. Extract Intelligence
        extractIntelligence(request.getMessage().getText(), session.getIntelligence());

        // 3. Generate Response
        String responseText;

        if (session.isScamDetected()) {
            responseText = generatePersonaResponse(incomingText, session);
            session.getIntelligence().setTurnCount(session.getIntelligence().getTurnCount() + 1);
            
            // Check if we should report
            // Only report after some engagement or if specific info found
            if (!session.getIntelligence().getUpiIds().isEmpty() 
                    || !session.getIntelligence().getBankAccounts().isEmpty()
                    || session.getIntelligence().getTurnCount() >= 3) {
                sendCallback(session);
            }
        } else {
            responseText = "Hello, who is this? I don't recognize this number.";
        }

        return ApiResponse.builder()
                .status("success")
                .reply(responseText)
                .build();
    }

    private void extractIntelligence(String text, Intelligence intelligence) {
        if (text == null) return;
        
        Matcher upiMatcher = UPI_PATTERN.matcher(text);
        while (upiMatcher.find()) intelligence.getUpiIds().add(upiMatcher.group());

        Matcher phoneMatcher = PHONE_PATTERN.matcher(text);
        while (phoneMatcher.find()) intelligence.getPhoneNumbers().add(phoneMatcher.group());
        
        Matcher urlMatcher = URL_PATTERN.matcher(text);
        while (urlMatcher.find()) intelligence.getUrls().add(urlMatcher.group());
        
        String lowerText = text.toLowerCase();
        for (String keyword : SCAM_KEYWORDS) {
            if (lowerText.contains(keyword)) intelligence.getKeywords().add(keyword);
        }
        
        // Simple heuristic for bank accounts (digits 9-18)
        // This is a naive check, can be improved
        Pattern bankPattern = Pattern.compile("\\b\\d{9,18}\\b");
        Matcher bankMatcher = bankPattern.matcher(text);
        while (bankMatcher.find()) intelligence.getBankAccounts().add(bankMatcher.group());
    }

    private String generatePersonaResponse(String text, SessionData session) {
        // Simple heuristic persona (Naive Indian User)
        if (text.contains("upi") || text.contains("pay") || text.contains("amount")) {
            return "Sir, I am trying to pay 500 rupees but it fails. Google Pay says server error. I am not good with tech sir. What to do?";
        } else if (text.contains("otp") || text.contains("code")) {
            return "I got one SMS with code 5821. Is this the one? I am scared to share sir, is it safe?";
        } else if (text.contains("link") || text.contains("click") || text.contains("website")) {
            return "I clicked the blue link you sent. It opened a page but now it is white screen. My internet is slow maybe?";
        } else if (text.contains("download") || text.contains("app") || text.contains("apk")) {
            return "My phone storage is full sir. Can I do it without downloading app? My grandson usually helps me with this.";
        } else if (text.contains("verify") || text.contains("kyc") || text.contains("blocked")) {
            return "Oh no! Blocked? Please don't block me sir. I have my pension in this account. Please help me fix it immediately.";
        }
        
        List<String> fallbacks = Arrays.asList(
            "Okay sir, I am listening. Please guide me.",
            "I am very worried about this. Please help me.",
            "Sorry sir, network is bad here in village. Can you repeat?",
            "Yes sir, I want to resolve this quickly."
        );
        return fallbacks.get(new Random().nextInt(fallbacks.size()));
    }

    private void sendCallback(SessionData session) {
        new Thread(() -> { // Async callback
            try {
                ExtractedIntelligence extracted = new ExtractedIntelligence();
                extracted.setBankAccounts(new ArrayList<>(session.getIntelligence().getBankAccounts()));
                extracted.setUpiIds(new ArrayList<>(session.getIntelligence().getUpiIds()));
                extracted.setPhishingLinks(new ArrayList<>(session.getIntelligence().getUrls()));
                extracted.setPhoneNumbers(new ArrayList<>(session.getIntelligence().getPhoneNumbers()));
                extracted.setSuspiciousKeywords(new ArrayList<>(session.getIntelligence().getKeywords()));

                CallbackPayload payload = CallbackPayload.builder()
                        .sessionId(session.getSessionId())
                        .scamDetected(session.isScamDetected())
                        .totalMessagesExchanged(session.getIntelligence().getTurnCount())
                        .extractedIntelligence(extracted)
                        .agentNotes("Scam detected based on keywords and engagement. Persona engaged as naive user.")
                        .build();

                restTemplate.postForObject(GUVI_CALLBACK_URL, payload, String.class);
                log.info("Callback sent to GUVI for session: {}", session.getSessionId());
            } catch (Exception e) {
                log.error("Failed to send callback to GUVI: {}", e.getMessage());
            }
        }).start();
    }
}
