package com.guvi.honeypot.model;

import lombok.Data;
import java.util.List;

@Data
public class ExtractedIntelligence {
    private List<String> bankAccounts;
    private List<String> upiIds;
    private List<String> phishingLinks;
    private List<String> phoneNumbers;
    private List<String> suspiciousKeywords;
}
