package com.guvi.honeypot.model;

import lombok.Data;
import java.util.HashSet;
import java.util.Set;

@Data
public class Intelligence {
    private Set<String> upiIds = new HashSet<>();
    private Set<String> phoneNumbers = new HashSet<>();
    private Set<String> urls = new HashSet<>();
    private Set<String> keywords = new HashSet<>();
    private Set<String> bankAccounts = new HashSet<>();
    private int turnCount = 0;
}
