package com.guvi.honeypot.model;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ApiResponse {
    private String status;
    private String reply;
}
