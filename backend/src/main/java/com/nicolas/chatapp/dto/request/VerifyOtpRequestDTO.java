package com.nicolas.chatapp.dto.request;

public record VerifyOtpRequestDTO(String email, String otpCode) {
}