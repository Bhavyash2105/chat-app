package com.nicolas.chatapp.dto.request;

public record ResetPasswordRequestDTO(String email, String otpCode, String newPassword) {
}
