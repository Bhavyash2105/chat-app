package com.nicolas.chatapp.dto.request;

public record DecryptFailureLogDTO(
        String userId,
        String chatId,
        String messageId,
        String failureReason,
        String timestamp
) {
}

