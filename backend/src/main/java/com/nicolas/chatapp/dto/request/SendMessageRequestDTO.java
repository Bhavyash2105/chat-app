package com.nicolas.chatapp.dto.request;

import java.util.UUID;

public record SendMessageRequestDTO(
        UUID chatId,
        String content,
        String iv,
        String ratchetHeader,
        String encryptionFormat
) {}
