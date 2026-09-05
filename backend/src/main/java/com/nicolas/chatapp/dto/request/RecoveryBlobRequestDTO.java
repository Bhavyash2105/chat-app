package com.nicolas.chatapp.dto.request;

public record RecoveryBlobRequestDTO(
        String encryptedData,
        String iv,
        String salt
) {
}

