package com.nicolas.chatapp.dto.request;

import java.util.UUID;

/**
 * Request to atomically consume one one-time pre-key for session initiation.
 * The consumed key is returned in the response.
 */
public record PreKeyConsumeRequestDTO(UUID senderUserId) {}

