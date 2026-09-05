package com.nicolas.chatapp.service;

import com.nicolas.chatapp.dto.request.RecoveryBlobRequestDTO;
import com.nicolas.chatapp.exception.UserException;
import com.nicolas.chatapp.model.RecoveryBlob;

import java.util.Optional;
import java.util.UUID;

public interface RecoveryService {

    void saveRecoveryBlob(UUID userId, RecoveryBlobRequestDTO request) throws UserException;

    Optional<RecoveryBlob> getRecoveryBlob(UUID userId) throws UserException;

}

