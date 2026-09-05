package com.nicolas.chatapp.service.implementation;

import com.nicolas.chatapp.dto.request.RecoveryBlobRequestDTO;
import com.nicolas.chatapp.exception.UserException;
import com.nicolas.chatapp.model.RecoveryBlob;
import com.nicolas.chatapp.repository.RecoveryBlobRepository;
import com.nicolas.chatapp.service.RecoveryService;
import com.nicolas.chatapp.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class RecoveryServiceImpl implements RecoveryService {

    private final RecoveryBlobRepository recoveryBlobRepository;
    private final UserService userService;

    @Override
    public void saveRecoveryBlob(UUID userId, RecoveryBlobRequestDTO request) throws UserException {
        userService.findUserById(userId); // validates user exists

        RecoveryBlob blob = recoveryBlobRepository.findById(userId)
                .map(existing -> {
                    existing.setEncryptedData(request.encryptedData());
                    existing.setIv(request.iv());
                    existing.setSalt(request.salt());
                    existing.setUpdatedAt(LocalDateTime.now());
                    return existing;
                })
                .orElseGet(() -> RecoveryBlob.builder()
                        .userId(userId)
                        .encryptedData(request.encryptedData())
                        .iv(request.iv())
                        .salt(request.salt())
                        .createdAt(LocalDateTime.now())
                        .updatedAt(LocalDateTime.now())
                        .build());

        recoveryBlobRepository.save(blob);
        log.info("Recovery blob saved for user: {}", userId);
    }

    @Override
    public Optional<RecoveryBlob> getRecoveryBlob(UUID userId) throws UserException {
        userService.findUserById(userId); // validates user exists
        return recoveryBlobRepository.findById(userId);
    }
}

