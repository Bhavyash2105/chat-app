package com.nicolas.chatapp.repository;

import com.nicolas.chatapp.model.PendingPasswordReset;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface PendingPasswordResetRepository extends JpaRepository<PendingPasswordReset, UUID> {
    Optional<PendingPasswordReset> findByEmail(String email);
    void deleteByEmail(String email);
}
