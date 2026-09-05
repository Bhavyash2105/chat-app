package com.nicolas.chatapp.repository;

import com.nicolas.chatapp.model.RecoveryBlob;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface RecoveryBlobRepository extends JpaRepository<RecoveryBlob, UUID> {
}

