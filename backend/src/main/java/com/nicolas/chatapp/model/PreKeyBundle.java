package com.nicolas.chatapp.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * X3DH pre-key bundle for Signal Protocol session initiation.
 *
 * Each user publishes one bundle containing:
 *   - identityKey:       Curve25519 long-term identity public key (base64)
 *   - signedPreKey:      Medium-term Curve25519 public key (base64)
 *   - signedPreKeySignature: Signature of signedPreKey by identityKey (base64)
 *   - signedPreKeyId:    Numeric ID for the signed pre-key
 *   - oneTimePreKeys:    JSON array of {id, key} objects — single-use pre-keys (base64)
 *
 * When the one-time pre-key pool runs low, the client uploads a fresh batch.
 * The last element is consumed atomically via a CTE + FOR UPDATE query.
 */
@Getter
@Setter
@Entity
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "pre_key_bundle")
public class PreKeyBundle {

    @Id
    private UUID userId;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String identityKey;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String signedPreKey;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String signedPreKeySignature;

    @Column(nullable = false)
    private int signedPreKeyId;

    /**
     * JSON array of one-time pre-key objects.
     * Example: [{"id":1,"key":"base64..."}, {"id":2,"key":"base64..."}]
     * Stored as TEXT in PostgreSQL (application-level JSON parsing).
     */
    @Column(nullable = false, columnDefinition = "TEXT")
    private String oneTimePreKeys;

    @Column(nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }
}

