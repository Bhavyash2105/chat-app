package com.nicolas.chatapp.dto.request;

/**
 * DTO for uploading an X3DH pre-key bundle.
 *
 * All keys are base64-encoded Curve25519 public keys.
 * oneTimePreKeys is a JSON array: [{"id":1,"key":"base64..."}, ...]
 */
public record PreKeyBundleRequestDTO(
        String identityKey,
        String signedPreKey,
        String signedPreKeySignature,
        int signedPreKeyId,
        String oneTimePreKeys
) {}

