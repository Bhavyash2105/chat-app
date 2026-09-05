package com.nicolas.chatapp.service;

import com.nicolas.chatapp.dto.request.PreKeyBundleRequestDTO;
import com.nicolas.chatapp.dto.request.UpdateUserRequestDTO;
import com.nicolas.chatapp.exception.UserException;
import com.nicolas.chatapp.model.PreKeyBundle;
import com.nicolas.chatapp.model.User;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface UserService {

    User findUserById(UUID id) throws UserException;

    User findUserByProfile(String jwt) throws UserException;

    User updateUser(UUID id, UpdateUserRequestDTO request) throws UserException;

    List<User> searchUser(String query);

List<User> searchUserByName(String name);

    // ---- Pre-key bundle (X3DH / Double Ratchet) ----

    /**
     * Save or replace the user's X3DH pre-key bundle.
     * Replaces the previous bundle entirely (old one-time keys discarded).
     */
    void updatePreKeyBundle(UUID userId, PreKeyBundleRequestDTO request) throws UserException;

    /**
     * Fetch the user's current pre-key bundle for session initiation.
     * Returns empty if no bundle has been uploaded yet.
     */
    Optional<PreKeyBundle> getPreKeyBundle(UUID userId) throws UserException;

    /**
     * Atomically consume one one-time pre-key from the user's pool.
     * Returns the consumed key as a JSON object string {"id":..., "key":"..."},
     * or empty if no one-time pre-keys remain.
     *
     * Uses PostgreSQL CTE + FOR UPDATE for atomicity.
     */
    Optional<String> consumeOneTimePreKeyAtomic(UUID userId) throws UserException;

}

