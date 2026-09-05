package com.nicolas.chatapp.service.implementation;

import com.nicolas.chatapp.config.JwtConstants;
import com.nicolas.chatapp.config.TokenProvider;
import com.nicolas.chatapp.dto.request.PreKeyBundleRequestDTO;
import com.nicolas.chatapp.dto.request.UpdateUserRequestDTO;
import com.nicolas.chatapp.exception.UserException;
import com.nicolas.chatapp.model.PreKeyBundle;
import com.nicolas.chatapp.model.User;
import com.nicolas.chatapp.repository.PreKeyBundleRepository;
import com.nicolas.chatapp.repository.UserRepository;
import com.nicolas.chatapp.service.UserService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

private final UserRepository userRepository;
    private final PreKeyBundleRepository preKeyBundleRepository;
    private final TokenProvider tokenProvider;

    @Override
    public User findUserById(UUID id) throws UserException {

        Optional<User> user = userRepository.findById(id);

        if (user.isPresent()) {
            return user.get();
        }

        throw new UserException("User not found with id " + id);
    }

    @Override
    public User findUserByProfile(String jwt) throws UserException {

        String email = String.valueOf(tokenProvider.getClaimsFromToken(jwt).get(JwtConstants.EMAIL));

        if (email == null) {
            throw new BadCredentialsException("Invalid token");
        }

        Optional<User> user = userRepository.findByEmail(email);

        if (user.isPresent()) {
            return user.get();
        }

        throw new UserException("User not found with email " + email);
    }

    @Override
    public User updateUser(UUID id, UpdateUserRequestDTO request) throws UserException {

        User user = findUserById(id);

        if (Objects.nonNull(request.fullName())) {
            user.setFullName(request.fullName());
        }

        return userRepository.save(user);
    }

    @Override
    public List<User> searchUser(String query) {
        return userRepository.findByFullNameOrEmail(query).stream()
                .sorted(Comparator.comparing(User::getFullName))
                .toList();
    }

    @Override
    public List<User> searchUserByName(String name) {
        return userRepository.findByFullName(name).stream()
                .sorted(Comparator.comparing(User::getFullName))
                .toList();
    }

// ──────────────────────────────────────────────────────────────
    // Pre-Key Bundle (X3DH / Double Ratchet)
    // ──────────────────────────────────────────────────────────────

    @Override
    @Transactional
    public void updatePreKeyBundle(UUID userId, PreKeyBundleRequestDTO request) throws UserException {
        findUserById(userId); // validates user exists

        PreKeyBundle bundle = preKeyBundleRepository.findById(userId)
                .map(existing -> {
                    existing.setIdentityKey(request.identityKey());
                    existing.setSignedPreKey(request.signedPreKey());
                    existing.setSignedPreKeySignature(request.signedPreKeySignature());
                    existing.setSignedPreKeyId(request.signedPreKeyId());
                    existing.setOneTimePreKeys(request.oneTimePreKeys());
                    return existing;
                })
                .orElseGet(() -> PreKeyBundle.builder()
                        .userId(userId)
                        .identityKey(request.identityKey())
                        .signedPreKey(request.signedPreKey())
                        .signedPreKeySignature(request.signedPreKeySignature())
                        .signedPreKeyId(request.signedPreKeyId())
                        .oneTimePreKeys(request.oneTimePreKeys())
                        .updatedAt(LocalDateTime.now())
                        .build());

        preKeyBundleRepository.save(bundle);
        log.info("Pre-key bundle updated for user: {}", userId);
    }

    @Override
    public Optional<PreKeyBundle> getPreKeyBundle(UUID userId) throws UserException {
        findUserById(userId); // validates user exists
        return preKeyBundleRepository.findById(userId);
    }

@Override
    @Transactional
    public Optional<String> consumeOneTimePreKeyAtomic(UUID userId) throws UserException {
        findUserById(userId); // validates user exists

        // Pessimistic write lock on the bundle row: concurrent consumers of the
        // same user's one-time pre-key pool serialize here until we commit.
        Optional<PreKeyBundle> locked = preKeyBundleRepository.findByIdForUpdate(userId);

        if (locked.isEmpty()) {
            log.warn("No pre-key bundle found for user: {}", userId);
            return Optional.empty();
        }

        PreKeyBundle bundle = locked.get();

        ObjectMapper mapper = new ObjectMapper();
        try {
            List<Map<String, Object>> otpks = mapper.readValue(
                    bundle.getOneTimePreKeys(),
                    new TypeReference<List<Map<String, Object>>>() {}
            );

            if (otpks.isEmpty()) {
                log.warn("No one-time pre-keys available for user: {}", userId);
                return Optional.empty();
            }

            // Pop the last one-time pre-key.
            Map<String, Object> consumedOtpk = otpks.remove(otpks.size() - 1);
            bundle.setOneTimePreKeys(mapper.writeValueAsString(otpks));
            preKeyBundleRepository.save(bundle);

            String consumedJson = mapper.writeValueAsString(consumedOtpk);
            log.info("One-time pre-key consumed for user: {}", userId);
            return Optional.of(consumedJson);
        } catch (JsonProcessingException e) {
            log.error("Failed to parse/serialize one-time pre-keys for user: {}", userId, e);
            throw new UserException("Failed to consume one-time pre-key: " + e.getMessage());
        }
    }

}

