package com.nicolas.chatapp.controllers;

import com.nicolas.chatapp.config.JwtConstants;
import com.nicolas.chatapp.dto.request.PreKeyBundleRequestDTO;
import com.nicolas.chatapp.dto.request.PreKeyConsumeRequestDTO;
import com.nicolas.chatapp.dto.request.UpdateUserRequestDTO;
import com.nicolas.chatapp.dto.response.ApiResponseDTO;
import com.nicolas.chatapp.dto.response.UserDTO;
import com.nicolas.chatapp.exception.UserException;
import com.nicolas.chatapp.model.PreKeyBundle;
import com.nicolas.chatapp.model.User;
import com.nicolas.chatapp.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/profile")
    public ResponseEntity<UserDTO> getUserProfile(@RequestHeader(JwtConstants.TOKEN_HEADER) String token) throws UserException {

        User user = userService.findUserByProfile(token);

        return new ResponseEntity<>(UserDTO.fromUser(user), HttpStatus.OK);
    }

    @GetMapping("/{query}")
    public ResponseEntity<List<UserDTO>> searchUsers(@PathVariable String query) {

        List<User> users = userService.searchUser(query);

        return new ResponseEntity<>(UserDTO.fromUsersAsList(users), HttpStatus.OK);
    }

    @GetMapping("/search")
    public ResponseEntity<Set<UserDTO>> searchUsersByName(@RequestParam("name") String name) {

        List<User> users = userService.searchUserByName(name);

        return new ResponseEntity<>(UserDTO.fromUsers(users), HttpStatus.OK);
    }

    @PutMapping("/update")
    public ResponseEntity<ApiResponseDTO> updateUser(@RequestBody UpdateUserRequestDTO request,
                                                     @RequestHeader(JwtConstants.TOKEN_HEADER) String token)
            throws UserException {

        User user = userService.findUserByProfile(token);
        user = userService.updateUser(user.getId(), request);
        log.info("User updated: {}", user.getEmail());

        ApiResponseDTO response = ApiResponseDTO.builder()
                .message("User updated")
                .status(true)
                .build();

        return new ResponseEntity<>(response, HttpStatus.OK);
    }

// ──────────────────────────────────────────────────────────────
    // Pre-Key Bundle Endpoints (X3DH / Double Ratchet)
    // ──────────────────────────────────────────────────────────────

    /**
     * Upload or replace the current user's X3DH pre-key bundle.
     * Called after signup and periodically when one-time pre-keys run low.
     */
    @PutMapping("/pre-key-bundle")
    public ResponseEntity<ApiResponseDTO> updatePreKeyBundle(
            @RequestBody PreKeyBundleRequestDTO request,
            @RequestHeader(JwtConstants.TOKEN_HEADER) String token) throws UserException {

        User user = userService.findUserByProfile(token);
        userService.updatePreKeyBundle(user.getId(), request);
        log.info("Pre-key bundle uploaded for user: {}", user.getEmail());

        ApiResponseDTO response = ApiResponseDTO.builder()
                .message("Pre-key bundle updated")
                .status(true)
                .build();

        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    /**
     * Fetch a user's pre-key bundle to initiate an X3DH session.
     * Returns the bundle including one-time pre-keys, or 204 No Content if none exists.
     */
    @GetMapping("/{userId}/pre-key-bundle")
    public ResponseEntity<PreKeyBundleResponse> getPreKeyBundle(@PathVariable UUID userId) throws UserException {

        Optional<PreKeyBundle> bundle = userService.getPreKeyBundle(userId);

        return bundle.map(b -> {
            PreKeyBundleResponse resp = new PreKeyBundleResponse(
                    b.getIdentityKey(),
                    b.getSignedPreKey(),
                    b.getSignedPreKeySignature(),
                    b.getSignedPreKeyId(),
                    b.getOneTimePreKeys()
            );
            return new ResponseEntity<>(resp, HttpStatus.OK);
        }).orElseGet(() -> new ResponseEntity<>(HttpStatus.NO_CONTENT));
    }

    /**
     * Atomically consume one one-time pre-key from the target user's pool.
     * Used during X3DH session initiation.
     *
     * POST body includes the sender's userId (for audit logging).
     * Response contains the consumed key as a JSON string {"id":..., "key":"..."},
     * or 204 No Content if no one-time pre-keys remain.
     */
    @PostMapping("/pre-key-bundle/consume")
    public ResponseEntity<String> consumeOneTimePreKey(
            @RequestBody PreKeyConsumeRequestDTO request,
            @RequestHeader(JwtConstants.TOKEN_HEADER) String token) throws UserException {

        User requester = userService.findUserByProfile(token);
        Optional<String> consumed = userService.consumeOneTimePreKeyAtomic(request.senderUserId());

        log.info("User {} consumed one-time pre-key for user {}",
                requester.getId(), request.senderUserId());

        return consumed.map(key -> new ResponseEntity<>(key, HttpStatus.OK))
                .orElseGet(() -> new ResponseEntity<>(HttpStatus.NO_CONTENT));
    }

    /**
     * Internal response DTO for the pre-key bundle.
     * Excludes updatedAt and other internal fields.
     */
    private record PreKeyBundleResponse(
            String identityKey,
            String signedPreKey,
            String signedPreKeySignature,
            int signedPreKeyId,
            String oneTimePreKeys
    ) {}
}

