package com.nicolas.chatapp.controllers;

import com.nicolas.chatapp.config.JwtConstants;
import com.nicolas.chatapp.dto.request.RecoveryBlobRequestDTO;
import com.nicolas.chatapp.exception.UserException;
import com.nicolas.chatapp.model.RecoveryBlob;
import com.nicolas.chatapp.service.RecoveryService;
import com.nicolas.chatapp.service.UserService;
import com.nicolas.chatapp.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@Slf4j
@RestController
@RequestMapping("/api/recovery")
@RequiredArgsConstructor
public class RecoveryController {

    private final RecoveryService recoveryService;
    private final UserService userService;

    @PutMapping("/blob")
    public ResponseEntity<Void> saveRecoveryBlob(
            @RequestBody RecoveryBlobRequestDTO request,
            @RequestHeader(JwtConstants.TOKEN_HEADER) String jwt) throws UserException {

        User user = userService.findUserByProfile(jwt);
        recoveryService.saveRecoveryBlob(user.getId(), request);
        log.info("Recovery blob saved for user: {}", user.getEmail());

        return new ResponseEntity<>(HttpStatus.OK);
    }

    @GetMapping("/blob")
    public ResponseEntity<RecoveryBlobResponse> getRecoveryBlob(
            @RequestHeader(JwtConstants.TOKEN_HEADER) String jwt) throws UserException {

        User user = userService.findUserByProfile(jwt);
        Optional<RecoveryBlob> blob = recoveryService.getRecoveryBlob(user.getId());

        return blob.map(b -> {
            RecoveryBlobResponse resp = new RecoveryBlobResponse(
                    b.getEncryptedData(),
                    b.getIv(),
                    b.getSalt()
            );
            return new ResponseEntity<>(resp, HttpStatus.OK);
        }).orElseGet(() -> new ResponseEntity<>(HttpStatus.NO_CONTENT));
    }

    private record RecoveryBlobResponse(String encryptedData, String iv, String salt) {}
}

