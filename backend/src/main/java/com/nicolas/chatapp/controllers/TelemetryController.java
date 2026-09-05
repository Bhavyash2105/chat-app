package com.nicolas.chatapp.controllers;

import com.nicolas.chatapp.dto.request.DecryptFailureLogDTO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/telemetry")
public class TelemetryController {

    @PostMapping("/decrypt-failure")
    public ResponseEntity<Void> logDecryptFailure(@RequestBody DecryptFailureLogDTO event) {
        log.warn(
                "DECRYPT_FAILURE | userId={} | chatId={} | messageId={} | reason={} | timestamp={}",
                event.userId(),
                event.chatId(),
                event.messageId(),
                event.failureReason(),
                event.timestamp()
        );
        return new ResponseEntity<>(HttpStatus.ACCEPTED);
    }
}

