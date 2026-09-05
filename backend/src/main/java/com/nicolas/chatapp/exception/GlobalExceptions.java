package com.nicolas.chatapp.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.NoHandlerFoundException;

import java.time.LocalDateTime;
import java.util.Objects;

@Slf4j
@RestControllerAdvice
public class GlobalExceptions {

    @ExceptionHandler(UserException.class)
    public ResponseEntity<ErrorDetails> userExceptionHandler(UserException e, WebRequest request) {
        log.warn("UserException: {} (request={})", e.getMessage(), request.getDescription(false));
        ErrorDetails error = new ErrorDetails(e.getMessage(), request.getDescription(false),
                LocalDateTime.now());

        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(MessageException.class)
    public ResponseEntity<ErrorDetails> messageExceptionHandler(MessageException e, WebRequest request) {
        log.warn("MessageException: {} (request={})", e.getMessage(), request.getDescription(false));
        ErrorDetails error = new ErrorDetails(e.getMessage(), request.getDescription(false),
                LocalDateTime.now());

        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(ChatException.class)
    public ResponseEntity<ErrorDetails> chatExceptionHandler(ChatException e, WebRequest request) {
        log.warn("ChatException: {} (request={})", e.getMessage(), request.getDescription(false));
        ErrorDetails error = new ErrorDetails(e.getMessage(), request.getDescription(false),
                LocalDateTime.now());

        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorDetails> methodArgumentNotValidExceptionHandler(MethodArgumentNotValidException e, WebRequest request) {
        log.warn("MethodArgumentNotValidException: {}", e.getMessage());
        String err = Objects.requireNonNull(e.getBindingResult().getFieldError()).getDefaultMessage();
        ErrorDetails error = new ErrorDetails(e.getMessage(), err,
                LocalDateTime.now());

        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<ErrorDetails> noHandlerFoundExceptionHandler(NoHandlerFoundException e, WebRequest request) {
        log.warn("NoHandlerFoundException: {}", e.getMessage());
        ErrorDetails error = new ErrorDetails("No handler available for this endpoint", e.getMessage(),
                LocalDateTime.now());

        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorDetails> exceptionHandler(Exception e, WebRequest request) {
        // This catches DB connection errors, Hikari pool failures, and any unexpected
        // exception. Log the full stack trace so the actual root cause is visible.
        log.error("Unhandled exception on request {}: {}", request.getDescription(false), e.getMessage(), e);
        ErrorDetails error=new ErrorDetails(e.getMessage(),request.getDescription(false), LocalDateTime.now());
        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }

}
