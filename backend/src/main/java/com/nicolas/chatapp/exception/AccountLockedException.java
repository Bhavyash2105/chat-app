package com.nicolas.chatapp.exception;

import lombok.Getter;

@Getter
public class AccountLockedException extends RuntimeException {
    private final long remainingMinutes;

    public AccountLockedException(long remainingMinutes) {
        super("Account locked for " + remainingMinutes + " more minute(s)");
        this.remainingMinutes = remainingMinutes;
    }
}

