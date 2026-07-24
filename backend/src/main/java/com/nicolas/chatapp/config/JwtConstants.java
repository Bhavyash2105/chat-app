package com.nicolas.chatapp.config;

public class JwtConstants {

    private JwtConstants() {
    }

    public static final String TOKEN_HEADER = "Authorization";
    public static final String EMAIL = "email";
    public static final String TOKEN_PREFIX = "Bearer ";
    static final long ACCESS_TOKEN_VALIDITY = 60 * 60 * 1000L;
    static final String ISSUER = "chat-app-backend";
    static final String AUTHORITIES = "authorities";
    static final String SECRET_KEY = System.getenv().getOrDefault(
            "JWT_SECRET_KEY",
            "local-dev-only-insecure-default-key-do-not-use-in-production-1234567890"
    );
}