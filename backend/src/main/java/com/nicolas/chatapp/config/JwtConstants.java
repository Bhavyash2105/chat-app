package com.nicolas.chatapp.config;

import org.springframework.util.StringUtils;

public class JwtConstants {

    private JwtConstants() {
    }

    public static final String TOKEN_HEADER = "Authorization";
    public static final String EMAIL = "email";
    public static final String TOKEN_PREFIX = "Bearer ";
    static final long ACCESS_TOKEN_VALIDITY = 60 * 60 * 1000L;
    static final String ISSUER = "chat-app-backend";
    static final String AUTHORITIES = "authorities";

    /**
     * The HMAC-SHA256 secret used to sign JWT tokens.
     *
     * ALWAYS set this via the {@code JWT_SECRET_KEY} environment variable in production.
     * If it is not set, we "fail fast" at startup in a production profile rather than
     * silently signing tokens with a hardcoded, publicly-known default. This prevents an
     * attacker from forging JWTs.
     */
    static final String SECRET_KEY;

    static {
        String envSecret = System.getenv("JWT_SECRET_KEY");
        if (StringUtils.hasText(envSecret)) {
            SECRET_KEY = envSecret;
        } else if (isProductionProfile()) {
            // Production without a secret is a hard error — never ship with the default.
            throw new IllegalStateException(
                    "JWT_SECRET_KEY environment variable is REQUIRED in production. " +
                    "Generate a strong 256-bit key, e.g.: " +
                    "node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\""
            );
        } else {
            // Local development only — an insecure default is acceptable for the dev loop.
            SECRET_KEY = "local-dev-only-insecure-default-key-do-not-use-in-production-1234567890";
        }
    }

    private static boolean isProductionProfile() {
        String profiles = System.getenv("SPRING_PROFILES_ACTIVE");
        return profiles != null && profiles.contains("prod");
    }
}
