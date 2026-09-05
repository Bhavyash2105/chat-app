package com.nicolas.chatapp.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

@Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry.addEndpoint("/ws")
                .setAllowedOriginPatterns(allowedOrigins())
                .withSockJS();
    }

    /**
     * Read the allowed WebSocket origins from the {@code CORS_ALLOWED_ORIGINS} environment
     * variable (comma-separated). Defaults to the local dev origin.
     *
     * In production, set this to exactly your frontend domain(s), e.g.:
     * {@code CORS_ALLOWED_ORIGINS=https://your-app.vercel.app,http://localhost:3000}
     */
    private static String[] allowedOrigins() {
        String env = System.getenv("CORS_ALLOWED_ORIGINS");
        if (env != null && !env.isBlank()) {
            return java.util.Arrays.stream(env.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .toArray(String[]::new);
        }
        return new String[]{"http://localhost:3000"};
    }

    @Override
    public void configureMessageBroker(MessageBrokerRegistry registry) {
        registry.enableSimpleBroker("/topic/");
        registry.setApplicationDestinationPrefixes("/app");
    }

}
