package com.nicolas.chatapp.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nicolas.chatapp.model.Message;
import com.nicolas.chatapp.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Controller;

import java.util.Map;

@Slf4j
@Controller
@RequiredArgsConstructor
public class RealtimeChatController {

    private final SimpMessagingTemplate messagingTemplate;
    private final ObjectMapper objectMapper;

    /**
     * Broadcast a sent message to every member of the chat.
     *
     * The client sends the stored message together with a {@code perRecipientContent}
     * map keyed by user UUID. Each map value is {@code {content, iv, ratchetHeader}}
     * — the ciphertext encrypted specifically for that recipient. Because the DB
     * stores only the sender's own copy, we deliver each member their own ciphertext
     * so every recipient (including group members) can decrypt it.
     *
     * If {@code perRecipientContent} is absent, we fall back to broadcasting the
     * message as-is (legacy behavior).
     */
    @MessageMapping("/messages")
    public void receiveMessage(@Payload Map<String, Object> payload) {
        try {
            Message message = objectMapper.convertValue(payload.get("message"), Message.class);
            @SuppressWarnings("unchecked")
            Map<String, Object> perRecipient = (Map<String, Object>) payload.get("perRecipientContent");

for (User user : message.getChat().getUsers()) {
                final String destination = "/topic/" + user.getId();
                final String userId = user.getId().toString();

                Object delivered = message;
                boolean gotOwnCopy = false;
                if (perRecipient != null && perRecipient.containsKey(userId)) {
                    // Send the recipient their own encrypted copy.
                    Map<String, Object> recipientCopy = new java.util.HashMap<>(messagePayload(message));
                    recipientCopy.putAll((Map<String, Object>) perRecipient.get(userId));
                    delivered = recipientCopy;
                    gotOwnCopy = true;
                } else {
                    // No per-recipient copy for this user — send the stored message.
                    delivered = messagePayload(message);
                }

                // Log whether each recipient got their own per-recipient ciphertext
                // (the key to successful decryption) or the stored sender's copy.
                long contentLen = -1;
                long headerLen = -1;
                String encFormat = null;
                if (delivered instanceof Map<?, ?> m) {
                    Object c = m.get("content");
                    Object h = m.get("ratchetHeader");
                    Object f = m.get("encryptionFormat");
                    contentLen = c instanceof String s ? s.length() : -1;
                    headerLen = h instanceof String s ? s.length() : -1;
                    encFormat = f instanceof String s ? s : null;
                }
                log.info("[RealtimeChat] -> userId={} gotOwnCopy={} contentLen={} headerLen={} encryptionFormat={} appKeyCount={}",
                        userId, gotOwnCopy, contentLen, headerLen, encFormat,
                        perRecipient == null ? 0 : perRecipient.size());
                messagingTemplate.convertAndSend(destination, delivered);
            }
        } catch (Exception e) {
            System.err.println("[RealtimeChat] Failed to broadcast message: " + e.getMessage());
        }
    }

    private Map<String, Object> messagePayload(Message message) {
        return new java.util.HashMap<>(objectMapper.convertValue(message, Map.class));
    }

}
