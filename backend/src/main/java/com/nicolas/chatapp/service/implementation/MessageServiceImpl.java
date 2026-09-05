package com.nicolas.chatapp.service.implementation;

import com.nicolas.chatapp.dto.request.SendMessageRequestDTO;
import com.nicolas.chatapp.exception.ChatException;
import com.nicolas.chatapp.exception.MessageException;
import com.nicolas.chatapp.exception.UserException;
import com.nicolas.chatapp.model.Chat;
import com.nicolas.chatapp.model.Message;
import com.nicolas.chatapp.model.User;
import com.nicolas.chatapp.repository.MessageRepository;
import com.nicolas.chatapp.service.ChatService;
import com.nicolas.chatapp.service.MessageService;
import com.nicolas.chatapp.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class MessageServiceImpl implements MessageService {

    private final UserService userService;
    private final ChatService chatService;
    private final MessageRepository messageRepository;

    @Override
    public Message sendMessage(SendMessageRequestDTO req, UUID userId) throws UserException, ChatException {

        log.info("[sendMessage] START for userId={}, chatId={}, encryptionFormat={}, contentLength={}, ivLength={}, ratchetHeaderLength={}",
                userId, req.chatId(), req.encryptionFormat(),
                req.content() == null ? 0 : req.content().length(),
                req.iv() == null ? 0 : req.iv().length(),
                req.ratchetHeader() == null ? 0 : req.ratchetHeader().length());

        User user = userService.findUserById(userId);
        Chat chat = chatService.findChatById(req.chatId());

        String encryptionFormat = req.encryptionFormat();
        boolean isRatchet = "ratchet".equals(encryptionFormat);
        boolean isEncrypted = isRatchet;

        Message.MessageBuilder builder = Message.builder()
                .chat(chat)
                .user(user)
                .content(req.content())
                .timeStamp(LocalDateTime.now())
                .readBy(new HashSet<>(Set.of(user.getId())))
                .isEncrypted(isEncrypted)
                .encryptionFormat(isRatchet ? "ratchet" : null);

        if (!isRatchet) {
            throw new ChatException("ratchetHeader is required when encryptionFormat is 'ratchet'");
        }

        if (req.ratchetHeader() == null || req.ratchetHeader().isBlank()) {
            throw new ChatException("ratchetHeader is required when encryptionFormat is 'ratchet'");
        }

builder.ratchetHeader(req.ratchetHeader());
        builder.iv(req.iv());

        // Defensive: strip NUL bytes (0x00) from all text fields before persistence.
        // PostgreSQL forbids 0x00 in TEXT/VARCHAR columns — if the client ever sends
        // raw binary ciphertext (shouldn't happen after the base64 fix), this prevents
        // the insert from failing and the message from silently disappearing.
        String safeContent = req.content() == null ? null : req.content().replace("\u0000", "");
        String safeHeader = req.ratchetHeader() == null ? null : req.ratchetHeader().replace("\u0000", "");
        String safeIv = req.iv() == null ? null : req.iv().replace("\u0000", "");

        if (req.content() != null && safeContent != null && !safeContent.equals(req.content())) {
            log.warn("[sendMessage] NUL bytes stripped from content (length {} -> {})", req.content().length(), safeContent.length());
        }
        if (!safeHeader.equals(req.ratchetHeader())) {
            log.warn("[sendMessage] NUL bytes stripped from ratchetHeader (length {} -> {})", req.ratchetHeader().length(), safeHeader.length());
        }

        // Detect if content is NOT valid base64 (i.e. contains raw binary). Log loudly.
        if (req.content() != null && !isBase64(safeContent)) {
            log.error("[sendMessage] content is NOT valid base64 — ciphertext is likely raw binary! contentLength={}", safeContent.length());
        }

        Message.MessageBuilder safeBuilder = Message.builder()
                .chat(chat)
                .user(user)
                .content(safeContent)
                .timeStamp(LocalDateTime.now())
                .readBy(new HashSet<>(Set.of(user.getId())))
                .isEncrypted(isRatchet)
                .encryptionFormat(isRatchet ? "ratchet" : null)
                .ratchetHeader(safeHeader)
                .iv(safeIv);

        Message message = safeBuilder.build();
        chat.getMessages().add(message);

        Message saved;
        try {
            saved = messageRepository.save(message);
            log.info("[sendMessage] SAVED message id={} for userId={}, chatId={}", saved.getId(), userId, req.chatId());
        } catch (Exception e) {
            log.error("[sendMessage] SAVE FAILED for userId={}, chatId={}: {}", userId, req.chatId(), e.getMessage());
            throw e;
        }
        return saved;
    }

    /**
     * Heuristic check: base64 strings only contain [A-Za-z0-9+/=] and are a multiple of 4 chunks.
     */
    private boolean isBase64(String s) {
        if (s == null || s.isEmpty()) return true;
        if (s.length() % 4 != 0) return false;
        return s.matches("^[A-Za-z0-9+/]*={0,2}$");
    }

    @Override
    public List<Message> getChatMessages(UUID chatId, User reqUser) throws UserException, ChatException {

        Chat chat = chatService.findChatById(chatId);

        if (!chat.getUsers().contains(reqUser)) {
            throw new UserException("User isn't related to chat " + chatId);
        }

        return messageRepository.findByChat_Id(chat.getId());
    }

    @Override
    public Message findMessageById(UUID messageId) throws MessageException {

        Optional<Message> message = messageRepository.findById(messageId);

        if (message.isPresent()) {
            return message.get();
        }

        throw new MessageException("Message not found " + messageId);
    }

    @Override
    public void deleteMessageById(UUID messageId, User reqUser) throws UserException, MessageException {

        Message message = findMessageById(messageId);

        if (message.getUser().getId().equals(reqUser.getId())) {
            messageRepository.deleteById(messageId);
            return;
        }

        throw new UserException("User is not related to message " + message.getId());
    }

}

