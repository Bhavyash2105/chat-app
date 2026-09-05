package com.nicolas.chatapp.service;

import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;

    public void sendOtpEmail(String toEmail, String otpCode) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("omshantii2024@gmail.com");
        message.setTo(toEmail);
        message.setSubject("Your ChatApp verification code");
        message.setText("Your verification code is: " + otpCode + "\n\nThis code expires in 10 minutes.");
        mailSender.send(message);
    }

    public void sendPasswordResetOtpEmail(String toEmail, String otpCode) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("omshantii2024@gmail.com");
        message.setTo(toEmail);
        message.setSubject("Your ChatApp password reset code");
        message.setText("Your password reset code is: " + otpCode + "\n\nThis code expires in 10 minutes.");
        mailSender.send(message);
    }
}

