package com.nicolas.chatapp.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class CaptchaService {

    @Value("${recaptcha.secret}")
    private String recaptchaSecret;

    private final RestTemplate restTemplate = new RestTemplate();

    public boolean verifyCaptcha(String captchaToken) {

        if (captchaToken == null || captchaToken.isBlank()) {
            return false;
        }

        String url = "https://www.google.com/recaptcha/api/siteverify";

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("secret", recaptchaSecret);
        params.add("response", captchaToken);

        Map<String, Object> response = restTemplate.postForObject(url, params, Map.class);

        boolean success = response != null && Boolean.TRUE.equals(response.get("success"));

        if (!success) {
            log.warn("Captcha verification failed: {}", response);
        }

        return success;
    }
}
