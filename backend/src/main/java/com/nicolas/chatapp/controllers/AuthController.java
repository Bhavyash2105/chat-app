package com.nicolas.chatapp.controllers;

import com.nicolas.chatapp.config.TokenProvider;
import com.nicolas.chatapp.dto.request.LoginRequestDTO;
import com.nicolas.chatapp.dto.request.UpdateUserRequestDTO;
import com.nicolas.chatapp.dto.request.VerifyOtpRequestDTO;
import com.nicolas.chatapp.dto.response.ApiResponseDTO;
import com.nicolas.chatapp.dto.response.LoginResponseDTO;
import com.nicolas.chatapp.exception.UserException;
import com.nicolas.chatapp.model.PendingSignup;
import com.nicolas.chatapp.model.User;
import com.nicolas.chatapp.repository.PendingSignupRepository;
import com.nicolas.chatapp.repository.UserRepository;
import com.nicolas.chatapp.service.CaptchaService;
import com.nicolas.chatapp.service.EmailService;
import com.nicolas.chatapp.service.implementation.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.Random;

@Slf4j
@CrossOrigin
@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final TokenProvider tokenProvider;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final CustomUserDetailsService customUserDetailsService;
    private final PendingSignupRepository pendingSignupRepository;
    private final EmailService emailService;
    private final CaptchaService captchaService;

    @PostMapping("/signup")
    public ResponseEntity<ApiResponseDTO> signup(@RequestBody UpdateUserRequestDTO signupRequestDTO) throws UserException {

        final String email = signupRequestDTO.email();
        final String password = signupRequestDTO.password();
        final String fullName = signupRequestDTO.fullName();

        if (!captchaService.verifyCaptcha(signupRequestDTO.captchaToken())) {
            throw new UserException("Captcha verification failed. Please try again.");
        }

        Optional<User> existingUser = userRepository.findByEmail(email);

        if (existingUser.isPresent()) {
            throw new UserException("Account with email " + email + " already exists");
        }

        // Generate 6-digit OTP
        String otpCode = String.format("%06d", new Random().nextInt(1000000));

        // Remove any previous pending signup for this email (e.g. retry)
        pendingSignupRepository.deleteByEmail(email);

        PendingSignup pendingSignup = PendingSignup.builder()
                .email(email)
                .password(passwordEncoder.encode(password))
                .fullName(fullName)
                .otpCode(otpCode)
                .expiresAt(LocalDateTime.now().plusMinutes(10))
                .build();

        pendingSignupRepository.save(pendingSignup);
        emailService.sendOtpEmail(email, otpCode);

        log.info("OTP sent to {}", email);

        ApiResponseDTO response = ApiResponseDTO.builder()
                .message("OTP sent to your email")
                .status(true)
                .build();

        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<LoginResponseDTO> verifyOtp(@RequestBody VerifyOtpRequestDTO verifyOtpRequestDTO) throws UserException {

        final String email = verifyOtpRequestDTO.email();
        final String otpCode = verifyOtpRequestDTO.otpCode();

        PendingSignup pendingSignup = pendingSignupRepository.findByEmail(email)
                .orElseThrow(() -> new UserException("No pending signup found for this email"));

        if (pendingSignup.getExpiresAt().isBefore(LocalDateTime.now())) {
            pendingSignupRepository.deleteByEmail(email);
            throw new UserException("OTP has expired. Please sign up again.");
        }

        if (!pendingSignup.getOtpCode().equals(otpCode)) {
            throw new UserException("Invalid OTP code");
        }

        User newUser = User.builder()
                .email(pendingSignup.getEmail())
                .password(pendingSignup.getPassword())
                .fullName(pendingSignup.getFullName())
                .build();

        userRepository.save(newUser);
        pendingSignupRepository.deleteByEmail(email);

        Authentication authentication = new UsernamePasswordAuthenticationToken(email, null, List.of());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = tokenProvider.generateToken(authentication);

        LoginResponseDTO loginResponseDTO = LoginResponseDTO.builder()
                .token(jwt)
                .isAuthenticated(true)
                .build();

        log.info("User {} successfully verified and signed up", email);

        return new ResponseEntity<>(loginResponseDTO, HttpStatus.CREATED);
    }

    @PostMapping("/signin")
    public ResponseEntity<LoginResponseDTO> login(@RequestBody LoginRequestDTO loginRequestDTO) {

        final String email = loginRequestDTO.email();
        final String password = loginRequestDTO.password();

        Authentication authentication = authenticateReq(email, password);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = tokenProvider.generateToken(authentication);

        LoginResponseDTO loginResponseDTO = LoginResponseDTO.builder()
                .token(jwt)
                .isAuthenticated(true)
                .build();

        log.info("User {} successfully signed in", loginRequestDTO.email());

        return new ResponseEntity<>(loginResponseDTO, HttpStatus.ACCEPTED);
    }

    public Authentication authenticateReq(String username, String password) {

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);

        if (userDetails == null) {
            throw new BadCredentialsException("Invalid username");
        }

        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new BadCredentialsException("Invalid Password");
        }

        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

}