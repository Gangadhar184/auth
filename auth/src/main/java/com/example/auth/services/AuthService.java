package com.example.auth.services;

import com.example.auth.dtos.*;
import com.example.auth.exceptions.BadRequestException;
import com.example.auth.exceptions.TokenRefreshException;
import com.example.auth.mappers.UserMapper;
import com.example.auth.models.RefreshToken;
import com.example.auth.models.User;
import com.example.auth.repositories.UserRepository;
import com.example.auth.security.JwtTokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtTokenProvider tokenProvider;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final UserMapper userMapper;


    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if(userRepository.existsByUsername(request.getUsername())) {
            throw new BadRequestException("Username is already taken");
        }
        if(userRepository.existsByEmail(request.getEmail())) {
            throw new BadRequestException("Email is already in use");
        }

        Set<String> roles = request.getRoles();
        if(roles == null || roles.isEmpty()) {
            roles = new HashSet<>();
            roles.add("ROLE_USER");
        }
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(roles)
                .enabled(true)
                .build();

        user = userRepository.save(user);

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                user.getUsername(),
                null,
                roles.stream().map(SimpleGrantedAuthority::new)
                        .toList()
        );
        String accessToken = tokenProvider.generateAccessToken(authentication);
        return AuthResponse.builder()
                .accessToken(accessToken)
                .user(userMapper.toDto(user))
                .build();

    }


    @Transactional
    public AuthResponse login(LoginRequest loginRequest) {
        User user = userRepository.findByUsername(loginRequest.getUsername())
                .orElseThrow(()->new BadCredentialsException("Invalid username or password"));

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
            userRepository.save(user);
            String accessToken = tokenProvider.generateAccessToken(authentication);
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(
                    user
            );

            return AuthResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken.getToken())
                    .expiresIn(tokenProvider.getAccessTokenExpiration())
                    .user(userMapper.toDto(user))
                    .build();
        }catch (BadCredentialsException ex) {
            userRepository.save(user);
            throw new BadCredentialsException("Invalid username or password");
        }
    }

    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest tokenRequest) {
        String requestRefreshToken = tokenRequest.getRefreshToken();
        RefreshToken refreshToken = refreshTokenService.findByToken(requestRefreshToken)
                .orElseThrow(()->new TokenRefreshException(requestRefreshToken, "Refresh token not found")      );

        refreshTokenService.validateRefreshToken(refreshToken);
        User user = refreshToken.getUser();

        String rolesString = String.join(",", user.getRoles());
        String accessToken = tokenProvider.generateAccessTokenFromUsername(user.getUsername(), rolesString);

        //rotate refresh token
        RefreshToken newRefreshToken = refreshTokenService.rotateRefreshToken(refreshToken);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(newRefreshToken.getToken())
                .expiresIn(tokenProvider.getAccessTokenExpiration())
                .user(userMapper.toDto(user))
                .build();
    }

    @Transactional
    public ApiResponse logout(LogoutRequest logoutRequest, Authentication authentication) {
        if(logoutRequest.getRefreshToken() != null) {
            RefreshToken refreshToken = refreshTokenService.findByToken(logoutRequest.getRefreshToken())
                    .orElseThrow(()->new TokenRefreshException(logoutRequest.getRefreshToken(),"Refresh token not found"));


            if (logoutRequest.getLogoutAllDevices()) {
                // Logout from all devices
                refreshTokenService.revokeAllUserTokens(refreshToken.getUser());
                log.info("All sessions logged out for user: {}", refreshToken.getUser().getUsername());

                return ApiResponse.builder()
                        .success(true)
                        .message("Logged out from all devices successfully")
                        .build();
            } else {
                // Logout from current device only
                refreshTokenService.revokeToken(logoutRequest.getRefreshToken());
                log.info("Session logged out for user: {}",
                        refreshToken.getUser().getUsername());

                return ApiResponse.builder()
                        .success(true)
                        .message("Logged out successfully")
                        .build();
            }
        }
        return ApiResponse.builder()
                .success(true)
                .message("Logged out successfully")
                .build();
    }


}
