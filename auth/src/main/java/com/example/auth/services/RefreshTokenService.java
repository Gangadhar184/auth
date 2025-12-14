package com.example.auth.services;

import com.example.auth.exceptions.TokenRefreshException;
import com.example.auth.models.RefreshToken;
import com.example.auth.models.User;
import com.example.auth.repositories.RefreshTokenRepository;
import com.example.auth.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenProvider jwtTokenProvider;

    @Transactional
    public RefreshToken createRefreshToken(User user) {
        String tokenFamily = UUID.randomUUID().toString();
        String token = jwtTokenProvider.generateRefreshToken(user.getUsername())    ;
        RefreshToken refreshToken = RefreshToken.builder()
                .token(token)
                .user(user)
                .tokenFamily(tokenFamily)
                .expiryDate(LocalDateTime.now().plusSeconds(jwtTokenProvider.getRefreshTokenExpiration()))
                .revoked(false)
                .replaced(false)
                .compromised(false)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    @Transactional
    public RefreshToken rotateRefreshToken(RefreshToken oldToken) {
        String newTokenString = jwtTokenProvider.generateRefreshToken(oldToken.getUser().getUsername());

        RefreshToken newToken = RefreshToken.builder()
                .token(newTokenString)
                .user(oldToken.getUser())
                .tokenFamily(oldToken.getTokenFamily())
                .expiryDate(LocalDateTime.now().plusSeconds(jwtTokenProvider.getRefreshTokenExpiration()))
                .revoked(false)
                .replaced(false)
                .compromised(false)
                .build();

        newToken = refreshTokenRepository.save(newToken);

        //makre oldtoken as replaced
        refreshTokenRepository.markAsReplaced(oldToken.getToken(), newToken.getToken(), LocalDateTime.now());
        return newToken;
    }

    @Transactional
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Transactional
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.isExpired()) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(), "Refresh token has expired. Please login again");
        }

        // Update last used time
        token.setLastUsedAt(LocalDateTime.now());
        return refreshTokenRepository.save(token);
    }

    @Transactional
    public void validateRefreshToken(RefreshToken token) {
        // Check if token is revoked
        if (token.getRevoked()) {
            throw new TokenRefreshException(token.getToken(), "Refresh token has been revoked");
        }

        // Check if token is expired
        if (token.isExpired()) {
            throw new TokenRefreshException(token.getToken(), "Refresh token has expired");
        }

        // Check if user is still enabled
        if (!token.getUser().getEnabled()) {
            throw new TokenRefreshException(token.getToken(), "User account is disabled");
        }

        //  check if token was replaced (rotation attack detection)
        if (token.getReplaced()) {
            log.warn("SECURITY ALERT: Attempted reuse of replaced refresh token. Token family: {}, User: {}",
                    token.getTokenFamily(), token.getUser().getUsername());

            // Mark entire token family as compromised
            markTokenFamilyAsCompromised(token.getTokenFamily());

            throw new TokenRefreshException(token.getToken(),
                    "Token reuse detected. All sessions have been invalidated. Please login again");
        }

        // Check if token family is compromised
        if (token.getCompromised()) {
            throw new TokenRefreshException(token.getToken(),
                    "Token family is compromised. Please login again");
        }
    }
    @Transactional
    public void markTokenFamilyAsCompromised(String tokenFamily) {
        // Mark all tokens in this family as compromised
        refreshTokenRepository.markFamilyAsCompromised(tokenFamily);

        // Also revoke all tokens in this family
        List<RefreshToken> familyTokens = refreshTokenRepository.findActiveTokensByFamily(tokenFamily);
        LocalDateTime now = LocalDateTime.now();

        familyTokens.forEach(token -> {
            token.setRevoked(true);
            token.setRevokedAt(now);
            token.setCompromised(true);
        });

        refreshTokenRepository.saveAll(familyTokens);
    }

    @Transactional
    public void revokeToken(String token) {
        refreshTokenRepository.findByToken(token).ifPresent(refreshToken -> {
            refreshToken.setRevoked(true);
            refreshToken.setRevokedAt(LocalDateTime.now());
            refreshTokenRepository.save(refreshToken);
        });
    }

    @Transactional
    public void revokeAllUserTokens(User user) {
        refreshTokenRepository.revokeAllUserTokens(user, LocalDateTime.now());
    }

    @Transactional
    public List<RefreshToken> getActiveTokensByUser(User user) {
        return refreshTokenRepository.findActiveTokensByUser(user);
    }

    // Scheduled cleanup of expired tokens (runs daily at 2 AM)
    @Scheduled(cron = "0 0 2 * * ?")
    @Transactional
    public void cleanupExpiredTokens() {
        log.info("Running scheduled cleanup of expired refresh tokens");
        refreshTokenRepository.deleteExpiredTokens(LocalDateTime.now());
    }

}
