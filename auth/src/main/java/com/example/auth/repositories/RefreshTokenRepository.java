package com.example.auth.repositories;

import com.example.auth.models.RefreshToken;
import com.example.auth.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    List<RefreshToken> findByUser(User user);

    Optional<RefreshToken> findByTokenFamily(String tokenFamily);

    @Query("SELECT rt FROM RefreshToken rt WHERE rt.user = ?1 AND rt.revoked = false AND rt.compromised = false")
    List<RefreshToken> findActiveTokensByUser(User user);

    @Query("SELECT rt FROM RefreshToken rt WHERE rt.tokenFamily = ?1 AND rt.revoked = false")
    List<RefreshToken> findActiveTokensByFamily(String tokenFamily);

    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revoked = true, rt.revokedAt = ?2 WHERE rt.user = ?1")
    void revokeAllUserTokens(User user, LocalDateTime revokedAt);

    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.compromised = true WHERE rt.tokenFamily = ?1")
    void markFamilyAsCompromised(String tokenFamily);

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiryDate < ?1")
    void deleteExpiredTokens(LocalDateTime now);

    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.replaced = true, rt.replacedAt = ?3, rt.replacedByToken = ?2 WHERE rt.token = ?1")
    void markAsReplaced(String oldToken, String newToken, LocalDateTime replacedAt);

}
