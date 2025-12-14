package com.example.auth.models;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "refresh_tokens")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 512)
    private String token;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private LocalDateTime expiryDate;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column
    private LocalDateTime lastUsedAt;

    @Column(nullable = false)
    private Boolean revoked = false;

    @Column
    private LocalDateTime revokedAt;

    // For token rotation - track the token family to detect reuse attacks
    @Column(nullable = false, length = 100)
    private String tokenFamily;

    // Track if token was replaced (rotated)
    @Column
    private Boolean replaced = false;

    @Column
    private LocalDateTime replacedAt;

    @Column(length = 512)
    private String replacedByToken;

    // Reuse detection flag - if true, this token family is compromised
    @Column(nullable = false)
    private Boolean compromised = false;

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiryDate);
    }

    public boolean isValid() {
        return !revoked  && !compromised;
    }
}
