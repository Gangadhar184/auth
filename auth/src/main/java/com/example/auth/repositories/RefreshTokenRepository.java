package com.example.auth.repositories;

import com.example.auth.models.RefreshToken;
import com.example.auth.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    List<RefreshToken> findByUser(User user);

    Optional<RefreshToken> findByTokenFamily(String tokenFamily);

}
