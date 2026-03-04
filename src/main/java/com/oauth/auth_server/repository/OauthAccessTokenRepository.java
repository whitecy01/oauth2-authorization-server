package com.oauth.auth_server.repository;

import com.oauth.auth_server.entity.OauthAccessToken;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OauthAccessTokenRepository extends JpaRepository<OauthAccessToken, Long> {
    Optional<OauthAccessToken> findByToken(String token);
}
