package com.oauth.auth_server.repository;

import com.oauth.auth_server.entity.OauthAuthorizationCode;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OauthAuthorizationCodeRepository extends JpaRepository<OauthAuthorizationCode, Long> {
    Optional<OauthAuthorizationCode> findByCode(String code);
}