package com.oauth.auth_server.oauth2.service;

import com.oauth.auth_server.entity.OauthAuthorizationCode;
import java.time.Instant;
import java.util.Optional;

public interface OAuth2AuthorizationService {

    void saveAuthorizationCode(String code, String clientId, String username,
                               String redirectUri, String state, Instant expiresAt);

    Optional<OauthAuthorizationCode> findByCode(String code);

    void deleteByCode(String code);
}