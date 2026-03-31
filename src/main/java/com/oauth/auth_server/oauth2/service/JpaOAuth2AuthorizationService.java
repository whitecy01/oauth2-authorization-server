package com.oauth.auth_server.oauth2.service;

import com.oauth.auth_server.entity.OauthAccessToken;
import com.oauth.auth_server.entity.OauthAuthorizationCode;
import com.oauth.auth_server.oauth2.core.OAuth2AccessToken;
import com.oauth.auth_server.repository.OauthAccessTokenRepository;
import com.oauth.auth_server.repository.OauthAuthorizationCodeRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JpaOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final OauthAuthorizationCodeRepository authorizationCodeRepository;
    private final OauthAccessTokenRepository accessTokenRepository;

    @Override
    public void saveAuthorizationCode(String code, String clientId, String username,
                                      String redirectUri, String state, Instant expiresAt) {
        authorizationCodeRepository.save(
                new OauthAuthorizationCode(code, clientId, username, redirectUri, state, expiresAt)
        );
    }

    @Override
    public Optional<OauthAuthorizationCode> findByCode(String code) {
        return authorizationCodeRepository.findByCode(code);
    }

    @Override
    public void deleteByCode(String code) {
        authorizationCodeRepository.findByCode(code)
                .ifPresent(authorizationCodeRepository::delete);
    }

    @Override
    public OAuth2AccessToken saveAccessToken(String clientId, String username, Instant issuedAt, Instant expiresAt) {
        String tokenValue = UUID.randomUUID().toString().replace("-", "");
        accessTokenRepository.save(new OauthAccessToken(tokenValue, clientId, username, expiresAt));
        return new OAuth2AccessToken(tokenValue, issuedAt, expiresAt);
    }
}