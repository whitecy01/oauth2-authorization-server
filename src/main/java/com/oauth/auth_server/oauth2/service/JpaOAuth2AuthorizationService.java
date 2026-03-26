package com.oauth.auth_server.oauth2.service;

import com.oauth.auth_server.entity.OauthAuthorizationCode;
import com.oauth.auth_server.repository.OauthAuthorizationCodeRepository;
import java.time.Instant;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JpaOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final OauthAuthorizationCodeRepository authorizationCodeRepository;

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
}