package com.oauth.auth_server.oauth2.token;

import com.oauth.auth_server.entity.OauthAuthorizationCode;
import com.oauth.auth_server.oauth2.core.AuthorizationGrantType;
import com.oauth.auth_server.oauth2.core.OAuth2AccessToken;
import com.oauth.auth_server.oauth2.core.OAuth2AuthorizationException;
import com.oauth.auth_server.oauth2.core.OAuth2Error;
import com.oauth.auth_server.oauth2.core.RegisteredClient;
import com.oauth.auth_server.oauth2.service.OAuth2AuthorizationService;
import com.oauth.auth_server.oauth2.service.RegisteredClientRepository;
import java.time.Instant;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class AuthorizationCodeTokenProvider {

    private static final long ACCESS_TOKEN_TTL_SECONDS = 3600;

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final ClientCredentialsExtractor credentialsExtractor;

    public AuthorizationCodeTokenProvider(
            RegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationService authorizationService,
            ClientCredentialsExtractor credentialsExtractor
    ) {
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
        this.credentialsExtractor = credentialsExtractor;
    }

    public OAuth2AccessToken process(AuthorizationCodeTokenRequest request) {
        validateGrantType(request);
        validateCode(request);
        validateRedirectUri(request);

        ClientCredentials credentials = credentialsExtractor
                .extract(request.getAuthorizationHeader(), request.getClientId(), request.getClientSecret())
                .orElseThrow(() -> new OAuth2AuthorizationException(
                        new OAuth2Error("invalid_client", "client authentication is required", null)));

        RegisteredClient registeredClient = registeredClientRepository
                .findByClientId(credentials.clientId())
                .filter(c -> c.isActive() && c.getClientSecret().equals(credentials.clientSecret()))
                .orElseThrow(() -> new OAuth2AuthorizationException(
                        new OAuth2Error("invalid_client", "invalid client credentials", null)));

        if (!registeredClient.getRedirectUris().contains(request.getRedirectUri())) {
            throw new OAuth2AuthorizationException(
                    new OAuth2Error("invalid_grant", "redirect_uri is not registered", null));
        }

        OauthAuthorizationCode authorizationCode = authorizationService
                .findByCode(request.getCode())
                .orElseThrow(() -> new OAuth2AuthorizationException(
                        new OAuth2Error("invalid_grant", "authorization code is invalid", null)));

        if (authorizationCode.getExpiresAt().isBefore(Instant.now())) {
            authorizationService.deleteByCode(request.getCode());
            throw new OAuth2AuthorizationException(
                    new OAuth2Error("invalid_grant", "authorization code is expired", null));
        }

        if (!authorizationCode.getClientId().equals(registeredClient.getClientId())) {
            throw new OAuth2AuthorizationException(
                    new OAuth2Error("invalid_grant", "authorization code was not issued to this client", null));
        }

        if (!authorizationCode.getRedirectUri().equals(request.getRedirectUri())) {
            throw new OAuth2AuthorizationException(
                    new OAuth2Error("invalid_grant", "redirect_uri does not match", null));
        }

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plusSeconds(ACCESS_TOKEN_TTL_SECONDS);

        OAuth2AccessToken accessToken = authorizationService.saveAccessToken(
                registeredClient.getClientId(),
                authorizationCode.getUsername(),
                issuedAt,
                expiresAt
        );

        authorizationService.deleteByCode(request.getCode());

        return accessToken;
    }

    private void validateGrantType(AuthorizationCodeTokenRequest request) {
        if (request.getGrantTypeParamCount() == 0) {
            throw new OAuth2AuthorizationException(
                    new OAuth2Error("invalid_request", "grant_type is required", null));
        }
        if (request.getGrantTypeParamCount() > 1) {
            throw new OAuth2AuthorizationException(
                    new OAuth2Error("invalid_request", "grant_type must not be duplicated", null));
        }
        if (!StringUtils.hasText(request.getGrantType())) {
            throw new OAuth2AuthorizationException(
                    new OAuth2Error("invalid_request", "grant_type is required", null));
        }
        if (!AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(request.getGrantType())) {
            throw new OAuth2AuthorizationException(
                    new OAuth2Error("unsupported_grant_type", "grant_type must be authorization_code", null));
        }
    }

    private void validateCode(AuthorizationCodeTokenRequest request) {
        if (request.getCodeParamCount() == 0) {
            throw new OAuth2AuthorizationException(
                    new OAuth2Error("invalid_request", "code is required", null));
        }
        if (request.getCodeParamCount() > 1) {
            throw new OAuth2AuthorizationException(
                    new OAuth2Error("invalid_request", "code must not be duplicated", null));
        }
        if (!StringUtils.hasText(request.getCode())) {
            throw new OAuth2AuthorizationException(
                    new OAuth2Error("invalid_request", "code is required", null));
        }
    }

    private void validateRedirectUri(AuthorizationCodeTokenRequest request) {
        if (request.getRedirectUriParamCount() == 0) {
            throw new OAuth2AuthorizationException(
                    new OAuth2Error("invalid_grant", "redirect_uri is required", null));
        }
        if (request.getRedirectUriParamCount() > 1) {
            throw new OAuth2AuthorizationException(
                    new OAuth2Error("invalid_request", "redirect_uri must not be duplicated", null));
        }
        if (!StringUtils.hasText(request.getRedirectUri())) {
            throw new OAuth2AuthorizationException(
                    new OAuth2Error("invalid_grant", "redirect_uri is required", null));
        }
    }
}
