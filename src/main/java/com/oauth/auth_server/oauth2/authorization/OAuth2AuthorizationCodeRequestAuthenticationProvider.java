package com.oauth.auth_server.oauth2.authorization;

import com.oauth.auth_server.oauth2.core.OAuth2Error;
import com.oauth.auth_server.oauth2.core.RegisteredClient;
import com.oauth.auth_server.oauth2.service.OAuth2AuthorizationService;
import com.oauth.auth_server.oauth2.service.RegisteredClientRepository;
import com.oauth.auth_server.service.AuthorizationConsentService;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * 인가 코드 요청을 처리하는 Provider.
 * 검증 → 동의 확인 → 코드 발급을 순서대로 수행한다.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1">RFC 6749 §4.1</a>
 */
@Component
@RequiredArgsConstructor
public class OAuth2AuthorizationCodeRequestAuthenticationProvider {

    private static final Pattern SCOPE_TOKEN_PATTERN = Pattern.compile("[\\x21\\x23-\\x5B\\x5D-\\x7E]+");
    private static final int AUTHORIZATION_CODE_TTL_SECONDS = 600;

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final AuthorizationConsentService consentService;

    /**
     * 인가 코드 요청을 처리한다.
     *
     * @return 코드 발급 성공 시 {@link AuthorizationCodeIssuedToken}
     * @throws ConsentRequiredException                                   동의가 필요한 경우
     * @throws OAuth2AuthorizationCodeRequestAuthenticationException      검증 실패 시
     */
    public AuthorizationCodeIssuedToken process(OAuth2AuthorizationCodeRequestAuthenticationToken token) {
        validateResponseType(token);

        RegisteredClient client = findClient(token);

        String resolvedRedirectUri = resolveRedirectUri(token, client);

        validateScopes(token, client, resolvedRedirectUri);

        if (!consentService.hasConsent(token.getUsername(), client.getClientId(), token.getScopes())) {
            throw new ConsentRequiredException(client, token.getUsername(), token.getScopes(), token);
        }

        return issueCode(client.getClientId(), token.getUsername(), resolvedRedirectUri, token.getState(), token.getScopes());
    }

    /**
     * 동의 완료 후 코드를 발급한다. (POST /oauth2/authorize approve 처리용)
     */
    public AuthorizationCodeIssuedToken issueCode(
            String clientId,
            String username,
            String redirectUri,
            String state,
            List<String> scopes
    ) {
        RegisteredClient client = registeredClientRepository.findByClientId(clientId)
                .orElseThrow(() -> new IllegalArgumentException("client not found: " + clientId));

        String code = UUID.randomUUID().toString().replace("-", "");
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plusSeconds(AUTHORIZATION_CODE_TTL_SECONDS);

        authorizationService.saveAuthorizationCode(code, client.getClientId(), username, redirectUri, state, issuedAt, expiresAt);

        return new AuthorizationCodeIssuedToken(code, redirectUri, state);
    }

    private void validateResponseType(OAuth2AuthorizationCodeRequestAuthenticationToken token) {
        String responseType = token.getResponseType();

        if (responseType == null || responseType.isBlank()) {
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                    new OAuth2Error("invalid_request", "response_type is required", null),
                    token.getRedirectUri(), token.getState());
        }
        if (!responseType.equals("code")) {
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                    new OAuth2Error("unsupported_response_type", "only response_type=code is supported", null),
                    token.getRedirectUri(), token.getState());
        }
    }

    private RegisteredClient findClient(OAuth2AuthorizationCodeRequestAuthenticationToken token) {
        String clientId = token.getClientId();

        if (clientId != null && clientId.isBlank()) {
            // client_id 가 빈 값으로 제공된 경우 → redirect_uri 로 에러 redirect
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                    new OAuth2Error("invalid_request", "client_id must not be blank", null),
                    token.getRedirectUri(), token.getState());
        }

        // client_id 가 존재하지 않거나 비활성 → redirect_uri 를 신뢰할 수 없으므로 null (400)
        return registeredClientRepository.findByClientId(clientId)
                .orElseThrow(() -> new OAuth2AuthorizationCodeRequestAuthenticationException(
                        new OAuth2Error("invalid_client", "client not found or inactive", null),
                        null, null));
    }

    private String resolveRedirectUri(OAuth2AuthorizationCodeRequestAuthenticationToken token, RegisteredClient client) {
        String redirectUri = token.getRedirectUri();

        // redirect_uri 관련 에러는 redirect_uri 를 신뢰할 수 없으므로 null (400)
        if (redirectUri != null && redirectUri.isBlank()) {
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                    new OAuth2Error("invalid_request", "redirect_uri must not be blank", null),
                    null, null);
        }
        if (redirectUri != null && redirectUri.contains("#")) {
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                    new OAuth2Error("invalid_request", "redirect_uri must not contain a fragment", null),
                    null, null);
        }

        if (redirectUri == null) {
            if (client.getRedirectUris().size() != 1) {
                throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                        new OAuth2Error("invalid_request", "redirect_uri is required when multiple redirect URIs are registered", null),
                        null, null);
            }
            return client.getRedirectUris().iterator().next();
        }

        if (!client.getRedirectUris().contains(redirectUri)) {
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                    new OAuth2Error("invalid_request", "redirect_uri is not registered", null),
                    null, null);
        }
        return redirectUri;
    }

    private void validateScopes(
            OAuth2AuthorizationCodeRequestAuthenticationToken token,
            RegisteredClient client,
            String resolvedRedirectUri
    ) {
        // scope 에러는 redirect_uri 가 이미 검증됐으므로 redirect
        if (token.getRawScopeParamCount() > 1) {
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                    new OAuth2Error("invalid_scope", "scope parameter must not be duplicated", null),
                    resolvedRedirectUri, token.getState());
        }

        for (String scope : token.getScopes()) {
            if (!SCOPE_TOKEN_PATTERN.matcher(scope).matches()) {
                throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                        new OAuth2Error("invalid_scope", "scope contains invalid characters: " + scope, null),
                        resolvedRedirectUri, token.getState());
            }
            if (!client.getScopes().contains(scope)) {
                throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                        new OAuth2Error("invalid_scope", "scope is not registered: " + scope, null),
                        resolvedRedirectUri, token.getState());
            }
        }
    }
}