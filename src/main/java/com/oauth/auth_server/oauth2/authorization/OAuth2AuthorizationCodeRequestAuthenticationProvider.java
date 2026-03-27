package com.oauth.auth_server.oauth2.authorization;

import com.oauth.auth_server.oauth2.core.OAuth2AuthorizationException;
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
     * @throws ConsentRequiredException        동의가 필요한 경우
     * @throws OAuth2AuthorizationException    검증 실패 시
     */
    public AuthorizationCodeIssuedToken process(OAuth2AuthorizationCodeRequestAuthenticationToken token) {
        validateResponseType(token);

        RegisteredClient client = findClient(token.getClientId());

        String redirectUri = resolveRedirectUri(token, client);

        validateScopes(token, client);

        if (!consentService.hasConsent(token.getUsername(), client.getClientId(), token.getScopes())) {
            throw new ConsentRequiredException(client, token.getUsername(), token.getScopes(), token);
        }

        return issueCode(client, token.getUsername(), redirectUri, token.getState(), token.getScopes());
    }

    /**
     * 동의 완료 후 코드를 발급한다. (POST /oauth2/authorize approve 처리용)
     */
    public AuthorizationCodeIssuedToken issueCode(
            RegisteredClient client,
            String username,
            String redirectUri,
            String state,
            List<String> scopes
    ) {
        String code = UUID.randomUUID().toString().replace("-", "");
        Instant expiresAt = Instant.now().plusSeconds(AUTHORIZATION_CODE_TTL_SECONDS);

        authorizationService.saveAuthorizationCode(code, client.getClientId(), username, redirectUri, state, expiresAt);

        return new AuthorizationCodeIssuedToken(code, redirectUri, state);
    }

    private void validateResponseType(OAuth2AuthorizationCodeRequestAuthenticationToken token) {
        String responseType = token.getResponseType();
        if (responseType == null || responseType.isBlank()) {
            throw new OAuth2AuthorizationException(new OAuth2Error("invalid_request",
                    "response_type is required", null));
        }
        if (!responseType.equals("code")) {
            throw new OAuth2AuthorizationException(new OAuth2Error("unsupported_response_type",
                    "only response_type=code is supported", null));
        }
    }

    private RegisteredClient findClient(String clientId) {
        if (clientId == null || clientId.isBlank()) {
            throw new OAuth2AuthorizationException(new OAuth2Error("invalid_request",
                    "client_id is required", null));
        }
        return registeredClientRepository.findByClientId(clientId)
                .orElseThrow(() -> new OAuth2AuthorizationException(new OAuth2Error("invalid_client",
                        "client not found or inactive", null)));
    }

    private String resolveRedirectUri(OAuth2AuthorizationCodeRequestAuthenticationToken token, RegisteredClient client) {
        String redirectUri = token.getRedirectUri();

        if (redirectUri != null && redirectUri.isBlank()) {
            throw new OAuth2AuthorizationException(new OAuth2Error("invalid_request",
                    "redirect_uri must not be blank", null));
        }
        if (redirectUri != null && redirectUri.contains("#")) {
            throw new OAuth2AuthorizationException(new OAuth2Error("invalid_request",
                    "redirect_uri must not contain a fragment", null));
        }

        if (redirectUri == null) {
            if (client.getRedirectUris().size() != 1) {
                throw new OAuth2AuthorizationException(new OAuth2Error("invalid_request",
                        "redirect_uri is required when multiple redirect URIs are registered", null));
            }
            return client.getRedirectUris().iterator().next();
        }

        if (!client.getRedirectUris().contains(redirectUri)) {
            throw new OAuth2AuthorizationException(new OAuth2Error("invalid_request",
                    "redirect_uri is not registered", null));
        }
        return redirectUri;
    }

    private void validateScopes(OAuth2AuthorizationCodeRequestAuthenticationToken token, RegisteredClient client) {
        if (token.getRawScopeParamCount() > 1) {
            throw new OAuth2AuthorizationException(new OAuth2Error("invalid_scope",
                    "scope parameter must not be duplicated", null));
        }

        for (String scope : token.getScopes()) {
            if (!SCOPE_TOKEN_PATTERN.matcher(scope).matches()) {
                throw new OAuth2AuthorizationException(new OAuth2Error("invalid_scope",
                        "scope contains invalid characters: " + scope, null));
            }
            if (!client.getScopes().contains(scope)) {
                throw new OAuth2AuthorizationException(new OAuth2Error("invalid_scope",
                        "scope is not registered: " + scope, null));
            }
        }
    }
}
