package com.oauth.auth_server.oauth2.authorization;

import com.oauth.auth_server.oauth2.core.RegisteredClient;
import java.util.List;

/**
 * 사용자가 아직 동의하지 않은 경우 Provider가 던지는 예외.
 * Controller가 이를 잡아 동의 화면 렌더링에 필요한 데이터를 model에 담는다.
 */
public class ConsentRequiredException extends RuntimeException {

    private final RegisteredClient registeredClient;
    private final String username;
    private final List<String> requestedScopes;
    private final OAuth2AuthorizationCodeRequestAuthenticationToken authorizationRequest;

    public ConsentRequiredException(
            RegisteredClient registeredClient,
            String username,
            List<String> requestedScopes,
            OAuth2AuthorizationCodeRequestAuthenticationToken authorizationRequest
    ) {
        super("Consent required for client: " + registeredClient.getClientId());
        this.registeredClient = registeredClient;
        this.username = username;
        this.requestedScopes = List.copyOf(requestedScopes);
        this.authorizationRequest = authorizationRequest;
    }

    public RegisteredClient getRegisteredClient() {
        return registeredClient;
    }

    public String getUsername() {
        return username;
    }

    public List<String> getRequestedScopes() {
        return requestedScopes;
    }

    public OAuth2AuthorizationCodeRequestAuthenticationToken getAuthorizationRequest() {
        return authorizationRequest;
    }
}