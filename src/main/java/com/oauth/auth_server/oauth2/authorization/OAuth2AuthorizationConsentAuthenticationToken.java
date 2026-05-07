package com.oauth.auth_server.oauth2.authorization;

import java.util.List;

public class OAuth2AuthorizationConsentAuthenticationToken {

    private final String clientId;
    private final String redirectUri;
    private final List<String> scopes;
    private final String state;
    private final String username;
    private final boolean approved;

    public OAuth2AuthorizationConsentAuthenticationToken(
            String clientId,
            String redirectUri,
            List<String> scopes,
            String state,
            String username,
            boolean approved
    ) {
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.scopes = List.copyOf(scopes);
        this.state = state;
        this.username = username;
        this.approved = approved;
    }

    public String getClientId() { return clientId; }
    public String getRedirectUri() { return redirectUri; }
    public List<String> getScopes() { return scopes; }
    public String getState() { return state; }
    public String getUsername() { return username; }
    public boolean isApproved() { return approved; }
}
