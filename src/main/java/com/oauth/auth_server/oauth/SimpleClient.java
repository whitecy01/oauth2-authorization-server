package com.oauth.auth_server.oauth;

public class SimpleClient {

    private final String clientId;
    private final String redirectUri;

    public SimpleClient(String clientId, String redirectUri) {
        this.clientId = clientId;
        this.redirectUri = redirectUri;
    }

    public String getClientId() {
        return clientId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }
}