package com.oauth.auth_server.oauth2.core;

public enum AuthorizationGrantType {

    AUTHORIZATION_CODE("authorization_code");

    private final String value;

    AuthorizationGrantType(String value) {
        this.value = value;
    }

    public String getValue() {
        return this.value;
    }
}
