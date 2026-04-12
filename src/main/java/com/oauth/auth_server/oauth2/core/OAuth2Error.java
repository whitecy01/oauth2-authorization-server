package com.oauth.auth_server.oauth2.core;

import java.io.Serializable;

public class OAuth2Error implements Serializable {

    private static final long serialVersionUID = 620L;

    private final String errorCode;
    private final String description;
    private final String uri;

    public OAuth2Error(String errorCode) {
        this(errorCode, null, null);
    }

    public OAuth2Error(String errorCode, String description, String uri) {
        if (errorCode == null || errorCode.isBlank()) {
            throw new IllegalArgumentException("errorCode cannot be empty");
        }
        this.errorCode = errorCode;
        this.description = description;
        this.uri = uri != null ? uri : OAuth2ErrorCodes.getUri(errorCode);
    }

    public final String getErrorCode() {
        return this.errorCode;
    }

    public final String getDescription() {
        return this.description;
    }

    public final String getUri() {
        return this.uri;
    }

    @Override
    public String toString() {
        return "[" + this.errorCode + "] " + (this.description != null ? this.description : "");
    }
}
