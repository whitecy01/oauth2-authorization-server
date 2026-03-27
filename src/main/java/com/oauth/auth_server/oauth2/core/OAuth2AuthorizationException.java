package com.oauth.auth_server.oauth2.core;

import java.io.Serial;

public class OAuth2AuthorizationException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = -5470222190376181102L;

    private final OAuth2Error error;

    public OAuth2AuthorizationException(OAuth2Error error) {
        this(error, error.toString());
    }

    public OAuth2AuthorizationException(OAuth2Error error, String message) {
        super(message);
        if (error == null) {
            throw new IllegalArgumentException("error must not be null");
        }
        this.error = error;
    }

    public OAuth2AuthorizationException(OAuth2Error error, Throwable cause) {
        this(error, error.toString(), cause);
    }

    public OAuth2AuthorizationException(OAuth2Error error, String message, Throwable cause) {
        super(message, cause);
        if (error == null) {
            throw new IllegalArgumentException("error must not be null");
        }
        this.error = error;
    }

    public OAuth2Error getError() {
        return this.error;
    }
}