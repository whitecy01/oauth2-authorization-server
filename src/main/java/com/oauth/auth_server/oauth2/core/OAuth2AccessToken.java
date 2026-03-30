package com.oauth.auth_server.oauth2.core;

import java.time.Instant;

public class OAuth2AccessToken {

    private final String tokenValue;
    private final Instant issuedAt;
    private final Instant expiresAt;

    public OAuth2AccessToken(String tokenValue, Instant issuedAt, Instant expiresAt) {
        this.tokenValue = tokenValue;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
    }

    public String getTokenValue() {
        return this.tokenValue;
    }

    public Instant getIssuedAt() {
        return this.issuedAt;
    }

    public Instant getExpiresAt() {
        return this.expiresAt;
    }

    public long getExpiresInSeconds() {
        return this.expiresAt.getEpochSecond() - this.issuedAt.getEpochSecond();
    }
}
