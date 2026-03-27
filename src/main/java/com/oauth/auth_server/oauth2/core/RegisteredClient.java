package com.oauth.auth_server.oauth2.core;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class RegisteredClient implements Serializable {

    @Serial
    private static final long serialVersionUID = -717282636175335081L;

    private String clientId;
    private String clientName;
    private String clientSecret;
    private Set<String> redirectUris;
    private Set<String> scopes;
    private boolean active;

    protected RegisteredClient() {
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientName() {
        return clientName;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public Set<String> getRedirectUris() {
        return redirectUris;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public boolean isActive() {
        return active;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private String clientId;
        private String clientName;
        private String clientSecret;
        private final Set<String> redirectUris = new HashSet<>();
        private final Set<String> scopes = new HashSet<>();
        private boolean active;

        private Builder() {
        }

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder clientName(String clientName) {
            this.clientName = clientName;
            return this;
        }

        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        public Builder redirectUri(String redirectUri) {
            this.redirectUris.add(redirectUri);
            return this;
        }

        public Builder scope(String scope) {
            this.scopes.add(scope);
            return this;
        }

        public Builder active(boolean active) {
            this.active = active;
            return this;
        }

        public RegisteredClient build() {
            if (clientId == null || clientId.isBlank()) {
                throw new IllegalArgumentException("clientId cannot be empty");
            }
            RegisteredClient client = new RegisteredClient();
            client.clientId = this.clientId;
            client.clientName = this.clientName;
            client.clientSecret = this.clientSecret;
            client.redirectUris = Collections.unmodifiableSet(new HashSet<>(this.redirectUris));
            client.scopes = Collections.unmodifiableSet(new HashSet<>(this.scopes));
            client.active = this.active;
            return client;
        }
    }
}