package com.oauth.auth_server;

import com.oauth.auth_server.client.RegisteredClient;
import io.micrometer.common.lang.Nullable;
import java.io.Serial;
import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * OAuth2Authorization는 이런 걸 담는 도메인 객체다:
 * 	- RegisteredClient
 * 	- principalName (사용자)
 * 	- authorizationGrantType
 * 	- scopes
 * 	- authorizationCode
 * 	- accessToken
 * 	- refreshToken
 * 	- attributes (추가 데이터)
 * 	즉, 하나의 OAuth 흐름 전체 상태
 */
public class OAuth2Authorization {
    private String id;

    private String registeredClientId;

    private String principalName;

    private AuthorizationGrantType authorizationGrantType;

    private Set<String> authorizedScopes;

    private Map<Class<? extends OAuth2Token>, Token<?>> tokens;

    private Map<String, Object> attributes;

    protected OAuth2Authorization() {
    }

    public String getId() {
        return this.id;
    }

    public String getRegisteredClientId() {
        return this.registeredClientId;
    }

    public String getPrincipalName() {
        return this.principalName;
    }

    public AuthorizationGrantType getAuthorizationGrantType() {
        return this.authorizationGrantType;
    }

    public Set<String> getAuthorizedScopes() {
        return this.authorizedScopes;
    }

    @Nullable
    @SuppressWarnings("unchecked")
    public <T extends OAuth2Token> Token<T> getToken(Class<T> tokenType) {
        Assert.notNull(tokenType, "tokenType cannot be null");
        Token<?> token = this.tokens.get(tokenType);
        return (token != null) ? (Token<T>) token : null;
    }

    @Nullable
    @SuppressWarnings("unchecked")
    public <T extends OAuth2Token> Token<T> getToken(String tokenValue) {
        Assert.hasText(tokenValue, "tokenValue cannot be empty");
        for (Token<?> token : this.tokens.values()) {
            if (token.getToken().getTokenValue().equals(tokenValue)) {
                return (Token<T>) token;
            }
        }
        return null;
    }

    public Map<String, Object> getAttributes() {
        return this.attributes;
    }

    @Nullable
    @SuppressWarnings("unchecked")
    public <T> T getAttribute(String name) {
        Assert.hasText(name, "name cannot be empty");
        return (T) this.attributes.get(name);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        OAuth2Authorization that = (OAuth2Authorization) obj;
        return Objects.equals(this.id, that.id) && Objects.equals(this.registeredClientId, that.registeredClientId)
                && Objects.equals(this.principalName, that.principalName)
                && Objects.equals(this.authorizationGrantType, that.authorizationGrantType)
                && Objects.equals(this.authorizedScopes, that.authorizedScopes)
                && Objects.equals(this.tokens, that.tokens) && Objects.equals(this.attributes, that.attributes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.id, this.registeredClientId, this.principalName, this.authorizationGrantType,
                this.authorizedScopes, this.tokens, this.attributes);
    }

    public static Builder withRegisteredClient(RegisteredClient registeredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        return new Builder(registeredClient.getId());
    }

    public static Builder from(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        return new Builder(authorization.getRegisteredClientId()).id(authorization.getId())
                .principalName(authorization.getPrincipalName())
                .authorizationGrantType(authorization.getAuthorizationGrantType())
                .authorizedScopes(authorization.getAuthorizedScopes())
                .tokens(authorization.tokens)
                .attributes((attrs) -> attrs.putAll(authorization.getAttributes()));
    }

    public Token<OAuth2AccessToken> getAccessToken() {
        return getToken(OAuth2AccessToken.class);
    }

    public static class Token<T extends OAuth2Token> implements Serializable {

        @Serial
        private static final long serialVersionUID = -5931125502413497522L;

        private final T token;

        protected Token(T token) {
            this.token = token;
        }

        public T getToken() {
            return this.token;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || getClass() != obj.getClass()) {
                return false;
            }
            Token<?> that = (Token<?>) obj;
            return Objects.equals(this.token, that.token);
        }

        @Override
        public int hashCode() {
            return Objects.hash(this.token);
        }

    }

    public static class Builder {

        private String id;

        private final String registeredClientId;

        private String principalName;

        private AuthorizationGrantType authorizationGrantType;

        private Set<String> authorizedScopes;

        private Map<Class<? extends OAuth2Token>, Token<?>> tokens = new HashMap<>();

        private final Map<String, Object> attributes = new HashMap<>();

        protected Builder(String registeredClientId) {
            this.registeredClientId = registeredClientId;
        }

        public Builder id(String id) {
            this.id = id;
            return this;
        }

        public Builder principalName(String principalName) {
            this.principalName = principalName;
            return this;
        }

        public Builder authorizationGrantType(AuthorizationGrantType authorizationGrantType) {
            this.authorizationGrantType = authorizationGrantType;
            return this;
        }

        public Builder authorizedScopes(Set<String> authorizedScopes) {
            this.authorizedScopes = authorizedScopes;
            return this;
        }

        public <T extends OAuth2Token> Builder token(T token) {
            return token(token, (metadata) -> {
            });
        }

        public <T extends OAuth2Token> Builder token(T token, Consumer<Map<String, Object>> metadataConsumer) {
            Assert.notNull(token, "token cannot be null");
            Class<? extends OAuth2Token> tokenClass = token.getClass();
            this.tokens.put(tokenClass, new Token<>(token));
            return this;
        }

        protected final Builder tokens(Map<Class<? extends OAuth2Token>, Token<?>> tokens) {
            this.tokens = new HashMap<>(tokens);
            return this;
        }

        public Builder attribute(String name, Object value) {
            Assert.hasText(name, "name cannot be empty");
            Assert.notNull(value, "value cannot be null");
            this.attributes.put(name, value);
            return this;
        }

        public Builder attributes(Consumer<Map<String, Object>> attributesConsumer) {
            attributesConsumer.accept(this.attributes);
            return this;
        }

        public OAuth2Authorization build() {
            Assert.hasText(this.principalName, "principalName cannot be empty");
            Assert.notNull(this.authorizationGrantType, "authorizationGrantType cannot be null");

            OAuth2Authorization authorization = new OAuth2Authorization();
            if (!StringUtils.hasText(this.id)) {
                this.id = UUID.randomUUID().toString();
            }
            authorization.id = this.id;
            authorization.registeredClientId = this.registeredClientId;
            authorization.principalName = this.principalName;
            authorization.authorizationGrantType = this.authorizationGrantType;
            authorization.authorizedScopes = Collections.unmodifiableSet(!CollectionUtils.isEmpty(this.authorizedScopes)
                    ? new HashSet<>(this.authorizedScopes) : new HashSet<>());
            authorization.tokens = Collections.unmodifiableMap(this.tokens);
            authorization.attributes = Collections.unmodifiableMap(this.attributes);
            return authorization;
        }

    }
}
