package com.oauth.auth_server.client;

import com.oauth.auth_server.settings.ClientSettings;
import java.io.Serial;
import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * 도메인 엔티티
 * Spring Authorization Server 내부에서 사용하는 OAuth Client를 표현하는 도메인 모델
 * 왜 엔티티로 안 만들어졌냐면 Spring Authorization Server는 InMemoery, JDBC, JPA, REDIS, Custom 어떤 저장 방식도 가능하게 설계됨
 * 그래서 RegisteredClient (도메인 모델)
 *         ↓
 * RegisteredClientRepository (저장소 인터페이스)
 *         ↓
 * 구현체가 알아서 DB/JPA/Memory 처리
 */
public class RegisteredClient implements Serializable {
    @Serial
    private static final long serialVersionUID = -717282636175335081L;

    private String id;

    private String clientId;

    private String clientSecret;

    private Set<ClientAuthenticationMethod> clientAuthenticationMethods;

    private Set<AuthorizationGrantType> authorizationGrantTypes;

    private Set<String> redirectUris;

    private Set<String> scopes;

    private ClientSettings clientSettings;

    protected RegisteredClient() {
    }

    /**
     * Returns the identifier for the registration.
     *
     * @return the identifier for the registration
     */
    public String getId() {
        return this.id;
    }

    /**
     * Returns the client identifier.
     *
     * @return the client identifier
     */
    public String getClientId() {
        return this.clientId;
    }

    /**
     * Returns the client secret or {@code null} if not available.
     *
     * @return the client secret or {@code null} if not available
     */
    @Nullable
    public String getClientSecret() {
        return this.clientSecret;
    }

    /**
     * Returns the {@link ClientAuthenticationMethod authentication method(s)} that the client may use.
     *
     * @return the {@code Set} of {@link ClientAuthenticationMethod authentication method(s)}
     */
    public Set<ClientAuthenticationMethod> getClientAuthenticationMethods() {
        return this.clientAuthenticationMethods;
    }

    /**
     * Returns the {@link AuthorizationGrantType authorization grant type(s)} that the client may use.
     *
     * @return the {@code Set} of {@link AuthorizationGrantType authorization grant type(s)}
     */
    public Set<AuthorizationGrantType> getAuthorizationGrantTypes() {
        return this.authorizationGrantTypes;
    }

    /**
     * Returns the redirect URI(s) that the client may use in redirect-based flows.
     *
     * @return the {@code Set} of redirect URI(s)
     */
    public Set<String> getRedirectUris() {
        return this.redirectUris;
    }

    /**
     * Returns the scope(s) that the client may use.
     *
     * @return the {@code Set} of scope(s)
     */
    public Set<String> getScopes() {
        return this.scopes;
    }

    /**
     * Returns the {@link ClientSettings client configuration settings}.
     *
     * @return the {@link ClientSettings}
     */
    public ClientSettings getClientSettings() {
        return this.clientSettings;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        RegisteredClient that = (RegisteredClient) obj;
        return Objects.equals(this.id, that.id) && Objects.equals(this.clientId, that.clientId)
                && Objects.equals(this.clientSecret, that.clientSecret)
                && Objects.equals(this.clientAuthenticationMethods, that.clientAuthenticationMethods)
                && Objects.equals(this.authorizationGrantTypes, that.authorizationGrantTypes)
                && Objects.equals(this.redirectUris, that.redirectUris)
                && Objects.equals(this.scopes, that.scopes) && Objects.equals(this.clientSettings, that.clientSettings);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.id, this.clientId, this.clientSecret,
                this.clientAuthenticationMethods,
                this.authorizationGrantTypes, this.redirectUris, this.scopes,
                this.clientSettings);
    }

    @Override
    public String toString() {
        return "RegisteredClient {" + "id='" + this.id + '\'' + ", clientId='" + this.clientId + '\''
                + ", clientAuthenticationMethods=" + this.clientAuthenticationMethods
                + ", authorizationGrantTypes=" + this.authorizationGrantTypes + ", redirectUris=" + this.redirectUris
                + ", scopes=" + this.scopes
                + ", clientSettings=" + this.clientSettings + '}';
    }

    /**
     * Returns a new {@link Builder}, initialized with the provided registration identifier.
     *
     * @param id the identifier for the registration
     * @return the {@link Builder}
     */
    public static Builder withId(String id) {
        Assert.hasText(id, "id cannot be empty");
        return new Builder(id);
    }

    /**
     * Returns a new {@link Builder}, initialized with the values from the provided {@link RegisteredClient}.
     *
     * @param registeredClient the {@link RegisteredClient} used for initializing the {@link Builder}
     * @return the {@link Builder}
     */
    public static Builder from(RegisteredClient registeredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        return new Builder(registeredClient);
    }

    /**
     * A builder for {@link RegisteredClient}.
     */
    public static class Builder {

        private String id;

        private String clientId;

        private String clientSecret;

        private final Set<ClientAuthenticationMethod> clientAuthenticationMethods = new HashSet<>();

        private final Set<AuthorizationGrantType> authorizationGrantTypes = new HashSet<>();

        private final Set<String> redirectUris = new HashSet<>();

        private final Set<String> scopes = new HashSet<>();

        private ClientSettings clientSettings;

        protected Builder(String id) {
            this.id = id;
        }

        protected Builder(RegisteredClient registeredClient) {
            this.id = registeredClient.getId();
            this.clientId = registeredClient.getClientId();
            this.clientSecret = registeredClient.getClientSecret();
            if (!CollectionUtils.isEmpty(registeredClient.getClientAuthenticationMethods())) {
                this.clientAuthenticationMethods.addAll(registeredClient.getClientAuthenticationMethods());
            }
            if (!CollectionUtils.isEmpty(registeredClient.getAuthorizationGrantTypes())) {
                this.authorizationGrantTypes.addAll(registeredClient.getAuthorizationGrantTypes());
            }
            if (!CollectionUtils.isEmpty(registeredClient.getRedirectUris())) {
                this.redirectUris.addAll(registeredClient.getRedirectUris());
            }
            if (!CollectionUtils.isEmpty(registeredClient.getScopes())) {
                this.scopes.addAll(registeredClient.getScopes());
            }
            this.clientSettings = ClientSettings.withSettings(registeredClient.getClientSettings().getSettings())
                    .build();
        }

        /**
         * Sets the identifier for the registration.
         *
         * @param id the identifier for the registration
         * @return the {@link Builder}
         */
        public Builder id(String id) {
            this.id = id;
            return this;
        }

        /**
         * Sets the client identifier.
         *
         * @param clientId the client identifier
         * @return the {@link Builder}
         */
        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        /**
         * Sets the client secret.
         *
         * @param clientSecret the client secret
         * @return the {@link Builder}
         */
        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        /**
         * Adds an {@link ClientAuthenticationMethod authentication method} the client may use when authenticating with
         * the authorization server.
         *
         * @param clientAuthenticationMethod the authentication method
         * @return the {@link Builder}
         */
        public Builder clientAuthenticationMethod(ClientAuthenticationMethod clientAuthenticationMethod) {
            this.clientAuthenticationMethods.add(clientAuthenticationMethod);
            return this;
        }

        /**
         * A {@code Consumer} of the {@link ClientAuthenticationMethod authentication method(s)} allowing the ability to
         * add, replace, or remove.
         *
         * @param clientAuthenticationMethodsConsumer a {@code Consumer} of the authentication method(s)
         * @return the {@link Builder}
         */
        public Builder clientAuthenticationMethods(
                Consumer<Set<ClientAuthenticationMethod>> clientAuthenticationMethodsConsumer) {
            clientAuthenticationMethodsConsumer.accept(this.clientAuthenticationMethods);
            return this;
        }

        /**
         * Adds an {@link AuthorizationGrantType authorization grant type} the client may use.
         *
         * @param authorizationGrantType the authorization grant type
         * @return the {@link Builder}
         */
        public Builder authorizationGrantType(AuthorizationGrantType authorizationGrantType) {
            this.authorizationGrantTypes.add(authorizationGrantType);
            return this;
        }

        /**
         * A {@code Consumer} of the {@link AuthorizationGrantType authorization grant type(s)} allowing the ability to
         * add, replace, or remove.
         *
         * @param authorizationGrantTypesConsumer a {@code Consumer} of the authorization grant type(s)
         * @return the {@link Builder}
         */
        public Builder authorizationGrantTypes(Consumer<Set<AuthorizationGrantType>> authorizationGrantTypesConsumer) {
            authorizationGrantTypesConsumer.accept(this.authorizationGrantTypes);
            return this;
        }

        /**
         * Adds a redirect URI the client may use in a redirect-based flow.
         *
         * @param redirectUri the redirect URI
         * @return the {@link Builder}
         */
        public Builder redirectUri(String redirectUri) {
            this.redirectUris.add(redirectUri);
            return this;
        }

        /**
         * A {@code Consumer} of the redirect URI(s) allowing the ability to add, replace, or remove.
         *
         * @param redirectUrisConsumer a {@link Consumer} of the redirect URI(s)
         * @return the {@link Builder}
         */
        public Builder redirectUris(Consumer<Set<String>> redirectUrisConsumer) {
            redirectUrisConsumer.accept(this.redirectUris);
            return this;
        }

        /**
         * Adds a scope the client may use.
         *
         * @param scope the scope
         * @return the {@link Builder}
         */
        public Builder scope(String scope) {
            this.scopes.add(scope);
            return this;
        }

        /**
         * A {@code Consumer} of the scope(s) allowing the ability to add, replace, or remove.
         *
         * @param scopesConsumer a {@link Consumer} of the scope(s)
         * @return the {@link Builder}
         */
        public Builder scopes(Consumer<Set<String>> scopesConsumer) {
            scopesConsumer.accept(this.scopes);
            return this;
        }

        /**
         * Sets the {@link ClientSettings client configuration settings}.
         *
         * @param clientSettings the client configuration settings
         * @return the {@link Builder}
         */
        public Builder clientSettings(ClientSettings clientSettings) {
            this.clientSettings = clientSettings;
            return this;
        }

        /**
         * Builds a new {@link RegisteredClient}.
         *
         * @return a {@link RegisteredClient}
         */
        public RegisteredClient build() {
            Assert.hasText(this.clientId, "clientId cannot be empty");
            Assert.notEmpty(this.authorizationGrantTypes, "authorizationGrantTypes cannot be empty");
            if (this.authorizationGrantTypes.contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
                Assert.notEmpty(this.redirectUris, "redirectUris cannot be empty");
            }
            if (CollectionUtils.isEmpty(this.clientAuthenticationMethods)) {
                this.clientAuthenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
            }
//            if (this.clientSettings == null) {
//                ClientSettings.Builder builder = ClientSettings.builder();
//                if (isPublicClientType()) {
//                    // @formatter:off
//                    builder
//                            .requireProofKey(true)
//                            .requireAuthorizationConsent(true);
//                    // @formatter:on
//                }
//                this.clientSettings = builder.build();
//            }
            validateScopes();
            validateRedirectUris();
            return create();
        }

        private boolean isPublicClientType() {
            return this.authorizationGrantTypes.contains(AuthorizationGrantType.AUTHORIZATION_CODE)
                    && this.clientAuthenticationMethods.size() == 1
                    && this.clientAuthenticationMethods.contains(ClientAuthenticationMethod.NONE);
        }

        private RegisteredClient create() {
            RegisteredClient registeredClient = new RegisteredClient();

            registeredClient.id = this.id;
            registeredClient.clientId = this.clientId;
            registeredClient.clientSecret = this.clientSecret;
            registeredClient.clientAuthenticationMethods = Collections
                    .unmodifiableSet(new HashSet<>(this.clientAuthenticationMethods));
            registeredClient.authorizationGrantTypes = Collections
                    .unmodifiableSet(new HashSet<>(this.authorizationGrantTypes));
            registeredClient.redirectUris = Collections.unmodifiableSet(new HashSet<>(this.redirectUris));
            registeredClient.scopes = Collections.unmodifiableSet(new HashSet<>(this.scopes));
            registeredClient.clientSettings = this.clientSettings;

            return registeredClient;
        }

        private void validateScopes() {
            if (CollectionUtils.isEmpty(this.scopes)) {
                return;
            }

            for (String scope : this.scopes) {
                Assert.isTrue(validateScope(scope), "scope \"" + scope + "\" contains invalid characters");
            }
        }

        private static boolean validateScope(String scope) {
            return scope == null || scope.chars()
                    .allMatch((c) -> withinTheRangeOf(c, 0x21, 0x21) || withinTheRangeOf(c, 0x23, 0x5B)
                            || withinTheRangeOf(c, 0x5D, 0x7E));
        }

        private static boolean withinTheRangeOf(int c, int min, int max) {
            return c >= min && c <= max;
        }

        private void validateRedirectUris() {
            if (CollectionUtils.isEmpty(this.redirectUris)) {
                return;
            }

            for (String redirectUri : this.redirectUris) {
                Assert.isTrue(validateRedirectUri(redirectUri),
                        "redirect_uri \"" + redirectUri + "\" is not a valid redirect URI or contains fragment");
            }
        }

        private static boolean validateRedirectUri(String redirectUri) {
            try {
                URI validRedirectUri = new URI(redirectUri);
                return validRedirectUri.getFragment() == null;
            }
            catch (URISyntaxException ex) {
                return false;
            }
        }

    }

}
