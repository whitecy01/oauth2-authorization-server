package com.oauth.auth_server.authentication;

import java.io.Serial;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

abstract class AbstractOAuth2AuthorizationCodeRequestAuthenticationToken extends AbstractAuthenticationToken {

    @Serial
    private static final long serialVersionUID = -5813797478091794517L;

    private final String authorizationUri;

    private final String clientId;

    private final Authentication principal;

    private final String redirectUri;

    private final String state;

    private final Set<String> scopes;

    private final Map<String, Object> additionalParameters;

    protected AbstractOAuth2AuthorizationCodeRequestAuthenticationToken(String authorizationUri, String clientId,
                                                                        Authentication principal, @Nullable String redirectUri, @Nullable String state,
                                                                        @Nullable Set<String> scopes, @Nullable Map<String, Object> additionalParameters) {
        super(Collections.emptyList());
        Assert.hasText(authorizationUri, "authorizationUri cannot be empty");
        Assert.hasText(clientId, "clientId cannot be empty");
        Assert.notNull(principal, "principal cannot be null");
        this.authorizationUri = authorizationUri;
        this.clientId = clientId;
        this.principal = principal;
        this.redirectUri = redirectUri;
        this.state = state;
        this.scopes = Collections.unmodifiableSet((scopes != null) ? new HashSet<>(scopes) : Collections.emptySet());
        this.additionalParameters = Collections.unmodifiableMap(
                (additionalParameters != null) ? new HashMap<>(additionalParameters) : Collections.emptyMap());
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    /**
     * Returns the authorization URI.
     * @return the authorization URI
     */
    public String getAuthorizationUri() {
        return this.authorizationUri;
    }

    /**
     * Returns the client identifier.
     * @return the client identifier
     */
    public String getClientId() {
        return this.clientId;
    }

    /**
     * Returns the redirect uri.
     * @return the redirect uri
     */
    @Nullable
    public String getRedirectUri() {
        return this.redirectUri;
    }

    /**
     * Returns the state.
     * @return the state
     */
    @Nullable
    public String getState() {
        return this.state;
    }

    /**
     * Returns the requested (or authorized) scope(s).
     * @return the requested (or authorized) scope(s), or an empty {@code Set} if not
     * available
     */
    public Set<String> getScopes() {
        return this.scopes;
    }

    /**
     * Returns the additional parameters.
     * @return the additional parameters, or an empty {@code Map} if not available
     */
    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }

}
