package com.oauth.auth_server.web.authentication;

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

public class OAuth2AuthorizationConsentAuthenticationToken extends AbstractAuthenticationToken {

    @Serial
    private static final long serialVersionUID = -2111287271882598208L;

    private final String authorizationUri;

    private final String clientId;

    private final Authentication principal;

    private final String state;

    private final Set<String> scopes;

    private final Map<String, Object> additionalParameters;

    /**
     * 사용자가 특정 클라이언트에 대해 scope에 동의했다”는 사실을 표현하는 Authentication 객체
     * @param authorizationUri
     * @param clientId
     * @param principal
     * @param state
     * @param scopes
     * @param additionalParameters
     */
    public OAuth2AuthorizationConsentAuthenticationToken(String authorizationUri, String clientId,
                                                         Authentication principal, String state, @Nullable Set<String> scopes,
                                                         @Nullable Map<String, Object> additionalParameters) {
        super(Collections.emptyList());
        Assert.hasText(authorizationUri, "authorizationUri cannot be empty");
        Assert.hasText(clientId, "clientId cannot be empty");
        Assert.notNull(principal, "principal cannot be null");
        Assert.hasText(state, "state cannot be empty");
        this.authorizationUri = authorizationUri;
        this.clientId = clientId;
        this.principal = principal;
        this.state = state;
        this.scopes = Collections.unmodifiableSet((scopes != null) ? new HashSet<>(scopes) : Collections.emptySet());
        this.additionalParameters = Collections.unmodifiableMap(
                (additionalParameters != null) ? new HashMap<>(additionalParameters) : Collections.emptyMap());
        setAuthenticated(true);
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
     * Returns the state.
     * @return the state
     */
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