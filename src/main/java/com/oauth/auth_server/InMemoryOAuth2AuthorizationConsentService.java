package com.oauth.auth_server;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

/**
 * 사용자 동의를 메모리에 저장하는 구현체
 */
public final class InMemoryOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

    private final Map<Integer, OAuth2AuthorizationConsent> authorizationConsents = new ConcurrentHashMap<>();

    /**
     * Constructs an {@code InMemoryOAuth2AuthorizationConsentService}.
     */
    public InMemoryOAuth2AuthorizationConsentService() {
        this(Collections.emptyList());
    }

    /**
     * Constructs an {@code InMemoryOAuth2AuthorizationConsentService} using the provided
     * parameters.
     * @param authorizationConsents the authorization consent(s)
     */
    public InMemoryOAuth2AuthorizationConsentService(OAuth2AuthorizationConsent... authorizationConsents) {
        this(Arrays.asList(authorizationConsents));
    }

    /**
     * Constructs an {@code InMemoryOAuth2AuthorizationConsentService} using the provided
     * parameters.
     * @param authorizationConsents the authorization consent(s)
     */
    public InMemoryOAuth2AuthorizationConsentService(List<OAuth2AuthorizationConsent> authorizationConsents) {
        Assert.notNull(authorizationConsents, "authorizationConsents cannot be null");
        authorizationConsents.forEach((authorizationConsent) -> {
            Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
            int id = getId(authorizationConsent);
            Assert.isTrue(!this.authorizationConsents.containsKey(id),
                    "The authorizationConsent must be unique. Found duplicate, with registered client id: ["
                            + authorizationConsent.getRegisteredClientId() + "] and principal name: ["
                            + authorizationConsent.getPrincipalName() + "]");
            this.authorizationConsents.put(id, authorizationConsent);
        });
    }

    @Override
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
        int id = getId(authorizationConsent);
        this.authorizationConsents.put(id, authorizationConsent);
    }

    @Override
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
        int id = getId(authorizationConsent);
        this.authorizationConsents.remove(id, authorizationConsent);
    }

    @Override
    @Nullable
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
        Assert.hasText(principalName, "principalName cannot be empty");
        int id = getId(registeredClientId, principalName);
        return this.authorizationConsents.get(id);
    }

    private static int getId(String registeredClientId, String principalName) {
        return Objects.hash(registeredClientId, principalName);
    }

    private static int getId(OAuth2AuthorizationConsent authorizationConsent) {
        return getId(authorizationConsent.getRegisteredClientId(), authorizationConsent.getPrincipalName());
    }

}