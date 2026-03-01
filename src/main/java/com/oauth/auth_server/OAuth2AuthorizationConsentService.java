package com.oauth.auth_server;

import com.oauth.auth_server.client.RegisteredClient;
import java.security.Principal;
import org.springframework.lang.Nullable;

/**
 * 사용자가 특정 클라이언트에 대해 어떤 scope를 동의했는지 저장하는 서비스
 * 사용자가 이전에 이미 동의한 적이 있다면 매번 동의 화면을 보여줄 필요가 없다.
 * 그래서 사용자 + 클라이언트 조합별로 어떤 scope 승인했는지 저장
 */
public interface OAuth2AuthorizationConsentService {

    /**
     * Saves the {@link OAuth2AuthorizationConsent}.
     * @param authorizationConsent the {@link OAuth2AuthorizationConsent}
     */
    void save(OAuth2AuthorizationConsent authorizationConsent);

    /**
     * Removes the {@link OAuth2AuthorizationConsent}.
     * @param authorizationConsent the {@link OAuth2AuthorizationConsent}
     */
    void remove(OAuth2AuthorizationConsent authorizationConsent);

    /**
     * Returns the {@link OAuth2AuthorizationConsent} identified by the  provided
     * {@code registeredClientId} and {@code principalName}, or {@code null} if not found.
     * @param registeredClientId the identifier for the {@link RegisteredClient}
     * @param principalName the name of the {@link Principal}
     * @return the {@link OAuth2AuthorizationConsent} if found, otherwise {@code null}
     */
    @Nullable
    OAuth2AuthorizationConsent findById(String registeredClientId, String principalName);

}
