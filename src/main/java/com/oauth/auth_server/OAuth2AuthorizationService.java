package com.oauth.auth_server;

import org.springframework.lang.Nullable;


/**
 * 인가 서버는 다음과 같은 2가지 일을 함
 * 1. /oauth2/authorize
 * → Authorization Code 발급
 * 2. /oauth2/token
 * → 클라이언트가 Authorization Code 제출
 *
 * 그럼 서버는 검증을 “이 코드 내가 발급한 거 맞나?", “이미 사용된 코드 아닌가?”, “어떤 client_id에 발급했지?”, “어떤 redirect_uri로 요청됐지?”
 * 을 기억하고 있어야함 그 저장소가 바로 이거
 */
public interface OAuth2AuthorizationService {

    /**
     * Saves the {@link OAuth2Authorization}.
     * @param authorization the {@link OAuth2Authorization}
     */
    void save(OAuth2Authorization authorization);

    /**
     * Removes the {@link OAuth2Authorization}.
     * @param authorization the {@link OAuth2Authorization}
     */
    void remove(OAuth2Authorization authorization);

    /**
     * Returns the {@link OAuth2Authorization} identified by the provided {@code id}, or
     * {@code null} if not found.
     * @param id the authorization identifier
     * @return the {@link OAuth2Authorization} if found, otherwise {@code null}
     */
    @Nullable
    OAuth2Authorization findById(String id);

    /**
     * Returns the {@link OAuth2Authorization} containing the provided {@code token}, or
     * {@code null} if not found.
     * @param token the token credential
     * @param tokenType the {@link OAuth2TokenType token type}
     * @return the {@link OAuth2Authorization} if found, otherwise {@code null}
     */
    @Nullable
    OAuth2Authorization findByToken(String token, @Nullable OAuth2TokenType tokenType);

}
