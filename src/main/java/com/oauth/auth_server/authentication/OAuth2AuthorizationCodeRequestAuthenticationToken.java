package com.oauth.auth_server.authentication;

import com.oauth.auth_server.OAuth2AuthorizationCode;
import java.io.Serial;
import java.util.Map;
import java.util.Set;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

public class OAuth2AuthorizationCodeRequestAuthenticationToken
        extends AbstractOAuth2AuthorizationCodeRequestAuthenticationToken {


    @Serial
    private static final long serialVersionUID = -1946164725241393094L;

    /**
     * Authorization Code Grant에서 발급 되는 인가 코드 자체를 표현 하는 객체
     * OAuth2AuthorizationCodeRequestAuthenticationProvider 안에서 검증 완료 -> authorizationCode 생성 -> Authentication 객체에 포함 -> redirect_uri로 code 전달
     * OAuth2AuthorizationCode는 다음과 같은 구조를 가진다.
     * - tokenValue -> 실제 code 문자열, issuedAt -> 발급 시간, expiresAt -> 만료시간
     * GET /oauth2/authorize?response_type=code&client_id=abc에서 검증 성공하면
     * authorizationCode = new OAuth2AuthorizationCode(
     *     "SplxlOBeZQQYbYS6WxSbIA",
     *     issuedAt,
     *     expiresAt
     * )
     */
    private final OAuth2AuthorizationCode authorizationCode;

    /**
     * 역할
     * - OAuth2Error를 저장
     * - (선택적으로) 원래의 Authentication 객체도 저장 -> 왜 Authentication을 같이 저장할까?
     * 에러 응답을 보낼 때:
     * 	- redirect_uri
     * 	- state
     * 같은 값이 필요할 수 있기 때문
     */
    public OAuth2AuthorizationCodeRequestAuthenticationToken(String authorizationUri, String clientId,
                                                             Authentication principal, @Nullable String redirectUri, @Nullable String state,
                                                             @Nullable Set<String> scopes, @Nullable Map<String, Object> additionalParameters) {
        super(authorizationUri, clientId, principal, redirectUri, state, scopes, additionalParameters);
        this.authorizationCode = null;
    }

    /**
     * 역할
     * 	- 위와 동일하지만
     * 	- 내부 원인(cause)을 같이 보존
     * 즉, 디버깅이나 로깅용으로 예외 체인을 유지하기 위한 생성자
     */
    public OAuth2AuthorizationCodeRequestAuthenticationToken(String authorizationUri, String clientId,
                                                             Authentication principal, OAuth2AuthorizationCode authorizationCode, @Nullable String redirectUri,
                                                             @Nullable String state, @Nullable Set<String> scopes) {
        super(authorizationUri, clientId, principal, redirectUri, state, scopes, null);
        Assert.notNull(authorizationCode, "authorizationCode cannot be null");
        this.authorizationCode = authorizationCode;
        setAuthenticated(true);
    }

    /**
     * Returns the {@link OAuth2AuthorizationCode}.
     * @return the {@link OAuth2AuthorizationCode}
     */
    /**
     * 역할 -> 에러 발생 당시의 인가 요청 Authentication 객체를 반환한다.
     * OAuth2AuthorizationEndpointFilter 안을 보면 즉 에러가 나도 클라이언트의 redirect_uri로 돌려보내야함. 이때 원래 요청의 state 값이 필요함
     * 그래서 예외 객체 안에 Authentication을 같이 저장해둔다.
     */
    @Nullable
    public OAuth2AuthorizationCode getAuthorizationCode() {
        return this.authorizationCode;
    }
}

