package com.oauth.auth_server.web.authentication;

import com.oauth.auth_server.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

public class OAuth2AuthorizationCodeRequestAuthenticationException extends OAuth2AuthenticationException {

    /**
     * HTTP 인가 요청을 Spring Security 표준 Authentication 형태로 포장한 객체
     * 이 안에 clientId, redirectUri, responseType, scopes, state, additionalParameters, principal 이런 것들이 들어있음
     * Converter -> OAuth2AuthorizationCodeRequestAuthenticationToken 생성 -> AuthenticationManager.authenticate(authentication)
     * -> OAuth2AuthorizationCodeRequestAuthenticationProvider
     * - client_id 검증
     * - redirect_uri 검증
     * - scope 검증
     * - Authorization Code 생성
     * -> 인증 완료된 Authentication 반환
     *
     * 예외가 발생하면  에러가 발생했을 때 redirect_uri, state 값이 필요하기 때문
     */
    private final OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication;

    /**
     * 역할
     * - OAuth2Error를 저장
     * - (선택적으로) 원래의 Authentication 객체도 저장 -> 왜 Authentication을 같이 저장할까?
     * 에러 응답을 보낼 때:
     * 	- redirect_uri
     * 	- state
     * 같은 값이 필요할 수 있기 때문
     */
    public OAuth2AuthorizationCodeRequestAuthenticationException(OAuth2Error error,
                                                                 @Nullable OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication) {
        super(error);
        this.authorizationCodeRequestAuthentication = authorizationCodeRequestAuthentication;
    }

    /**
     * 역할
     * 	- 위와 동일하지만
     * 	- 내부 원인(cause)을 같이 보존
     * 즉, 디버깅이나 로깅용으로 예외 체인을 유지하기 위한 생성자
     */
    public OAuth2AuthorizationCodeRequestAuthenticationException(OAuth2Error error, Throwable cause,
                                                                 @Nullable OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication) {
        super(error, cause);
        this.authorizationCodeRequestAuthentication = authorizationCodeRequestAuthentication;
    }

    /**
     * 역할 -> 에러 발생 당시의 인가 요청 Authentication 객체를 반환한다.
     * OAuth2AuthorizationEndpointFilter 안을 보면 즉 에러가 나도 클라이언트의 redirect_uri로 돌려보내야함. 이때 원래 요청의 state 값이 필요함
     * 그래서 예외 객체 안에 Authentication을 같이 저장해둔다.
     */
    @Nullable
    public OAuth2AuthorizationCodeRequestAuthenticationToken getAuthorizationCodeRequestAuthentication() {
        return this.authorizationCodeRequestAuthentication;
    }

}