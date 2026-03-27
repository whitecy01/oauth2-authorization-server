package com.oauth.auth_server.oauth2.authorization;

import com.oauth.auth_server.oauth2.core.OAuth2AuthorizationException;
import com.oauth.auth_server.oauth2.core.OAuth2Error;

/**
 * 인가 코드 요청 처리 중 발생하는 예외.
 *
 * redirectUri 가 non-null 이면 Controller 가 해당 URI 로 error redirect 한다.
 * redirectUri 가 null 이면 Controller 가 400 Bad Request 를 반환한다.
 * (redirect_uri / client 검증 실패처럼 redirect_uri 를 신뢰할 수 없는 경우)
 *
 * SAS 참고: OAuth2AuthorizationCodeRequestAuthenticationException
 */
public class OAuth2AuthorizationCodeRequestAuthenticationException extends OAuth2AuthorizationException {

    private final String redirectUri;
    private final String state;

    public OAuth2AuthorizationCodeRequestAuthenticationException(
            OAuth2Error error, String redirectUri, String state) {
        super(error);
        this.redirectUri = redirectUri;
        this.state = state;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getState() {
        return state;
    }
}