package com.oauth.auth_server.oauth2.authorization;

/**
 * Provider가 인가 코드 발급에 성공했을 때 반환하는 결과 객체.
 * Controller가 이 객체를 받아 302 redirect 응답을 만든다.
 */
public class AuthorizationCodeIssuedToken {

    private final String code;
    private final String redirectUri;
    private final String state;

    public AuthorizationCodeIssuedToken(String code, String redirectUri, String state) {
        this.code = code;
        this.redirectUri = redirectUri;
        this.state = state;
    }

    public String getCode() {
        return code;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getState() {
        return state;
    }
}