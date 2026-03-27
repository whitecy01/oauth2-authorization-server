package com.oauth.auth_server.oauth2.authorization;

import java.util.List;

/**
 * 인가 코드 요청의 HTTP 파라미터를 파싱해 정리한 불변 값 객체.
 * Controller가 이 객체를 만들어 Provider에 넘긴다.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1">RFC 6749 §4.1.1</a>
 */
public class OAuth2AuthorizationCodeRequestAuthenticationToken {

    private final String responseType;
    private final String clientId;
    private final String redirectUri;       // nullable
    private final List<String> scopes;
    private final String state;             // nullable
    private final String username;
    private final int rawScopeParamCount;   // scope 파라미터 중복 검사용 (scope=read&scope=write 감지)

    public OAuth2AuthorizationCodeRequestAuthenticationToken(
            String responseType,
            String clientId,
            String redirectUri,
            List<String> scopes,
            String state,
            String username,
            int rawScopeParamCount
    ) {
        this.responseType = responseType;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.scopes = List.copyOf(scopes);
        this.state = state;
        this.username = username;
        this.rawScopeParamCount = rawScopeParamCount;
    }

    public String getResponseType() {
        return responseType;
    }

    public String getClientId() {
        return clientId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public String getState() {
        return state;
    }

    public String getUsername() {
        return username;
    }

    public int getRawScopeParamCount() {
        return rawScopeParamCount;
    }
}