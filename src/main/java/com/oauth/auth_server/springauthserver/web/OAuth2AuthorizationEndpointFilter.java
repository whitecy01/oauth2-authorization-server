package com.oauth.auth_server.springauthserver.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

public class OAuth2AuthorizationEndpointFilter extends OncePerRequestFilter {

    private static final String DEFAULT_AUTHORIZATION_ENDPOINT_URI = "/oauth2/authorize";

    /**
     * 이 HTTP 요청이 OAuth 인가 엔드포인트 요청인가?”를 판단하는 조건 객체
     */
    private final RequestMatcher authorizationEndpointMatcher;

    /**
     * 인가 엔드 포인트 URL을 따로 안 주면 기본 값 /oauth2/authorize를 쓰겠다.
     */
    public OAuth2AuthorizationEndpointFilter() {
        this(DEFAULT_AUTHORIZATION_ENDPOINT_URI);
    }

    public OAuth2AuthorizationEndpointFilter(String authorizationEndpointUri) {
        Assert.hasText(authorizationEndpointUri, "authorizationEndpointUri cannot be empty");
        /**
         * 어떤 HTTP 요청을 /oauth2/authorize 인가 요청으로 볼 것인가?를 정의하는 요청 판별기(RequestMatcher) 즉, 이 Filter 언제
         * 동작해야하는지 결정하는 규칙
         */
        this.authorizationEndpointMatcher = createDefaultRequestMatcher(authorizationEndpointUri);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        /**
         * 이 요청이 /oauth2/authorize 인가? -> 아니면 그냥 통과, 맞으면 OAuth 인가 처리 시작
         */
        if (!this.authorizationEndpointMatcher.matches(request)){
            filterChain.doFilter(request, response);
            return;
        }

        // 필터가 탔다 증거
        System.out.println("[AuthzFilter] matched: " + request.getMethod() + " " + request.getRequestURI()
                + (request.getQueryString() != null ? "?" + request.getQueryString() : ""));

        // 브라우저/클라이언트에서 확인 가능한 표시 (Network 탭에서 보임)
        response.setHeader("X-Debug-Authz-Filter", "matched");

        // 컨트롤러로 계속 진행
        filterChain.doFilter(request, response);

    }

    private static RequestMatcher createDefaultRequestMatcher(String authorizationEndpointUri) {
        /**
         *  GET /oauth2/authorize
         * 	OAuth 인가 요청의 기본 형태 (RFC 6749 3.1)
         * 	POST도 가능
         */
        RequestMatcher authorizationRequestGetMatcher = PathPatternRequestMatcher.withDefaults()
                .matcher(HttpMethod.GET, authorizationEndpointUri);
        RequestMatcher authorizationRequestPostMatcher = PathPatternRequestMatcher.withDefaults()
                .matcher(HttpMethod.POST, authorizationEndpointUri);

        /**
         * 인가 요청 판별
         * 다음 중 하나면 Authorization Request
         * 	1. GET /oauth2/authorize
         * 	2. POST /oauth2/authorize AND response_type 있음
         */
        RequestMatcher authorizationRequestMatcher = new OrRequestMatcher(authorizationRequestGetMatcher,
                new AndRequestMatcher(authorizationRequestPostMatcher));

        /**
         *  이 Filter는 최초 인가 요청
         */
        return new OrRequestMatcher(authorizationRequestMatcher);
    }


}