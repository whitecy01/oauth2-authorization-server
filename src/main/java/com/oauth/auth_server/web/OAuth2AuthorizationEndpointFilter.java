package com.oauth.auth_server.web;

import com.oauth.auth_server.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.DelegatingAuthenticationConverter;
import com.oauth.auth_server.web.authentication.OAuth2AuthorizationConsentAuthenticationConverter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
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

    private AuthenticationConverter authenticationConverter;

    /**
     * HTTP 요청으로부터 Authentication에 주입할 보안 메타데이터를 생성하는 컴포넌트
     */
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

    /**
     * Authentication 객체를 받아서 이게 인증 성공인지, 실패인지 판정하고 결과 Authentication을 반환하는 컴포넌트
     */
    private final AuthenticationManager authenticationManager;

    /**
     * 인가 엔드 포인트 URL을 따로 안 주면 기본 값 /oauth2/authorize를 쓰겠다.
     */    public OAuth2AuthorizationEndpointFilter(AuthenticationManager authenticationManager) {
        this(authenticationManager, DEFAULT_AUTHORIZATION_ENDPOINT_URI);
    }



    public OAuth2AuthorizationEndpointFilter(AuthenticationManager authenticationManager, String authorizationEndpointUri) {
        Assert.hasText(authorizationEndpointUri, "authorizationEndpointUri cannot be empty");
        /**
         * 어떤 HTTP 요청을 /oauth2/authorize 인가 요청으로 볼 것인가?를 정의하는 요청 판별기(RequestMatcher) 즉, 이 Filter 언제
         * 동작해야하는지 결정하는 규칙
         */
        this.authorizationEndpointMatcher = createDefaultRequestMatcher(authorizationEndpointUri);

        this.authenticationManager = authenticationManager;

        /**
         * 이 요청이 인가 요청이냐?, 아니면 동의 제출 요청이냐?, 누가 처리할 수 있으면 그 사람이 Authentication 만들어라
         *
         * 최초 인가 요청, 동의 POST 요청 → 둘 다 같은 /oauth2/authorize로 오니까 → converter가 분기 역할을 해주는 거다.
         * 즉, 분기를 자동으로 해주고, 파싱도 같이 해주는 역할
         * OAuth2AuthorizationCodeRequestAuthenticationConverter -> 최초 인가 요청
         * OAuth2AuthorizationConsentAuthenticationConverter -> 사용자가 동의 화면에서 '동의/거부' 버튼을 눌렀을 떄
         * DelegatingAuthenticationConverter에 등록된 객체들을 돌면서 객체들 안에서 response_type 파라미터가 없으면(동의 제출) null 있으면(최초 요청) Authentication 생성
         * DelegatingAuthenticationConverter이 “야, 너 이 요청 처리할 수 있어?” → 안 되면 다음 놈에게 또 물어봄 → 처리 가능하다고 응답한 첫 번째 놈을 채택
         * 1. AuthorizationCodeRequestConverter.convert(request)
         *    ├─ response_type=code ? → YES → Authentication 생성
         *    └─ 아니면 → null
         *
         * 2. ConsentRequestConverter.convert(request)
         *    ├─ 동의 제출 조건 만족? → YES → Authentication 생성
         *    └─ 아니면 → null
         *
         * 3. 둘 다 아니면 → null 반환
         */
        this.authenticationConverter = new DelegatingAuthenticationConverter(
                Arrays.asList(
                        new OAuth2AuthorizationCodeRequestAuthenticationConverter(),
                        new OAuth2AuthorizationConsentAuthenticationConverter()));
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

        /** HTTP 요청 → OAuth 요청 객체로 변환 즉, 파싱만 하는 거임
         *  request.getParameter(“client_id”)
         *  request.getParameter(“redirect_uri”)
         *  request.getParameter(“response_type”)
         *  convert는 자동으로 어떤 요청(최초 인가 요청, 동의 POST 요청)인지 판단해서 파싱함
         *  Authentication은 ‘누가/무엇이/어떤 자격으로 요청했는지’를 표현하는 Spring Security의 표준 보안 의미 객체다.
         */
        Authentication authentication = this.authenticationConverter.convert(request);

        /**
         * authentication이 AbstractAuthenticationToken 타입이면 안전하게 캐스팅해서 authenticationToken 변수로 쓰겠다
         * AbstractAuthenticationToken으로 바꾸는 이유는 Authentication에 ‘요청의 맥락 정보(details)’를 저장하기 위해서다.
         * Authentication의 인터페이스에 요청 환경 담을 자리가 없음 그래서 AbstractAuthenticationToken는 실제 쓰라고 만든 기본 구현체임
         * 그래서 이 Authentication이 Spring Security 표준 토큰 계열이라면 요청의 IP, 세션 같은 맥락 정보를 여기에 붙여두자
         * 하는 이유 -> 이 요청이 어디서 왔는지(IP, 세션 등)를 Authentication 객체에 기록해 두려고” 하는 것
         */
        if (authentication instanceof AbstractAuthenticationToken authenticationToken) {
            /**
             * authenticationDetailsSource는 HttpServletRequest로부터 Authentication에 넣을 ‘요청 환경 정보(details)’를 만들어주는 팩토리다.
             * authentication -> 보안 의미(누가 무엇을 요청), authenticationDetialsSource -> 요청 환경 정보 생성, details -> 환경 정보 저장소
             * authenticationDetailsSource 인터페이스 안에 -> buildDetails
             * Spring Security 기본 값은 WebAuthenticationDetailsSource -> 안에 요청한 IP, sessionId 이걸 Authentication에 붙여주는 거
             */
            authenticationToken.setDetails(this.authenticationDetailsSource.buildDetails(request));
        }

        Authentication authenticationResult = this.authenticationManager.authenticate(authentication);






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