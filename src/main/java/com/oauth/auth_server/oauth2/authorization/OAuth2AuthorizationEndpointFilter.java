package com.oauth.auth_server.oauth2.authorization;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * GET /oauth2/authorize 요청을 가로채 인가 코드 흐름을 처리하는 Filter.
 *
 * SAS 참고: OAuth2AuthorizationEndpointFilter
 */
public class OAuth2AuthorizationEndpointFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_URI = "/oauth2/authorize";
    public static final String CONSENT_VIEW_URI = "/oauth2/consent-view";
    public static final String CONSENT_EXCEPTION_ATTR = "consentException";

    private final OAuth2AuthorizationCodeRequestAuthenticationConverter converter;
    private final OAuth2AuthorizationCodeRequestAuthenticationProvider provider;

    public OAuth2AuthorizationEndpointFilter(
            OAuth2AuthorizationCodeRequestAuthenticationConverter converter,
            OAuth2AuthorizationCodeRequestAuthenticationProvider provider) {
        this.converter = converter;
        this.provider = provider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        if (!requiresProcessing(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        //Spring Security가 세션에서 꺼내 저장해 둔 현재 요청의 인증 정보를 가져옴
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        //인증 정보 자체가 없는 경우 (세션 없음) || 인증 객체는 있지만 인증이 완료되지 않은 경우
        if (authentication == null || !authentication.isAuthenticated()
                // Spring Security가 비로그인 사용자에게 자동으로 부여하는 익명 토큰인 경우
                || authentication instanceof AnonymousAuthenticationToken) {
            // → 그러면 Spring Security의 FilterSecurityInterceptor가 "인증 필요한
            //  URL인데 미인증"으로 판단해서 로그인 페이지로 redirect 시켜줌
            filterChain.doFilter(request, response);
            return;
        }

        if (request.getParameter("client_id") == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        OAuth2AuthorizationCodeRequestAuthenticationToken token = converter.convert(request);

        try {
            AuthorizationCodeIssuedToken issued = provider.process(token);
            sendCodeRedirect(response, issued);

        } catch (ConsentRequiredException e) {
            request.setAttribute(CONSENT_EXCEPTION_ATTR, e);
            //getRequestDispatcher -> 서버 내부에서 다른 URL로 요청을 넘기는 객체를 가져옴
            // .forword -> 현재 요청과 응답 객체를 그대로 들고 지정한 URL로 서버 내부에서 이동
            // redirect (response.sendRedirect)
            //    브라우저 → 서버: GET /oauth2/authorize
            //    서버 → 브라우저: 302 /oauth2/consent-view  (브라우저에게 다시 요청하라고 지시)
            //    브라우저 → 서버: GET /oauth2/consent-view   (브라우저가 새 요청 발생)
            //    URL 바뀜, request 객체 새로 생성
            //
            //  forward (request.getRequestDispatcher().forward)
            //    브라우저 → 서버: GET /oauth2/authorize
            //    서버 내부:       /oauth2/consent-view 로 넘김 (브라우저 모름)
            //    URL 안 바뀜, request 객체 그대로 유지
            //Filter에서 ConsentRequiredException을 잡은 뒤 동의 화면을 렌더링해야함. 그런데 Filter는 Thymeleaf 템플릿을 직접 렌더링할 수 없다.
            // /oauth2/consent-view Controller가 request.getAttribute(CONSENT_EXCEPTION_ATTR)로 꺼내서 Thymeleaf 뷰를 렌더링합니다. redirect였다면 request 객체가
            // 새로 생겨서 저장해 둔 데이터가 사라진다.
            request.getRequestDispatcher(CONSENT_VIEW_URI).forward(request, response);

        } catch (OAuth2AuthorizationCodeRequestAuthenticationException e) {
            if (e.getRedirectUri() != null) {
                sendErrorRedirect(response, e.getRedirectUri(), e.getError().getErrorCode(), e.getState());
            } else {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            }
        }
    }

    private boolean requiresProcessing(HttpServletRequest request) {
        return "GET".equalsIgnoreCase(request.getMethod())
                && AUTHORIZATION_URI.equals(request.getServletPath());
    }

    private void sendCodeRedirect(HttpServletResponse response, AuthorizationCodeIssuedToken issued)
            throws IOException {
        UriComponentsBuilder builder = UriComponentsBuilder
                .fromUriString(issued.getRedirectUri())
                .queryParam("code", issued.getCode());
        if (StringUtils.hasText(issued.getState())) {
            builder.queryParam("state", issued.getState());
        }
        response.sendRedirect(builder.toUriString());
    }

    private void sendErrorRedirect(HttpServletResponse response, String redirectUri,
            String error, String state) throws IOException {
        UriComponentsBuilder builder = UriComponentsBuilder
                .fromUriString(redirectUri)
                .queryParam("error", error);
        if (StringUtils.hasText(state)) {
            builder.queryParam("state", state);
        }
        response.sendRedirect(builder.toUriString());
    }
}
