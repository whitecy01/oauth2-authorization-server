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
 * GET 및 POST /oauth2/authorize 요청을 가로채 인가 코드 흐름을 처리하는 Filter.
 * - GET, POST(response_type 있음): 최초 인가 요청
 * - POST(action 있음): 동의 제출
 *
 * SAS 참고: OAuth2AuthorizationEndpointFilter
 */
public class OAuth2AuthorizationEndpointFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_URI = "/oauth2/authorize";
    public static final String CONSENT_VIEW_URI = "/oauth2/consent-view";
    public static final String CONSENT_EXCEPTION_ATTR = "consentException";

    private final OAuth2AuthorizationCodeRequestAuthenticationConverter authorizationConverter;
    private final OAuth2AuthorizationConsentAuthenticationConverter consentConverter;
    private final OAuth2AuthorizationCodeRequestAuthenticationProvider provider;

    public OAuth2AuthorizationEndpointFilter(
            OAuth2AuthorizationCodeRequestAuthenticationConverter authorizationConverter,
            OAuth2AuthorizationConsentAuthenticationConverter consentConverter,
            OAuth2AuthorizationCodeRequestAuthenticationProvider provider) {
        this.authorizationConverter = authorizationConverter;
        this.consentConverter = consentConverter;
        this.provider = provider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        if (!requiresProcessing(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {
            filterChain.doFilter(request, response);
            return;
        }

        // 동의 제출 POST
        if (isConsentSubmission(request)) {
            handleConsent(request, response);
            return;
        }

        // 최초 인가 요청 (GET / POST with response_type)
        if (request.getParameter("client_id") == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        OAuth2AuthorizationCodeRequestAuthenticationToken token = authorizationConverter.convert(request);

        try {
            AuthorizationCodeIssuedToken issued = provider.process(token);
            sendCodeRedirect(response, issued);

        } catch (ConsentRequiredException e) {
            request.setAttribute(CONSENT_EXCEPTION_ATTR, e);
            request.getRequestDispatcher(CONSENT_VIEW_URI).forward(request, response);

        } catch (OAuth2AuthorizationCodeRequestAuthenticationException e) {
            if (e.getRedirectUri() != null) {
                sendErrorRedirect(response, e.getRedirectUri(), e.getError(), e.getState());
            } else {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            }
        }
    }

    private void handleConsent(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        OAuth2AuthorizationConsentAuthenticationToken consentToken = consentConverter.convert(request);

        if (!consentToken.isApproved()) {
            UriComponentsBuilder builder = UriComponentsBuilder
                    .fromUriString(consentToken.getRedirectUri())
                    .queryParam("error", "access_denied");
            if (StringUtils.hasText(consentToken.getState())) {
                builder.queryParam("state", consentToken.getState());
            }
            response.sendRedirect(builder.toUriString());
            return;
        }

        AuthorizationCodeIssuedToken issued = provider.processConsent(consentToken);
        sendCodeRedirect(response, issued);
    }

    private boolean requiresProcessing(HttpServletRequest request) {
        if (!AUTHORIZATION_URI.equals(request.getServletPath())) {
            return false;
        }
        return "GET".equalsIgnoreCase(request.getMethod())
                || "POST".equalsIgnoreCase(request.getMethod());
    }

    private boolean isConsentSubmission(HttpServletRequest request) {
        return "POST".equalsIgnoreCase(request.getMethod())
                && request.getParameter("response_type") == null;
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
            com.oauth.auth_server.oauth2.core.OAuth2Error error, String state) throws IOException {
        UriComponentsBuilder builder = UriComponentsBuilder
                .fromUriString(redirectUri)
                .queryParam("error", error.getErrorCode());
        if (StringUtils.hasText(error.getDescription())) {
            builder.queryParam("error_description", error.getDescription());
        }
        if (StringUtils.hasText(error.getUri())) {
            builder.queryParam("error_uri", error.getUri());
        }
        if (StringUtils.hasText(state)) {
            builder.queryParam("state", state);
        }
        response.sendRedirect(builder.toUriString());
    }
}
