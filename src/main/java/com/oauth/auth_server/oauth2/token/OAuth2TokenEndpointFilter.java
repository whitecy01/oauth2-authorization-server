package com.oauth.auth_server.oauth2.token;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.oauth.auth_server.oauth2.core.OAuth2AccessToken;
import com.oauth.auth_server.oauth2.core.OAuth2AuthorizationException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * POST /oauth2/token 요청을 가로채 액세스 토큰 발급 흐름을 처리하는 Filter.
 *
 * SAS 참고: OAuth2TokenEndpointFilter
 */
public class OAuth2TokenEndpointFilter extends OncePerRequestFilter {

    private static final String TOKEN_URI = "/oauth2/token";

    private final OAuth2TokenEndpointAuthenticationConverter converter;
    private final AuthorizationCodeTokenProvider provider;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public OAuth2TokenEndpointFilter(
            OAuth2TokenEndpointAuthenticationConverter converter,
            AuthorizationCodeTokenProvider provider) {
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

        AuthorizationCodeTokenRequest tokenRequest = converter.convert(request);

        try {
            OAuth2AccessToken accessToken = provider.process(tokenRequest);
            sendSuccessResponse(response, accessToken);
        } catch (OAuth2AuthorizationException e) {
            sendErrorResponse(response, e);
        }
    }

    private boolean requiresProcessing(HttpServletRequest request) {
        return "POST".equalsIgnoreCase(request.getMethod())
                && TOKEN_URI.equals(request.getServletPath());
    }

    private void sendSuccessResponse(HttpServletResponse response, OAuth2AccessToken accessToken)
            throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("access_token", accessToken.getTokenValue());
        body.put("token_type", "Bearer");
        body.put("expires_in", accessToken.getExpiresInSeconds());

        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), body);
    }

    private void sendErrorResponse(HttpServletResponse response, OAuth2AuthorizationException e)
            throws IOException {
        String errorCode = e.getError().getErrorCode();

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", errorCode);
        body.put("error_description", e.getError().getDescription());

        if ("invalid_client".equals(errorCode)) {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"oauth2/token\"");
        } else {
            response.setStatus(HttpStatus.BAD_REQUEST.value());
        }
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), body);
    }
}