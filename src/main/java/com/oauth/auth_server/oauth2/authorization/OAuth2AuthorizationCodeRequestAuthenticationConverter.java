package com.oauth.auth_server.oauth2.authorization;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * HttpServletRequest → OAuth2AuthorizationCodeRequestAuthenticationToken 변환.
 *
 * SAS 참고: OAuth2AuthorizationCodeRequestAuthenticationConverter
 */
@Component
public class OAuth2AuthorizationCodeRequestAuthenticationConverter {

    public OAuth2AuthorizationCodeRequestAuthenticationToken convert(HttpServletRequest request) {
        String responseType = request.getParameter("response_type");
        String clientId = request.getParameter("client_id");
        String redirectUri = request.getParameter("redirect_uri");
        String scope = request.getParameter("scope");
        String state = request.getParameter("state");

        String[] scopeValues = request.getParameterValues("scope");
        int rawScopeParamCount = scopeValues != null ? scopeValues.length : 0;

        String username = SecurityContextHolder.getContext().getAuthentication().getName();

        return new OAuth2AuthorizationCodeRequestAuthenticationToken(
                responseType, clientId, redirectUri,
                splitScopes(scope), state, username, rawScopeParamCount);
    }

    private List<String> splitScopes(String scope) {
        if (scope == null || scope.isBlank()) {
            return List.of();
        }
        return Arrays.stream(scope.trim().split("\\s+"))
                .filter(s -> !s.isBlank())
                .distinct()
                .toList();
    }
}
