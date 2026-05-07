package com.oauth.auth_server.oauth2.authorization;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * 동의 제출 POST 요청을 OAuth2AuthorizationConsentAuthenticationToken으로 변환한다.
 * action 파라미터가 없으면 null을 반환해 다음 Converter로 넘긴다.
 *
 * SAS 참고: OAuth2AuthorizationConsentAuthenticationConverter
 */
@Component
public class OAuth2AuthorizationConsentAuthenticationConverter {

    public OAuth2AuthorizationConsentAuthenticationToken convert(HttpServletRequest request) {
        String action     = request.getParameter("action");
        String clientId   = request.getParameter("client_id");
        String redirectUri = request.getParameter("redirect_uri");
        String scope      = request.getParameter("scope");
        String state      = request.getParameter("state");
        String username   = SecurityContextHolder.getContext().getAuthentication().getName();

        return new OAuth2AuthorizationConsentAuthenticationToken(
                clientId, redirectUri, splitScopes(scope), state, username,
                "approve".equals(action));
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
