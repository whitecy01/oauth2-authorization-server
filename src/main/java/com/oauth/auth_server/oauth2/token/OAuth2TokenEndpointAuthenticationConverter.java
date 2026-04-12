package com.oauth.auth_server.oauth2.token;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

/**
 * HttpServletRequest → AuthorizationCodeTokenRequest 변환.
 *
 * SAS 참고: OAuth2AuthorizationCodeAuthenticationConverter
 */
@Component
public class OAuth2TokenEndpointAuthenticationConverter {

    public AuthorizationCodeTokenRequest convert(HttpServletRequest request) {
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        List<String> grantTypes = toList(request.getParameterValues("grant_type"));
        List<String> codes = toList(request.getParameterValues("code"));
        List<String> redirectUris = toList(request.getParameterValues("redirect_uri"));
        String clientId = request.getParameter("client_id");
        String clientSecret = request.getParameter("client_secret");

        return new AuthorizationCodeTokenRequest(
                grantTypes, codes, redirectUris, clientId, clientSecret, authorizationHeader);
    }

    private List<String> toList(String[] values) {
        if (values == null) return List.of();
        return Arrays.asList(values);
    }
}