package com.oauth.auth_server.springauthserver.web.authentication;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public final class OAuth2AuthorizationCodeRequestAuthenticationConverter implements AuthenticationConverter {

    private final RequestMatcher requestMatcher = createDefaultRequestMatcher();


    private static RequestMatcher createDefaultRequestMatcher(){
        RequestMatcher getMethodMatcher = (request) -> "GET".equals(request.getMethod());
        RequestMatcher postMethodMatcher = (request) -> "POST".equals(request.getMethod());
        RequestMatcher responseTypeParameterMatcher = (
                request) -> request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE) != null;
        return new OrRequestMatcher(getMethodMatcher,
                new AndRequestMatcher(postMethodMatcher, responseTypeParameterMatcher));
    }

    @Override
    public Authentication convert(HttpServletRequest request) {

        if (!this.requestMatcher.matches(request)){
            return null;
        }

        return null;
    }
}
