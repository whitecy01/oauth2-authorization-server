package com.oauth.auth_server.springauthserver.web.authentication;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

public final class OAuth2AuthorizationCodeRequestAuthenticationConverter implements AuthenticationConverter {


    @Override
    public Authentication convert(HttpServletRequest request) {
        return null;
    }
}
